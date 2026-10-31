// Bounded Ghidra probe: output only coarse data-flow statistics, never C or game strings.
// Function ranges come from separately validated ARM64 .eh_frame records.
import java.util.*;

import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.ParameterDefinitionImpl;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.lang.Register;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.SourceType;

public class WorldboxProbe extends GhidraScript {
    private long originalBase;
    private static final int MAX_NODES = 256;
    private static final int MAX_DEPTH = 12;

    private Address mapped(long value) throws Exception {
        if (value < originalBase) throw new IllegalArgumentException("address below ELF image base");
        return currentProgram.getImageBase().add(value - originalBase);
    }

    private Function boundedFunction(long start, long size) throws Exception {
        if (size < 4 || size > 32768) return null;
        Address entry = mapped(start);
        AddressSet body = new AddressSet(entry, entry.add(size - 1));
        if (!currentProgram.getMemory().contains(entry) || !currentProgram.getMemory().contains(entry.add(size - 1))) return null;
        new DisassembleCommand(entry, body, true).applyTo(currentProgram, monitor);
        Function function = getFunctionAt(entry);
        if (function == null) {
            CreateFunctionCmd cmd = new CreateFunctionCmd(null, entry, body, SourceType.USER_DEFINED);
            if (!cmd.applyTo(currentProgram, monitor)) return null;
            function = getFunctionAt(entry);
        }
        if (function == null || !function.getEntryPoint().equals(entry)) return null;
        try {
            function.setBody(body);
        } catch (Exception ex) {
            return null;
        }
        return function;
    }

    private boolean applyProbeSignature(Function helper) throws Exception {
        // This is an explicitly artificial ABI signature used to expose input x0;
        // it is not a claim about the helper's real prototype or return type.
        FunctionDefinitionDataType sig = new FunctionDefinitionDataType("probe_helper");
        sig.setReturnType(PointerDataType.dataType);
        ParameterDefinition[] params = new ParameterDefinition[6];
        for (int i = 0; i < params.length; i++) {
            params[i] = new ParameterDefinitionImpl("arg" + i, PointerDataType.dataType, null);
        }
        sig.setArguments(params);
        return new ApplyFunctionSignatureCmd(helper.getEntryPoint(), sig, SourceType.USER_DEFINED)
            .applyTo(currentProgram, monitor);
    }

    private String safeStringCategory(long value) {
        try {
            Address a = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(value);
            if (!currentProgram.getMemory().contains(a)) return null;
            byte[] bytes = new byte[128];
            int n = currentProgram.getMemory().getBytes(a, bytes);
            int end = 0;
            while (end < n && bytes[end] != 0 && end < 127) end++;
            if (end == 0) return null;
            String text = new String(bytes, 0, end, java.nio.charset.StandardCharsets.US_ASCII).toLowerCase(Locale.ROOT);
            if (text.startsWith("global-metadata.dat") || text.startsWith("metadata.dat")) return "metadata-name";
            if (text.startsWith("assets/bin/data/")) return "unity-assets-path";
            if (text.startsWith("/proc/")) return "proc-path";
            if (text.equals("/dev/urandom") || text.equals("/dev/random")) return "system-random-device";
        } catch (Exception ex) {
            // An integer constant is not necessarily an address or readable memory.
        }
        return null;
    }

    // Recover only a simple input-register + constant-offset + load chain.
    // Unknown operations or conflicting phi inputs are deliberately unresolved.
    private List<String> accessPath(Varnode node, int depth, Set<Varnode> seen) {
        if (node == null || depth > 12 || !seen.add(node)) return null;
        if (node.isInput() && node.isRegister()) {
            Register register = currentProgram.getRegister(node.getAddress(), node.getSize());
            if (register == null) return null;
            String name = register.getName().toLowerCase(Locale.ROOT);
            if (!name.matches("x[0-7]")) return null;
            List<String> path = new ArrayList<>();
            path.add("input-" + name);
            return path;
        }
        PcodeOp def = node.getDef();
        if (def == null) return null;
        int opcode = def.getOpcode();
        if ((opcode == PcodeOp.COPY || opcode == PcodeOp.CAST) && def.getNumInputs() == 1)
            return accessPath(def.getInput(0), depth + 1, seen);
        if (opcode == PcodeOp.LOAD && def.getNumInputs() >= 2) {
            List<String> path = accessPath(def.getInput(1), depth + 1, seen);
            if (path == null || path.size() >= 16) return null;
            path.add("load");
            return path;
        }
        if ((opcode == PcodeOp.INT_ADD || opcode == PcodeOp.PTRSUB) && def.getNumInputs() == 2 && def.getInput(1).isConstant()) {
            List<String> path = accessPath(def.getInput(0), depth + 1, seen);
            if (path == null) return null;
            Varnode constant = def.getInput(1);
            int bits = Math.min(64, constant.getSize() * 8);
            long delta = constant.getOffset();
            if (bits < 64) delta = (delta << (64 - bits)) >> (64 - bits);
            if (delta < -4096 || delta > 4096 || path.size() >= 16) return null;
            if (delta != 0) path.add("offset:" + delta);
            return path;
        }
        if (opcode == PcodeOp.PTRADD && def.getNumInputs() == 3 && def.getInput(1).isConstant() && def.getInput(2).isConstant()) {
            List<String> path = accessPath(def.getInput(0), depth + 1, seen);
            if (path == null) return null;
            try {
                long delta = Math.multiplyExact(def.getInput(1).getOffset(), def.getInput(2).getOffset());
                if (delta < -4096 || delta > 4096 || path.size() >= 16) return null;
                if (delta != 0) path.add("offset:" + delta);
                return path;
            } catch (ArithmeticException ex) { return null; }
        }
        if (opcode == PcodeOp.MULTIEQUAL && def.getNumInputs() > 0) {
            List<String> same = null;
            for (int i = 0; i < def.getNumInputs(); i++) {
                List<String> path = accessPath(def.getInput(i), depth + 1, new HashSet<>(seen));
                if (path == null || (same != null && !same.equals(path))) return null;
                same = path;
            }
            return same;
        }
        return null;
    }

    private Map<String, Object> traceArgument(Varnode root) {
        Map<String, Object> result = new LinkedHashMap<>();
        Map<String, Integer> opCounts = new TreeMap<>();
        Set<String> roots = new TreeSet<>();
        Set<String> inputRegisters = new TreeSet<>();
        Set<String> stringCategories = new TreeSet<>();
        Set<Varnode> visited = new HashSet<>();
        Deque<Varnode> nodes = new ArrayDeque<>();
        Deque<Integer> depths = new ArrayDeque<>();
        nodes.add(root); depths.add(0);
        boolean depthLimit = false;
        while (!nodes.isEmpty() && visited.size() < MAX_NODES) {
            Varnode node = nodes.removeFirst();
            int depth = depths.removeFirst();
            if (!visited.add(node)) continue;
            if (node.isConstant()) {
                roots.add("constant");
                String category = safeStringCategory(node.getOffset());
                if (category != null) stringCategories.add(category);
            } else if (node.isRegister()) roots.add("register");
            else if (node.getAddress().isStackAddress()) roots.add("stack");
            else if (node.isAddress()) roots.add("address");
            else if (node.isUnique()) roots.add("temporary");
            if (node.isInput()) {
                roots.add("function-input");
                if (node.isRegister()) {
                    Register register = currentProgram.getRegister(node.getAddress(), node.getSize());
                    if (register != null) {
                        String name = register.getName().toLowerCase(Locale.ROOT);
                        if (name.matches("x[0-7]") || name.equals("sp")) inputRegisters.add(name);
                    }
                }
            }
            PcodeOp def = node.getDef();
            if (def == null) continue;
            String op = def.getMnemonic();
            opCounts.put(op, opCounts.getOrDefault(op, 0) + 1);
            if (depth >= MAX_DEPTH) { depthLimit = true; continue; }
            for (int i = 0; i < def.getNumInputs(); i++) {
                Varnode child = def.getInput(i);
                if (child != null) { nodes.addLast(child); depths.addLast(depth + 1); }
            }
        }
        result.put("nodes", visited.size());
        result.put("nodeLimitReached", !nodes.isEmpty());
        result.put("depthLimitReached", depthLimit);
        result.put("rootKinds", roots);
        result.put("inputRegisters", inputRegisters);
        result.put("memoryAccessPath", accessPath(root, 0, new HashSet<>()));
        result.put("operationCounts", opCounts);
        result.put("stringCategories", stringCategories);
        return result;
    }

    // Reduce a conservative subset of high-pcode pointer expressions to an SP-relative
    // offset. Unknown opcodes, differing phi inputs and non-SP roots are not guessed.
    private Long stackOffset(Varnode node, int depth, Set<Varnode> seen) {
        if (node == null || depth > 12 || !seen.add(node)) return null;
        if (node.getAddress().isStackAddress()) return node.getOffset();
        Register sp = currentProgram.getRegister("sp");
        if (node.isInput() && node.isRegister() && sp != null && node.getAddress().equals(sp.getAddress())) return 0L;
        PcodeOp def = node.getDef();
        if (def == null) return null;
        int opcode = def.getOpcode();
        if ((opcode == PcodeOp.COPY || opcode == PcodeOp.CAST) && def.getNumInputs() == 1)
            return stackOffset(def.getInput(0), depth + 1, seen);
        if ((opcode == PcodeOp.PTRSUB || opcode == PcodeOp.INT_ADD) && def.getNumInputs() == 2 && def.getInput(1).isConstant()) {
            Long base = stackOffset(def.getInput(0), depth + 1, seen);
            if (base == null) return null;
            Varnode constant = def.getInput(1);
            int bits = Math.min(64, constant.getSize() * 8);
            long delta = constant.getOffset();
            if (bits < 64) delta = (delta << (64 - bits)) >> (64 - bits);
            try { return Math.addExact(base, delta); } catch (ArithmeticException ex) { return null; }
        }
        if (opcode == PcodeOp.MULTIEQUAL && def.getNumInputs() > 0) {
            Long same = null;
            for (int i = 0; i < def.getNumInputs(); i++) {
                Long value = stackOffset(def.getInput(i), depth + 1, new HashSet<>(seen));
                if (value == null || (same != null && !same.equals(value))) return null;
                same = value;
            }
            return same;
        }
        return null;
    }

    private Long stackOffset(Varnode node) {
        return stackOffset(node, 0, new HashSet<>());
    }

    private boolean nearObject(long offset, long object) {
        try {
            long delta = Math.subtractExact(offset, object);
            return delta >= 0 && delta < 64;
        } catch (ArithmeticException ex) { return false; }
    }

    private Map<String, Object> stackEvidence(HighFunction high, Varnode argument, Address site, Address start, long size) {
        Map<String, Object> report = new LinkedHashMap<>();
        Long object = stackOffset(argument);
        report.put("stackAddressResolved", object != null);
        report.put("ordering", "instruction-address-only");
        List<Map<String, Object>> writes = new ArrayList<>();
        List<Map<String, Object>> calls = new ArrayList<>();
        int examined = 0, outsideFdeOperations = 0;
        boolean truncated = false;
        if (object != null) {
            Iterator<PcodeOpAST> ops = high.getPcodeOps();
            while (ops.hasNext()) {
                PcodeOpAST op = ops.next();
                if (++examined > 8192) { truncated = true; break; }
                Address pc = op.getSeqnum().getTarget();
                if (pc.compareTo(start) < 0 || pc.compareTo(start.add(size)) >= 0) { outsideFdeOperations++; continue; }
                if (pc.compareTo(site) >= 0) continue;
                Long destination = null;
                Varnode value = null;
                if (op.getOpcode() == PcodeOp.STORE && op.getNumInputs() >= 3) {
                    destination = stackOffset(op.getInput(1));
                    value = op.getInput(2);
                } else if (op.getOutput() != null && op.getOutput().getAddress().isStackAddress() && op.getNumInputs() >= 1) {
                    destination = stackOffset(op.getOutput());
                    value = op.getOutput();
                }
                if (destination != null && value != null && nearObject(destination, object)) {
                    if (writes.size() >= 8) { truncated = true; writes.remove(0); }
                    Map<String, Object> write = new LinkedHashMap<>();
                    write.put("relativeOffset", destination - object);
                    write.put("width", value.getSize());
                    Map<String, Object> source = traceArgument(value);
                    source.remove("operationCounts");
                    write.put("sourceGraph", source);
                    writes.add(write);
                }
                if (op.getOpcode() == PcodeOp.CALL && op.getNumInputs() > 1) {
                    for (int i = 1; i < op.getNumInputs(); i++) {
                        Long argumentOffset = stackOffset(op.getInput(i));
                        if (argumentOffset == null || !nearObject(argumentOffset, object)) continue;
                        if (calls.size() >= 8) { truncated = true; calls.remove(0); }
                        Map<String, Object> call = new LinkedHashMap<>();
                        call.put("site", "0x" + Long.toHexString(pc.getOffset() - currentProgram.getImageBase().getOffset() + originalBase));
                        long target = op.getInput(0).getOffset() - currentProgram.getImageBase().getOffset() + originalBase;
                        call.put("target", "0x" + Long.toHexString(target));
                        call.put("argumentIndex", i - 1);
                        call.put("relativeOffset", argumentOffset - object);
                        calls.add(call);
                    }
                }
            }
        }
        report.put("operationsExamined", examined);
        report.put("outsideFdeOperations", outsideFdeOperations);
        report.put("truncated", truncated);
        report.put("writes", writes);
        report.put("calls", calls);
        return report;
    }

    private String json(Object value) {
        if (value == null) return "null";
        if (value instanceof Boolean || value instanceof Number) return value.toString();
        if (value instanceof Map<?, ?>) {
            List<String> parts = new ArrayList<>();
            for (Map.Entry<?, ?> e : ((Map<?, ?>) value).entrySet()) parts.add(json(e.getKey().toString()) + ":" + json(e.getValue()));
            return "{" + String.join(",", parts) + "}";
        }
        if (value instanceof Iterable<?>) {
            List<String> parts = new ArrayList<>();
            for (Object v : (Iterable<?>) value) parts.add(json(v));
            return "[" + String.join(",", parts) + "]";
        }
        String text = value.toString().replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r");
        return "\"" + text + "\"";
    }

    private DecompInterface boundedDecompiler() {
        DecompInterface decompiler = new DecompInterface();
        DecompileOptions options = new DecompileOptions();
        options.setMaxInstructions(8192);
        options.setMaxJumpTableEntries(128);
        decompiler.setOptions(options);
        return decompiler;
    }

    private void inspectCallees(String[] args) throws Exception {
        if (args.length < 3) throw new IllegalArgumentException("expected image base and bounded functions");
        originalBase = Long.decode(args[1]);
        DecompInterface decompiler = boundedDecompiler();
        boolean opened = decompiler.openProgram(currentProgram);
        List<Map<String, Object>> functions = new ArrayList<>();
        for (int i = 2; i < args.length; i++) {
            String[] parts = args[i].split(":");
            if (parts.length != 2) throw new IllegalArgumentException("bad callee format");
            long start = Long.parseUnsignedLong(parts[0], 16);
            long size = Long.parseUnsignedLong(parts[1], 16);
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("entry", "0x" + Long.toHexString(start));
            row.put("fdeBytes", size);
            row.put("decompiled", false);
            try {
                Function function = boundedFunction(start, size);
                if (!opened || function == null) { row.put("status", "function-unavailable"); functions.add(row); continue; }
                decompiler.flushCache();
                DecompileResults result = decompiler.decompileFunction(function, 40, monitor);
                if (!result.decompileCompleted() || result.getHighFunction() == null) {
                    row.put("status", "decompile-failed-or-timed-out"); functions.add(row); continue;
                }
                row.put("decompiled", true);
                Map<String, Integer> counts = new TreeMap<>();
                Set<String> strings = new TreeSet<>();
                List<Map<String, Object>> calls = new ArrayList<>();
                List<Map<String, Object>> returns = new ArrayList<>();
                boolean truncated = false;
                int examined = 0, directCallCount = 0, outsideFdeOperations = 0;
                Address fdeStart = mapped(start), fdeEnd = fdeStart.add(size);
                Iterator<PcodeOpAST> ops = result.getHighFunction().getPcodeOps();
                while (ops.hasNext()) {
                    PcodeOpAST op = ops.next();
                    if (++examined > 8192) { truncated = true; break; }
                    Address opAddress = op.getSeqnum().getTarget();
                    if (opAddress.compareTo(fdeStart) < 0 || opAddress.compareTo(fdeEnd) >= 0) { outsideFdeOperations++; continue; }
                    String mnemonic = op.getMnemonic();
                    counts.put(mnemonic, counts.getOrDefault(mnemonic, 0) + 1);
                    for (int j = 0; j < op.getNumInputs(); j++) {
                        Varnode input = op.getInput(j);
                        if (input != null && input.isConstant()) {
                            String cat = safeStringCategory(input.getOffset());
                            if (cat != null) strings.add(cat);
                        }
                    }
                    if (op.getOpcode() == PcodeOp.CALL && op.getNumInputs() > 0) {
                        directCallCount++;
                        if (calls.size() >= 16) { truncated = true; continue; }
                        Map<String, Object> call = new LinkedHashMap<>();
                        long site = op.getSeqnum().getTarget().getOffset() - currentProgram.getImageBase().getOffset() + originalBase;
                        long target = op.getInput(0).getOffset() - currentProgram.getImageBase().getOffset() + originalBase;
                        call.put("site", "0x" + Long.toHexString(site));
                        call.put("target", "0x" + Long.toHexString(target));
                        if (calls.isEmpty()) {
                            call.put("firstArgumentAvailable", op.getNumInputs() > 1);
                            if (op.getNumInputs() > 1) call.put("firstArgumentGraph", traceArgument(op.getInput(1)));
                        }
                        calls.add(call);
                    } else if (op.getOpcode() == PcodeOp.RETURN && op.getNumInputs() > 1) {
                        if (returns.size() < 4) returns.add(traceArgument(op.getInput(1)));
                        else truncated = true;
                    }
                }
                row.put("operationCounts", counts);
                row.put("operationsExamined", examined);
                row.put("outsideFdeOperations", outsideFdeOperations);
                row.put("directCallCount", directCallCount);
                row.put("calls", calls);
                row.put("returnGraphs", returns);
                row.put("stringCategories", strings);
                row.put("truncated", truncated);
                row.put("status", "completed");
            } catch (Exception ex) { row.put("status", "analysis-exception-" + ex.getClass().getSimpleName()); }
            functions.add(row);
        }
        decompiler.dispose();
        Map<String, Object> output = new LinkedHashMap<>();
        output.put("kind", "ghidra-callees-probe");
        output.put("functions", functions);
        output.put("limitations", "No forced callee prototype; Ghidra may follow flow beyond the FDE, and SSA can depend on it. Reported operations are FDE-filtered, but do not prove runtime behavior or metadata access.");
        println("WB_GHIDRA_CALLEES:" + json(output));
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length > 0 && args[0].equals("callees")) { inspectCallees(args); return; }
        boolean sourceMode = args.length > 0 && args[0].equals("second-argument");
        if (sourceMode) args = Arrays.copyOfRange(args, 1, args.length);
        int focusArgument = sourceMode ? 1 : 0;
        if (args.length < 4) throw new IllegalArgumentException("expected image base, helper, size and call sites");
        originalBase = Long.decode(args[0]);
        long helperStart = Long.decode(args[1]);
        long helperSize = Long.parseLong(args[2]);
        Function helper = boundedFunction(helperStart, helperSize);
        boolean signatureApplied = helper != null && applyProbeSignature(helper);
        List<Map<String, Object>> rows = new ArrayList<>();
        Map<Long, Function> functions = new HashMap<>();
        DecompInterface decompiler = boundedDecompiler();
        boolean opened = decompiler.openProgram(currentProgram);
        for (int i = 3; i < args.length; i++) {
            String[] parts = args[i].split(":");
            if (parts.length != 3) throw new IllegalArgumentException("bad target format");
            long start = Long.parseUnsignedLong(parts[0], 16);
            long size = Long.parseUnsignedLong(parts[1], 16);
            long site = Long.parseUnsignedLong(parts[2], 16);
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("site", "0x" + Long.toHexString(site));
            row.put("entry", "0x" + Long.toHexString(start));
            row.put("decompiled", false);
            row.put("callFound", false);
            row.put("argumentAvailable", false);
            row.put("argumentIndex", focusArgument);
            try {
                Function function = functions.get(start);
                if (function == null) {
                    function = boundedFunction(start, size);
                    if (function != null) functions.put(start, function);
                }
                if (!opened || function == null || !signatureApplied) {
                    row.put("status", "function-or-signature-unavailable");
                } else {
                    decompiler.flushCache();
                    DecompileResults result = decompiler.decompileFunction(function, 40, monitor);
                    if (!result.decompileCompleted() || result.getHighFunction() == null) {
                        row.put("status", "decompile-failed-or-timed-out");
                    } else {
                        row.put("decompiled", true);
                        HighFunction high = result.getHighFunction();
                        Iterator<PcodeOpAST> ops = high.getPcodeOps(mapped(site));
                        while (ops.hasNext()) {
                            PcodeOpAST op = ops.next();
                            if (op.getOpcode() != PcodeOp.CALL || op.getNumInputs() < 1) continue;
                            if (op.getInput(0).getOffset() != mapped(helperStart).getOffset()) continue;
                            row.put("callFound", true);
                            if (op.getNumInputs() > 1 + focusArgument) {
                                row.put("argumentAvailable", true);
                                Varnode selectedArgument = op.getInput(1 + focusArgument);
                                row.put("argumentGraph", traceArgument(selectedArgument));
                                row.put("stackEvidence", stackEvidence(high, selectedArgument, mapped(site), mapped(start), size));
                            }
                            break;
                        }
                        row.put("status", "completed");
                    }
                }
            } catch (Exception ex) {
                row.put("status", "analysis-exception-" + ex.getClass().getSimpleName());
            }
            rows.add(row);
        }
        decompiler.dispose();
        Map<String, Object> output = new LinkedHashMap<>();
        output.put("kind", "ghidra-bounded-probe");
        output.put("helperSignatureApplied", signatureApplied);
        output.put("forcedPrototype", true);
        output.put("sites", rows);
        output.put("limitations", "Artificial helper prototype and FDE-filtered, address-ordered evidence are heuristic; Ghidra may follow flow beyond the FDE. Writes and calls may be infeasible or overwritten and do not prove runtime behavior.");
        println("WB_GHIDRA_JSON:" + json(output));
    }
}

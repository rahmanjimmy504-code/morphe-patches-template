// Bounded Ghidra probe: output only coarse data-flow statistics, never C or game strings.
// Function ranges come from separately validated ARM64 .eh_frame records.
import java.util.*;

import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.ParameterDefinitionImpl;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.listing.Function;
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

    private Map<String, Object> traceArgument(Varnode root) {
        Map<String, Object> result = new LinkedHashMap<>();
        Map<String, Integer> opCounts = new TreeMap<>();
        Set<String> roots = new TreeSet<>();
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
            if (node.isInput()) roots.add("function-input");
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
        result.put("operationCounts", opCounts);
        result.put("stringCategories", stringCategories);
        return result;
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

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 4) throw new IllegalArgumentException("expected image base, helper, size and call sites");
        originalBase = Long.decode(args[0]);
        long helperStart = Long.decode(args[1]);
        long helperSize = Long.parseLong(args[2]);
        Function helper = boundedFunction(helperStart, helperSize);
        boolean signatureApplied = helper != null && applyProbeSignature(helper);
        List<Map<String, Object>> rows = new ArrayList<>();
        Map<Long, Function> functions = new HashMap<>();
        DecompInterface decompiler = new DecompInterface();
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
                            if (op.getNumInputs() >= 2) {
                                row.put("argumentAvailable", true);
                                row.put("argumentGraph", traceArgument(op.getInput(1)));
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
        output.put("limitations", "Artificial helper prototype and bounded SSA ancestry do not establish stack contents, control-flow feasibility, metadata access, or runtime behavior.");
        println("WB_GHIDRA_JSON:" + json(output));
    }
}

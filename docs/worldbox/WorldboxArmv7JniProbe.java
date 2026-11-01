// Bounded ARMv7 JNI_OnLoad probe. Reports only call targets by safe category.
import java.util.*;

import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;

public class WorldboxArmv7JniProbe extends GhidraScript {
    private String category(Address target) {
        Symbol symbol = currentProgram.getSymbolTable().getPrimarySymbol(target);
        String name = symbol == null ? "" : symbol.getName();
        if (name.contains("RegisterNatives")) return "register-natives";
        if (name.contains("android_log_print")) return "android-log";
        if (name.startsWith("pthread_")) return "pthread";
        if (name.equals("open") || name.equals("read") || name.equals("mmap") ||
            name.equals("munmap") || name.equals("mprotect") || name.equals("dlopen")) return "file-or-loader-api";
        if (symbol != null && symbol.isExternal()) return "other-import";
        return "internal";
    }

    private String address(Address value) {
        return "0x" + Long.toHexString(value.getOffset());
    }

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 2) throw new IllegalArgumentException("Expected function size and fixture flag");
        int size = Integer.parseInt(args[0]);
        boolean fixture = Boolean.parseBoolean(args[1]);
        if (size < 4 || size > 512) throw new IllegalArgumentException("JNI_OnLoad size outside bound");

        Symbol entrySymbol = null;
        SymbolIterator symbols = currentProgram.getSymbolTable().getSymbols("JNI_OnLoad");
        while (symbols.hasNext()) {
            Symbol candidate = symbols.next();
            if (!candidate.isExternal() && candidate.getAddress() != null) {
                if (entrySymbol != null) throw new IllegalStateException("Multiple defined JNI_OnLoad symbols");
                entrySymbol = candidate;
            }
        }
        if (entrySymbol == null) throw new IllegalStateException("Defined JNI_OnLoad symbol not found");
        Address entry = entrySymbol.getAddress();
        Address end = entry.add(size - 1);
        if (!currentProgram.getMemory().contains(entry) || !currentProgram.getMemory().contains(end))
            throw new IllegalStateException("JNI_OnLoad range is outside mapped memory");
        AddressSet body = new AddressSet(entry, end);
        new DisassembleCommand(entry, body, true).applyTo(currentProgram, monitor);
        Function function = getFunctionAt(entry);
        if (function == null) {
            CreateFunctionCmd command = new CreateFunctionCmd(null, entry, body, SourceType.USER_DEFINED);
            if (!command.applyTo(currentProgram, monitor)) throw new IllegalStateException("Could not create bounded JNI_OnLoad function");
            function = getFunctionAt(entry);
        }
        if (function == null || !function.getEntryPoint().equals(entry))
            throw new IllegalStateException("Ghidra did not create the expected JNI_OnLoad function");
        function.setBody(body);

        List<String> calls = new ArrayList<>();
        boolean registerNatives = false;
        InstructionIterator iterator = currentProgram.getListing().getInstructions(body, true);
        while (iterator.hasNext()) {
            Instruction instruction = iterator.next();
            if (!instruction.getFlowType().isCall()) continue;
            for (Reference reference : instruction.getReferencesFrom()) {
                if (!reference.getReferenceType().isCall()) continue;
                String targetCategory = category(reference.getToAddress());
                if (targetCategory.equals("register-natives")) registerNatives = true;
                calls.add("{\"site\":\"" + address(instruction.getAddress()) +
                          "\",\"target\":\"" + address(reference.getToAddress()) +
                          "\",\"category\":\"" + targetCategory + "\"}");
            }
        }
        String json = "{\"kind\":\"worldbox-armv7-jni\",\"entry\":\"" + address(entry) +
                      "\",\"size\":" + size + ",\"calls\":[" + String.join(",", calls) +
                      "],\"registerNatives\":" + registerNatives + "}";
        println("WB_ARMV7_JNI:" + json);
        if (fixture && !registerNatives) throw new IllegalStateException("Synthetic fixture did not reference RegisterNatives");
    }
}

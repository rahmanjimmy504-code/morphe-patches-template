#!/usr/bin/env python3
"""Bounded, heuristic ARM64 file-call argument analysis of a known ELF.

No game code or strings are printed. Modeled paths are static possibilities,
not proof that instructions execute or that a particular file is accessed.
"""
import argparse
from collections import deque
import json
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_OP_IMM, ARM64_OP_MEM, ARM64_OP_REG
from elftools.dwarf.callframe import FDE
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from elftools.elf.sections import SymbolTableSection

import worldbox_native_scan as triage

# Relative virtual addresses observed in the verified ARM64 0.51.4 sample.
SITES = {
    0x18eadd8: 'open', 0x18eae2c: 'read',
    0x18ebdf0: 'open', 0x18ebec4: 'fstat',
    0x18ebf70: 'mmap', 0x18ebfb0: 'munmap',
}
MAX_EH_SIZE = 16 * 1024 * 1024
MAX_FUNCTION = 32 * 1024
MAX_STEPS = 50000
MAX_VALUES = 8
UNKNOWN = frozenset({('unknown', 0)})


def reg(name):
    if name == 'fp': return 'x29'
    if name == 'lr': return 'x30'
    if name in ('xzr', 'wzr'): return 'zero'
    if name.startswith('w') and name[1:].isdigit(): return 'x' + name[1:]
    return name


def read_reg(state, name):
    name = reg(name)
    return frozenset({('const', 0)}) if name == 'zero' else state['regs'].get(name, UNKNOWN)


def write_reg(state, name, value):
    canonical = reg(name)
    if canonical == 'zero': return
    if name.startswith('w') and name[1:].isdigit():
        value = frozenset((kind, n & 0xffffffff if kind == 'const' else n) for kind, n in value)
    state['regs'][canonical] = value


def joined(a, b):
    result = a | b
    return result if len(result) <= MAX_VALUES else UNKNOWN


def merge_state(old, new):
    if old is None:
        return {'regs': dict(new['regs']), 'stack': dict(new['stack'])}, True
    out = {'regs': {}, 'stack': {}}
    changed = False
    for group in ('regs', 'stack'):
        for key in old[group].keys() | new[group].keys():
            value = joined(old[group].get(key, UNKNOWN), new[group].get(key, UNKNOWN))
            out[group][key] = value
            if value != old[group].get(key, UNKNOWN): changed = True
    return out, changed


def copy_state(state):
    return {'regs': dict(state['regs']), 'stack': dict(state['stack'])}


def shifted(value, delta):
    out = set()
    for kind, num in value:
        if kind in ('const', 'stack'):
            out.add((kind, num + delta))
        else:
            out.add(('unknown', 0))
    return frozenset(out) if len(out) <= MAX_VALUES else UNKNOWN


def operand_value(ins, operand, state):
    if operand.type == ARM64_OP_REG:
        return read_reg(state, ins.reg_name(operand.reg))
    if operand.type == ARM64_OP_IMM:
        return frozenset({('const', operand.imm << operand.shift.value)})
    return UNKNOWN


def stack_keys(base, disp):
    keys = {value + disp for kind, value in base if kind == 'stack' and abs(value + disp) <= 131072}
    return keys if len(keys) == len(base) else set()


def describe(values, classify):
    result = set()
    for kind, value in values:
        if kind == 'const': result.add(classify(value))
        elif kind == 'arg': result.add('entry-argument-' + str(value))
        elif kind == 'fd': result.add('return-from-open@' + hex(value))
        elif kind == 'stack': result.add('stack-address')
        else: result.add('unknown')
    return sorted(result)


def analyze_window(data, start, plt, targets, classify):
    """Follow direct intra-window CFG edges with a small may-value analysis."""
    decoder = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    decoder.detail = True
    code = {i.address: i for i in decoder.disasm(data, start)}
    entry = {'regs': {f'x{i}': frozenset({('arg', i)}) for i in range(8)}, 'stack': {}}
    entry['regs']['sp'] = frozenset({('stack', 0)})
    states = {start: entry}
    queue = deque([start])
    seen = set()
    observations = {}
    branch_count = 0
    steps = 0
    while queue and steps < MAX_STEPS:
        pc = queue.popleft()
        ins = code.get(pc)
        if not ins:
            continue
        steps += 1
        seen.add(pc)
        state = copy_state(states[pc])
        ops, mnemonic = ins.operands, ins.mnemonic
        next_pcs = [pc + 4]
        handled = set()
        def name(op): return ins.reg_name(op.reg)
        def setreg(op, value):
            write_reg(state, name(op), value); handled.add(reg(name(op)))

        if mnemonic in ('adrp', 'adr', 'mov', 'movz') and len(ops) >= 2 and ops[0].type == ARM64_OP_REG:
            setreg(ops[0], operand_value(ins, ops[1], state))
        elif mnemonic in ('add', 'sub') and len(ops) >= 3 and ops[0].type == ARM64_OP_REG and ops[2].type == ARM64_OP_IMM:
            delta = ops[2].imm << ops[2].shift.value
            setreg(ops[0], shifted(operand_value(ins, ops[1], state), delta if mnemonic == 'add' else -delta))
        elif mnemonic in ('str', 'stur', 'ldr', 'ldur', 'stp', 'ldp'):
            memindex = next((i for i, op in enumerate(ops) if op.type == ARM64_OP_MEM), None)
            if memindex is not None:
                mem = ops[memindex].mem
                basename = ins.reg_name(mem.base)
                base = read_reg(state, basename)
                slots = stack_keys(base, mem.disp)
                is_load = mnemonic.startswith('ld')
                registers = [op for op in ops[:memindex] if op.type == ARM64_OP_REG]
                for index, op in enumerate(registers):
                    width = 4 if name(op).startswith('w') else 8
                    offsets = {slot + width * index for slot in slots}
                    if is_load:
                        value = frozenset()
                        for offset in offsets:
                            value = joined(value, state['stack'].get(offset, UNKNOWN))
                        setreg(op, value or UNKNOWN)
                    else:
                        value = operand_value(ins, op, state)
                        for offset in offsets:
                            state['stack'][offset] = value
                if ins.writeback:
                    delta = mem.disp
                    if len(ops) > memindex + 1 and ops[memindex + 1].type == ARM64_OP_IMM:
                        delta = ops[memindex + 1].imm
                    write_reg(state, basename, shifted(base, delta))
                    handled.add(reg(basename))
        if mnemonic in ('bl', 'blr'):
            target = ops[0].imm if mnemonic == 'bl' and ops and ops[0].type == ARM64_OP_IMM else None
            api = plt.get(target)
            if pc in targets and api == targets[pc]:
                values = {f'x{i}': read_reg(state, f'x{i}') for i in range(6)}
                current = observations.setdefault(pc, {f'x{i}': frozenset() for i in range(6)})
                for key, value in values.items(): current[key] = joined(current[key], value)
            for i in range(19): state['regs'][f'x{i}'] = UNKNOWN
            state['regs']['x0'] = frozenset({('fd', pc)}) if api in ('open', 'open64', 'openat', 'fopen', 'fopen64') else UNKNOWN
            handled.update(f'x{i}' for i in range(19))
        elif mnemonic == 'b':
            branch_count += 1
            next_pcs = [ops[0].imm] if ops and ops[0].type == ARM64_OP_IMM else []
        elif mnemonic.startswith('b.') or mnemonic in ('cbz', 'cbnz', 'tbz', 'tbnz'):
            branch_count += 1
            if ops and ops[-1].type == ARM64_OP_IMM: next_pcs.append(ops[-1].imm)
        elif mnemonic in ('ret', 'br', 'eret'):
            next_pcs = []
        # Any written register whose instruction semantics are not modeled is
        # invalidated, rather than silently retaining a misleading old value.
        try:
            for written in ins.regs_access()[1]:
                canonical = reg(ins.reg_name(written))
                if canonical not in handled and (canonical.startswith('x') or canonical == 'sp'):
                    state['regs'][canonical] = UNKNOWN
        except Exception:
            pass
        for nxt in next_pcs:
            if nxt in code:
                state_out, changed = merge_state(states.get(nxt), state)
                if changed:
                    states[nxt] = state_out
                    queue.append(nxt)
    results = []
    for pc, expected in sorted(targets.items()):
        observed = observations.get(pc)
        arg_regs = {'open': (0, 1), 'read': (0, 1, 2), 'fstat': (0, 1),
                    'mmap': (0, 1, 2, 3, 4, 5), 'munmap': (0, 1)}.get(expected, ())
        results.append({'site': hex(pc), 'api': expected, 'reachedInModel': observed is not None,
                        'arguments': {f'x{i}': describe(observed[f'x{i}'], classify) for i in arg_regs} if observed else {}})
    return {'decodedInstructions': len(code), 'visitedInstructions': len(seen), 'branchVisits': branch_count,
            'workLimitReached': bool(queue), 'calls': results}


def inspect(path, sites=SITES):
    with Path(path).open('rb') as f:
        elf = ELFFile(f)
        if elf.elfclass != 64 or not elf.little_endian or elf['e_machine'] != 'EM_AARCH64':
            raise ValueError('Expected a little-endian ELF64 AArch64 library')
        relocs = {}
        for sec in elf.iter_sections():
            if not isinstance(sec, RelocationSection) or '.plt' not in sec.name: continue
            symbols = elf.get_section(sec['sh_link'])
            if not isinstance(symbols, SymbolTableSection): continue
            for rel in sec.iter_relocations():
                idx = rel['r_info_sym']
                if idx < symbols.num_symbols():
                    symbol = symbols.get_symbol(idx).name
                    if symbol in triage.WATCHED: relocs[rel['r_offset']] = symbol
        plt, matched = triage.plt_targets(elf, relocs)
        executable = [s for s in elf.iter_sections() if s['sh_flags'] & 4 and s['sh_type'] != 'SHT_NOBITS']
        constants = [s for s in elf.iter_sections() if s['sh_flags'] & 2 and not s['sh_flags'] & (1 | 4) and s['sh_type'] != 'SHT_NOBITS']
        def classify(value):
            sec = next((s for s in constants if s['sh_addr'] <= value < s['sh_addr'] + s['sh_size']), None)
            if not sec:
                return 'small-constant' if 0 <= value <= 4096 else 'other-constant'
            offset = value - sec['sh_addr']
            f.seek(sec['sh_offset'] + offset)
            data = f.read(min(128, sec['sh_size'] - offset))
            category = triage.string_category(data)
            if category: return category
            raw = data.split(b'\0', 1)[0]
            return 'other-static-string' if raw and all(32 <= c <= 126 for c in raw) else 'static-data-address'
        eh = elf.get_section_by_name('.eh_frame')
        frames, status = [], 'missing'
        if eh and eh['sh_size'] > MAX_EH_SIZE:
            status = 'too-large'
        elif eh:
            try:
                dwarf = elf.get_dwarf_info()
                if dwarf.has_EH_CFI():
                    for entry in dwarf.EH_CFI_entries():
                        if isinstance(entry, FDE):
                            lo = entry['initial_location']
                            hi = lo + entry['address_range']
                            if hi > lo: frames.append((lo, hi))
                    status = 'parsed'
                else:
                    status = 'no-cfi'
            except Exception as exc:
                status = 'parse-error-' + type(exc).__name__
        grouped = {}
        locations = []
        for site, api in sorted(sites.items()):
            sec = next((s for s in executable if s['sh_addr'] <= site and site + 4 <= s['sh_addr'] + s['sh_size']), None)
            matched_frames = [(lo, hi) for lo, hi in frames if lo <= site < hi]
            if not sec or not matched_frames:
                locations.append({'site': hex(site), 'api': api, 'status': 'no-executable-unwind-range'})
                continue
            lo, hi = min(matched_frames, key=lambda pair: pair[1] - pair[0])
            if lo < sec['sh_addr'] or hi > sec['sh_addr'] + sec['sh_size'] or hi - lo > MAX_FUNCTION or lo % 4:
                locations.append({'site': hex(site), 'api': api, 'status': 'unusable-or-too-large-unwind-range'})
                continue
            f.seek(sec['sh_offset'] + site - sec['sh_addr'])
            raw = f.read(4)
            import struct
            target = triage.direct_branch(struct.unpack('<I', raw)[0], site) if len(raw) == 4 else None
            if plt.get(target) != api:
                locations.append({'site': hex(site), 'api': api, 'status': 'callsite-not-confirmed'})
                continue
            grouped.setdefault((lo, hi, sec.name), {})[site] = api
        functions = []
        for (lo, hi, section_name), wanted in grouped.items():
            sec = elf.get_section_by_name(section_name)
            f.seek(sec['sh_offset'] + lo - sec['sh_addr'])
            data = f.read(hi - lo)
            result = analyze_window(data, lo, plt, wanted, classify)
            result.update({'start': hex(lo), 'size': hi - lo, 'boundarySource': 'eh-frame-fde'})
            functions.append(result)
        return {'kind': 'arm64-static-flow', 'unwindStatus': status, 'unwindRanges': len(frames),
                'matchedWatchedPltStubs': matched, 'unresolvedSites': locations, 'functions': functions,
                'limitations': 'Heuristic CFG and register tracking with unwind-derived ranges; unsupported instructions, indirect branches, aliases, external callees, dynamic data and incomplete unwind information can cause false positives or missed paths. Static possibilities are not runtime proof.'}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('elf')
    args = parser.parse_args()
    print(json.dumps(inspect(args.elf), separators=(',', ':')))

if __name__ == '__main__': main()

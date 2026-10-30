#!/usr/bin/env python3
"""Bounded, heuristic ARM64 file-call argument analysis of a known ELF.

No game code or strings are printed. Modeled paths are static possibilities,
not proof that instructions execute or that a particular file is accessed.
"""
import argparse
import bisect
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
        elif kind in ('arg', 'arg-derived'):
            out.add(('arg' if delta == 0 and kind == 'arg' else 'arg-derived', num))
        elif kind in ('call', 'call-derived'):
            out.add(('call' if delta == 0 and kind == 'call' else 'call-derived', num))
        elif delta == 0:
            out.add((kind, num))
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


def loaded_from(base):
    """Only record a broad data origin; this does not model memory contents."""
    out = set()
    for kind, value in base:
        if kind in ('arg', 'arg-derived', 'memory-arg'):
            out.add(('memory-arg', value))
        elif kind in ('call', 'call-derived', 'memory-call'):
            out.add(('memory-call', value))
        else:
            out.add(('unknown', 0))
    return frozenset(out) if len(out) <= MAX_VALUES else UNKNOWN


def describe(values, classify):
    result = set()
    for kind, value in values:
        if kind == 'const': result.add(classify(value))
        elif kind == 'arg': result.add('entry-argument-' + str(value))
        elif kind == 'arg-derived': result.add('derived-from-entry-argument-' + str(value))
        elif kind == 'memory-arg': result.add('loaded-through-entry-argument-' + str(value))
        elif kind == 'call': result.add('x0-after-call@' + hex(value))
        elif kind == 'call-derived': result.add('derived-from-x0-after-call@' + hex(value))
        elif kind == 'memory-call': result.add('loaded-through-x0-after-call@' + hex(value))
        elif kind == 'fd': result.add('return-from-open@' + hex(value))
        elif kind == 'stack': result.add('stack-address')
        else: result.add('unknown')
    return sorted(result)


def analyze_window(data, start, plt, targets, classify, capture_returns=False):
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
    returns = {}
    transfers = {}
    call_sites = {}
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
                        if not offsets:
                            value = loaded_from(base)
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
            call_sites[pc] = {'site': hex(pc), 'kind': 'direct' if target is not None else 'indirect',
                              'target': hex(target) if target is not None else None,
                              'recognizedApi': api}
            if pc in targets and api == targets[pc]:
                values = {f'x{i}': read_reg(state, f'x{i}') for i in range(6)}
                current = observations.setdefault(pc, {f'x{i}': frozenset() for i in range(6)})
                for key, value in values.items(): current[key] = joined(current[key], value)
            for i in range(19): state['regs'][f'x{i}'] = UNKNOWN
            state['regs']['x0'] = frozenset({('fd', pc)}) if api in ('open', 'open64', 'openat', 'fopen', 'fopen64') else frozenset({('call', pc)})
            handled.update(f'x{i}' for i in range(19))
        elif mnemonic == 'b':
            branch_count += 1
            branch_target = ops[0].imm if ops and ops[0].type == ARM64_OP_IMM else None
            if pc in targets and plt.get(branch_target) == targets[pc]:
                current = observations.setdefault(pc, {f'x{i}': frozenset() for i in range(6)})
                for i in range(6):
                    key = f'x{i}'
                    current[key] = joined(current[key], read_reg(state, key))
            if capture_returns and branch_target is not None and branch_target not in code:
                old = transfers.get(pc, (branch_target, frozenset()))
                transfers[pc] = (branch_target, joined(old[1], read_reg(state, 'x0')))
            next_pcs = [branch_target] if branch_target is not None else []
        elif mnemonic.startswith('b.') or mnemonic in ('cbz', 'cbnz', 'tbz', 'tbnz'):
            branch_count += 1
            if ops and ops[-1].type == ARM64_OP_IMM: next_pcs.append(ops[-1].imm)
        elif mnemonic in ('ret', 'br', 'eret'):
            if mnemonic == 'ret' and capture_returns:
                returns[pc] = joined(returns.get(pc, frozenset()), read_reg(state, 'x0'))
            elif mnemonic == 'br' and capture_returns:
                old = transfers.get(pc, (None, frozenset()))
                transfers[pc] = (None, joined(old[1], read_reg(state, 'x0')))
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
                    'mmap': (0, 1, 2, 3, 4, 5), 'munmap': (0, 1),
                    'wrapper-open': (0, 1, 2, 3, 4, 5), 'wrapper-mmap': (0, 1, 2, 3, 4, 5),
                    'wrapper-mapparent': (0, 1, 2, 3, 4, 5), 'tail-mapparent': (0, 1, 2, 3, 4, 5),
                    'tail-parent-caller': (0, 1, 2, 3, 4, 5)}.get(expected, ())
        origins = set()
        if observed:
            for index in arg_regs:
                origins.update(value for kind, value in observed[f'x{index}']
                               if kind in ('call', 'call-derived', 'memory-call', 'fd'))
        results.append({'site': hex(pc), 'api': expected, 'reachedInModel': observed is not None,
                        'arguments': {f'x{i}': describe(observed[f'x{i}'], classify) for i in arg_regs} if observed else {},
                        'callOrigins': [call_sites[site] for site in sorted(origins) if site in call_sites][:12],
                        'callOriginsTruncated': len(origins) > 12})
    return_details = []
    for pc, values in sorted(returns.items())[:12]:
        origins = sorted(value for kind, value in values if kind in ('call', 'call-derived', 'memory-call', 'fd'))
        return_details.append({'site': hex(pc), 'x0': describe(values, classify),
                               'callOrigins': [call_sites[site] for site in origins if site in call_sites][:12],
                               'callOriginsTruncated': len(origins) > 12})
    tail_details = [{'site': hex(pc), 'target': hex(target) if target is not None else None,
                     'x0': describe(values, classify)}
                    for pc, (target, values) in sorted(transfers.items())[:12]]
    return {'decodedInstructions': len(code), 'visitedInstructions': len(seen), 'branchVisits': branch_count,
            'workLimitReached': bool(queue), 'calls': results, 'returns': return_details,
            'returnsTruncated': len(returns) > 12, 'tailTransfers': tail_details,
            'tailTransfersTruncated': len(transfers) > 12}


def frame_for_site(frames, starts, site):
    # Normally unwind ranges are disjoint. Check a bounded number of nearby
    # overlapping ranges and choose the narrowest; absence is inconclusive.
    index = bisect.bisect_right(starts, site)
    matches = [(lo, hi) for lo, hi in frames[max(0, index - 32):index] if lo <= site < hi]
    return min(matches, key=lambda item: item[1] - item[0]) if matches else None


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
        # Inspect only a few direct callers of the two generic wrappers. Callers
        # are examples, not an exhaustive interprocedural proof or call graph.
        wrapper_targets = {}
        for (lo, _hi, _name), wanted in grouped.items():
            if 0x18ebdf0 in wanted: wrapper_targets[lo] = 'wrapper-open'
            if 0x18ebf70 in wanted: wrapper_targets[lo] = 'wrapper-mmap'
        refs = {target: {'count': 0, 'sampleSites': []} for target in wrapper_targets}
        caller_scan_truncated = False
        for sec in executable:
            if sec['sh_size'] > triage.MAX_EXEC:
                caller_scan_truncated = True
                continue
            for pc, word in triage.instructions(sec.data(), sec['sh_addr']):
                target = triage.direct_branch(word, pc)
                if target in refs:
                    refs[target]['count'] += 1
                    if len(refs[target]['sampleSites']) < 4:
                        refs[target]['sampleSites'].append(pc)
        sorted_frames = sorted(frames)
        starts = [item[0] for item in sorted_frames]
        # If sampled callers of both wrappers share an unwind range, check a
        # bounded set of direct callers of that shared parent as a second hop.
        frame_sets = []
        for info in refs.values():
            frame_sets.append({frame for site in info['sampleSites']
                               if (frame := frame_for_site(sorted_frames, starts, site))})
        shared = set.intersection(*frame_sets) if len(frame_sets) >= 2 else set()
        parent_targets = {lo: 'wrapper-mapparent' for lo, _hi in sorted(shared)[:4]}
        if parent_targets:
            for target in parent_targets:
                refs[target] = {'count': 0, 'sampleSites': []}
            for sec in executable:
                if sec['sh_size'] > triage.MAX_EXEC:
                    caller_scan_truncated = True
                    continue
                for pc, word in triage.instructions(sec.data(), sec['sh_addr']):
                    target = triage.direct_branch(word, pc)
                    if target in parent_targets:
                        refs[target]['count'] += 1
                        if len(refs[target]['sampleSites']) < 4:
                            refs[target]['sampleSites'].append(pc)
            wrapper_targets.update(parent_targets)
        caller_results = []
        caller_plt = dict(plt)
        caller_plt.update(wrapper_targets)
        for target, info in refs.items():
            for site in info['sampleSites']:
                frame = frame_for_site(sorted_frames, starts, site)
                if not frame:
                    caller_results.append({'site': hex(site), 'target': wrapper_targets[target], 'status': 'no-unwind-range'})
                    continue
                lo, hi = frame
                sec = next((part for part in executable if part['sh_addr'] <= lo and hi <= part['sh_addr'] + part['sh_size']), None)
                if not sec or hi - lo > MAX_FUNCTION or lo % 4:
                    caller_results.append({'site': hex(site), 'target': wrapper_targets[target], 'status': 'unusable-or-too-large-range'})
                    continue
                f.seek(sec['sh_offset'] + lo - sec['sh_addr'])
                result = analyze_window(f.read(hi - lo), lo, caller_plt, {site: wrapper_targets[target]}, classify)
                caller_results.append({'site': hex(site), 'target': wrapper_targets[target], 'function': hex(lo),
                                       'workLimitReached': result['workLimitReached'], 'call': result['calls'][0]})
        caller_refs = {hex(target): {'kind': wrapper_targets[target], 'directCallCount': info['count'],
                                    'sampledSites': len(info['sampleSites'])}
                       for target, info in refs.items()}
        return {'kind': 'arm64-static-flow', 'unwindStatus': status, 'unwindRanges': len(frames),
                'matchedWatchedPltStubs': matched, 'unresolvedSites': locations, 'functions': functions,
                'directWrapperCallers': {'counts': caller_refs, 'examples': caller_results,
                                         'executableScanTruncated': caller_scan_truncated},
                'limitations': 'Heuristic CFG and register tracking with unwind-derived ranges; x0-after-call and loaded-through describe possible origins, not verified return values or memory contents. Unsupported instructions, indirect branches, aliases, external callees, dynamic data and incomplete unwind information can cause false positives or missed paths. Static possibilities are not runtime proof.'}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('elf')
    args = parser.parse_args()
    print(json.dumps(inspect(args.elf), separators=(',', ':')))

if __name__ == '__main__': main()

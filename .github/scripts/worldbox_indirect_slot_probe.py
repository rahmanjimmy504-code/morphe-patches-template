#!/usr/bin/env python3
"""Bounded indirect/GOT-mediated model for known thunk pointer-table slots.

Only aggregate counts, safe addresses, section names, FDE-relative addresses and
decoded ARM64 mnemonics/operands are emitted. No game bytes or unknown strings
leave the analysis. Candidates are static dataflow approximations, not proof of
executed control flow or metadata access.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import struct

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_OP_IMM, ARM64_OP_MEM, ARM64_OP_REG
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection

import worldbox_native_flow as flow
import worldbox_native_xrefs as xrefs
import worldbox_thunk_callers as thunks
from worldbox_bounded_reference_report import annotation, emit_fde_instructions
from worldbox_metadata_slot_probe import compact_xrefs

SLOTS = (0x40f1f70, 0x40f1f78)
KIND = 'worldbox-indirect-slot-probe'
DEFAULT_WINDOW = 0x1000
MAX_SECTION = 96 * 1024 * 1024
MAX_CANDIDATES = 128
MAX_SAMPLES = 12
ADRP_WINDOW = 36
FOLLOW_WINDOW = 64
MAX_FDE_REPORTS = 3
MAX_FDE_SIZE = 32 * 1024


def fde_for_site(frames, starts, site):
    frame = flow.frame_for_site(frames, starts, site)
    if not frame:
        return None, None
    return frame[0], frame[1] - frame[0]


def fde_reports(path, entries, max_reports=MAX_FDE_REPORTS):
    unique = sorted(set(entries))
    reports = []
    for entry in unique[:max_reports]:
        try:
            result = flow.disassemble_fde(path, entry, max_size=MAX_FDE_SIZE)
        except ValueError as exc:
            reports.append({'entry': hex(entry), 'status': 'unavailable', 'reason': str(exc)})
        else:
            reports.append(result)
    return reports, len(unique) > max_reports


def in_slot_ranges(value, slots, window):
    return [slot for slot in slots if slot - window <= value <= slot + window]


def data_candidates(path, slots, window):
    results = {hex(slot): {'samples': [], 'count': 0, 'exactSlotPointerCount': 0,
                           'samplesTruncated': False} for slot in slots}
    by_location = {}
    sections = {}
    total = scanned = 0
    with Path(path).open('rb') as handle:
        elf = ELFFile(handle)
        if elf.elfclass != 64 or not elf.little_endian or elf['e_machine'] != 'EM_AARCH64':
            raise ValueError('Expected a little-endian ELF64 AArch64 library')
        data_sections = [sec for sec in elf.iter_sections()
                         if sec['sh_flags'] & 2 and not sec['sh_flags'] & 4
                         and sec['sh_type'] != 'SHT_NOBITS']
        for sec in data_sections:
            total += sec['sh_size']
            budget = max(0, MAX_SECTION - scanned) & ~7
            if not budget:
                continue
            data = sec.data()[:budget]
            scanned += len(data)
            for offset in range(0, len(data) - 7, 8):
                value = int.from_bytes(data[offset:offset + 8], 'little')
                matched = in_slot_ranges(value, slots, window)
                if not matched:
                    continue
                location = sec['sh_addr'] + offset
                sections[sec.name] = sections.get(sec.name, 0) + 1
                by_location.setdefault(location, {'value': value, 'slots': set(),
                                                  'section': sec.name})
                by_location[location]['slots'].update(matched)
                for slot in matched:
                    result = results[hex(slot)]
                    result['count'] += 1
                    if value == slot:
                        result['exactSlotPointerCount'] += 1
                    if len(result['samples']) < MAX_SAMPLES:
                        result['samples'].append({'section': sec.name,
                                                  'location': hex(location),
                                                  'value': hex(value),
                                                  'deltaFromSlot': hex(slot - value)})
                    else:
                        result['samplesTruncated'] = True
        relocation_count = 0
        relocation_samples = []
        unsupported = []
        for sec in elf.iter_sections():
            if not isinstance(sec, RelocationSection):
                continue
            if xrefs.is_packed_relocation_type(sec['sh_type']):
                unsupported.append(sec.name)
                continue
            for rel in sec.iter_relocations():
                offset = int(rel['r_offset'])
                try:
                    addend = rel['r_addend']
                except (KeyError, ValueError):
                    addend = None
                offset_matches = in_slot_ranges(offset, slots, window)
                addend_matches = (in_slot_ranges(addend, slots, window)
                                  if isinstance(addend, int) else [])
                if not offset_matches and not addend_matches:
                    continue
                relocation_count += 1
                if len(relocation_samples) < MAX_SAMPLES:
                    relocation_samples.append({'section': sec.name,
                                               'rOffset': hex(offset),
                                               'rAddend': hex(addend) if isinstance(addend, int) else None,
                                               'rInfoType': int(rel['r_info_type']),
                                               'offsetMatches': list(map(hex, offset_matches)),
                                               'addendMatches': list(map(hex, addend_matches))})
    limited = dict(list(by_location.items())[:MAX_CANDIDATES])
    for item in limited.values():
        item['slots'] = sorted(item['slots'])
    return {'results': results, 'byLocation': limited,
            'candidateLocations': len(by_location),
            'candidateLocationsTruncated': len(by_location) > MAX_CANDIDATES,
            'candidateSections': dict(sorted(sections.items())),
            'relocationCandidateCount': relocation_count,
            'relocationSamples': relocation_samples,
            'unsupportedRelocationSections': sorted(set(unsupported)),
            'allocatedDataBytes': total, 'allocatedDataScanned': scanned,
            'dataTruncated': scanned < total}


def decoded_ldr(instruction):
    if (instruction.mnemonic not in ('ldr', 'ldur') or
            len(instruction.operands) < 2):
        return None
    destination, source = instruction.operands[0], instruction.operands[1]
    if destination.type != ARM64_OP_REG or source.type != ARM64_OP_MEM:
        return None
    return (instruction.reg_name(destination.reg),
            instruction.reg_name(source.mem.base), int(source.mem.disp))


def code_indirect_loads(path, slots, by_location, frames, starts):
    slot_set = set(slots)
    counts = {hex(slot): {'gotLoadCount': 0, 'slotLoadCount': 0,
                          'indirectCallCount': 0, 'gotLoadSamples': [],
                          'slotLoadSamples': [], 'indirectCallSamples': []}
              for slot in slots}
    total = scanned = 0
    with Path(path).open('rb') as handle:
        elf = ELFFile(handle)
        exec_sections = [sec for sec in elf.iter_sections()
                         if sec['sh_flags'] & 4 and sec['sh_type'] != 'SHT_NOBITS']
        decoder = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
        decoder.detail = True
        for sec in exec_sections:
            total += sec['sh_size']
            budget = max(0, MAX_SECTION - scanned) & ~3
            if not budget:
                continue
            data = sec.data()[:budget]
            scanned += len(data)
            words = list(struct.iter_unpack('<I', data[:len(data) & ~3]))
            for index, (word,) in enumerate(words):
                off = index * 4
                pc = sec['sh_addr'] + off
                page = xrefs.adrp_value(word, pc)
                if page is None or page[1] == 31:
                    continue
                for nextoff in range(off + 4, min(off + ADRP_WINDOW, len(data)), 4):
                    load_pc = sec['sh_addr'] + nextoff
                    raw = data[nextoff:nextoff + 4]
                    instruction = next(decoder.disasm(raw, load_pc), None)
                    parsed = decoded_ldr(instruction) if instruction else None
                    if not parsed:
                        continue
                    destination, base_register, displacement = parsed
                    if base_register != f'x{page[1]}':
                        continue
                    location = page[0] + displacement
                    candidate = by_location.get(location)
                    if not candidate:
                        continue
                    if not xrefs.verify_adrp_add(decoder, data[off:nextoff + 4], pc,
                                                 page[1], load_pc):
                        continue
                    base_value = candidate['value']
                    function, size = fde_for_site(frames, starts, pc)
                    for slot in candidate['slots']:
                        key = hex(slot)
                        row = counts[key]
                        row['gotLoadCount'] += 1
                        if len(row['gotLoadSamples']) < MAX_SAMPLES:
                            row['gotLoadSamples'].append({
                                'slot': key, 'adrp': hex(pc), 'ldr': hex(load_pc),
                                'gotLocation': hex(location),
                                'baseValue': hex(base_value),
                                'destinationRegister': destination,
                                'function': hex(function) if function else None,
                                'size': size})
                    known = {destination: base_value}
                    loaded_slot_registers = {}
                    follow = data[nextoff + 4:nextoff + 4 + FOLLOW_WINDOW]
                    for follow_instruction in decoder.disasm(follow, load_pc + 4):
                        operands = follow_instruction.operands
                        if (follow_instruction.mnemonic in ('add', 'mov') and
                                len(operands) >= 2 and operands[0].type == ARM64_OP_REG):
                            written = follow_instruction.reg_name(operands[0].reg)
                            loaded_slot_registers.pop(written, None)
                            source = operands[1]
                            if source.type == ARM64_OP_REG:
                                source_name = follow_instruction.reg_name(source.reg)
                                if source_name in known:
                                    value = known[source_name]
                                    if (follow_instruction.mnemonic == 'add' and
                                            len(operands) >= 3 and operands[2].type == ARM64_OP_IMM):
                                        value += int(operands[2].imm)
                                    known[written] = value
                            continue
                        parsed_follow = decoded_ldr(follow_instruction)
                        if parsed_follow:
                            dest, base, disp = parsed_follow
                            loaded_slot_registers.pop(dest, None)
                            if base in known:
                                address = known[base] + disp
                                if address in slot_set:
                                    loaded_slot_registers[dest] = address
                                    follow_function, follow_size = fde_for_site(frames, starts,
                                                                                follow_instruction.address)
                                    key = hex(address)
                                    row = counts[key]
                                    row['slotLoadCount'] += 1
                                    if len(row['slotLoadSamples']) < MAX_SAMPLES:
                                        row['slotLoadSamples'].append({
                                            'slot': key, 'site': hex(follow_instruction.address),
                                            'baseRegister': base, 'offset': hex(disp),
                                            'destinationRegister': dest,
                                            'function': hex(follow_function) if follow_function else None,
                                            'size': follow_size})
                            continue
                        if (follow_instruction.mnemonic in ('blr', 'br') and operands and
                                operands[0].type == ARM64_OP_REG):
                            register = follow_instruction.reg_name(operands[0].reg)
                            if register in loaded_slot_registers:
                                slot = loaded_slot_registers[register]
                                key = hex(slot)
                                row = counts[key]
                                row['indirectCallCount'] += 1
                                call_function, call_size = fde_for_site(frames, starts,
                                                                        follow_instruction.address)
                                if len(row['indirectCallSamples']) < MAX_SAMPLES:
                                    row['indirectCallSamples'].append({
                                        'slot': key, 'site': hex(follow_instruction.address),
                                        'register': register,
                                        'function': hex(call_function) if call_function else None,
                                        'size': call_size})
                    break
    return {'results': counts, 'executableBytes': total,
            'executableScanned': scanned, 'execTruncated': scanned < total}


def indirect_slot_report(path, slots=SLOTS, window=DEFAULT_WINDOW):
    with Path(path).open('rb') as handle:
        elf = ELFFile(handle)
        if elf.elfclass != 64 or not elf.little_endian or elf['e_machine'] != 'EM_AARCH64':
            raise ValueError('Expected a little-endian ELF64 AArch64 library')
        frames, unwind_status = thunks.unwind_frames(elf)
        starts = [lo for lo, _ in frames]
    data = data_candidates(path, slots, window)
    code = code_indirect_loads(path, slots, data['byLocation'], frames, starts)
    rows = []
    for slot in slots:
        key = hex(slot)
        xref_report = compact_xrefs(xrefs.inspect(path, target=slot))
        samples = (code['results'][key]['gotLoadSamples'] +
                   code['results'][key]['slotLoadSamples'] +
                   code['results'][key]['indirectCallSamples'])
        entries = [int(item['function'], 16) for item in samples if item.get('function')]
        fde_rows, fde_truncated = fde_reports(path, entries)
        rows.append({
            'slot': key, 'xrefs': xref_report,
            'dataPointerSamples': data['results'][key]['samples'],
            'dataPointerCount': data['results'][key]['count'],
            'exactSlotPointerCount': data['results'][key]['exactSlotPointerCount'],
            'dataSamplesTruncated': data['results'][key]['samplesTruncated'],
            'gotLoadSamples': code['results'][key]['gotLoadSamples'],
            'slotLoadSamples': code['results'][key]['slotLoadSamples'],
            'indirectCallSamples': code['results'][key]['indirectCallSamples'],
            'consumerCounts': {name: code['results'][key][name]
                               for name in ('gotLoadCount', 'slotLoadCount', 'indirectCallCount')},
            'fdeReports': fde_rows, 'fdeReportsTruncated': fde_truncated})
    data_summary = {name: data[name] for name in
                    ('candidateLocations', 'candidateLocationsTruncated', 'candidateSections',
                     'relocationCandidateCount', 'relocationSamples',
                     'unsupportedRelocationSections', 'allocatedDataBytes',
                     'allocatedDataScanned', 'dataTruncated')}
    code_summary = {name: code[name] for name in
                    ('executableBytes', 'executableScanned', 'execTruncated')}
    return {'kind': KIND, 'slots': list(map(hex, slots)), 'window': window,
            'unwindStatus': unwind_status, 'unwindRanges': len(frames),
            'dataScan': data_summary, 'codeScan': code_summary, 'rows': rows,
            'limitations': 'Bounded linear dataflow identifies ADRP+LDR loads of nearby static pointer words and simple register-offset loads/indirect branches. It does not model arbitrary pointer arithmetic, runtime writes, packed relocations, or executed control flow; candidates are not proof of metadata access.'}


def emit_indirect_slot_annotations(report):
    if report.get('kind') != KIND:
        raise RuntimeError('Unexpected WorldBox indirect slot report.')
    print('WorldBox full indirect slot report: ' +
          json.dumps(report, separators=(',', ':')))
    summary = {key: report[key] for key in
               ('slots', 'window', 'unwindStatus', 'unwindRanges',
                'dataScan', 'codeScan', 'limitations')}
    summary['rows'] = [{'slot': row['slot'],
                        'dataPointerCount': row['dataPointerCount'],
                        'exactSlotPointerCount': row['exactSlotPointerCount'],
                        'consumerCounts': row['consumerCounts'],
                        'fdeReportCount': len(row['fdeReports']),
                        'fdeReportsTruncated': row['fdeReportsTruncated']}
                       for row in report['rows']]
    print('::warning title=WorldBox indirect slot summary::' +
          annotation(json.dumps(summary, separators=(',', ':'))))
    for row in report['rows']:
        print('::warning title=WorldBox indirect slot xrefs ' + row['slot'] + '::' +
              annotation(json.dumps(row['xrefs'], separators=(',', ':'))))
        print('::warning title=WorldBox indirect slot data pointers ' + row['slot'] + '::' +
              annotation(json.dumps({'samples': row['dataPointerSamples'],
                                     'count': row['dataPointerCount'],
                                     'exactSlotPointerCount': row['exactSlotPointerCount'],
                                     'samplesTruncated': row['dataSamplesTruncated']},
                                    separators=(',', ':'))))
        consumers = {'slot': row['slot'], 'consumerCounts': row['consumerCounts'],
                     'gotLoadSamples': row['gotLoadSamples'],
                     'slotLoadSamples': row['slotLoadSamples'],
                     'indirectCallSamples': row['indirectCallSamples'],
                     'fdeReportEntries': [item.get('entry') for item in row['fdeReports']],
                     'fdeReportsTruncated': row['fdeReportsTruncated']}
        print('::warning title=WorldBox indirect slot consumers ' + row['slot'] + '::' +
              annotation(json.dumps(consumers, separators=(',', ':'))))
        for fde in row['fdeReports']:
            emit_fde_instructions(fde, 'indirect slot')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('elf')
    parser.add_argument('--slot', action='append', type=lambda value: int(value, 0))
    parser.add_argument('--window', type=lambda value: int(value, 0), default=DEFAULT_WINDOW)
    args = parser.parse_args()
    print(json.dumps(indirect_slot_report(args.elf,
                                          tuple(args.slot) if args.slot else SLOTS,
                                          window=args.window), separators=(',', ':')))


if __name__ == '__main__':
    main()

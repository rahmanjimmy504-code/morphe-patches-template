#!/usr/bin/env python3
"""Bounded static consumers of known metadata-path thunk pointer slots.

Only aggregate counts, safe addresses, section names, FDE-relative addresses and
decoded ARM64 mnemonics/operands are emitted. No game bytes or unknown strings
leave the analysis. References are static candidates, not executed control flow.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import struct

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_OP_MEM, ARM64_OP_REG
from elftools.elf.elffile import ELFFile

import worldbox_native_flow as flow
import worldbox_native_xrefs as xrefs
import worldbox_thunk_callers as thunks

SLOTS = (0x40f1f70, 0x40f1f78, 0x3e45c38)
MAX_SECTION = 96 * 1024 * 1024
MAX_SAMPLES = 12
MAX_FDE_REPORTS = 3
MAX_FDE_SIZE = 32 * 1024
ADRP_WINDOW = 36


def fde_for_site(frames, starts, site):
    frame = flow.frame_for_site(frames, starts, site)
    if not frame:
        return None, None
    return frame[0], frame[1] - frame[0]


def executable_slot_loads(path, slots, frames, starts):
    """Find ADRP+LDR pairs whose computed address is one of the target slots."""
    slot_set = set(slots)
    results = {hex(slot): [] for slot in slots}
    with Path(path).open('rb') as f:
        elf = ELFFile(f)
        sections = [sec for sec in elf.iter_sections()
                    if sec['sh_flags'] & 4 and sec['sh_type'] != 'SHT_NOBITS']
        decoder = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
        decoder.detail = True
        scanned = total = 0
        for sec in sections:
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
                    if (instruction is None or instruction.mnemonic != 'ldr' or
                            len(instruction.operands) < 2):
                        continue
                    destination, source = instruction.operands[0], instruction.operands[1]
                    if destination.type != ARM64_OP_REG or source.type != ARM64_OP_MEM:
                        continue
                    if instruction.reg_name(source.mem.base) != f'x{page[1]}':
                        continue
                    value = page[0] + source.mem.disp
                    if value not in slot_set:
                        continue
                    if not xrefs.verify_adrp_add(decoder, data[off:nextoff + 4], pc,
                                                 page[1], load_pc):
                        continue
                    function, size = fde_for_site(frames, starts, pc)
                    row = results[hex(value)]
                    if len(row) < MAX_SAMPLES:
                        row.append({'adrp': hex(pc), 'ldr': hex(load_pc),
                                    'destinationRegister': instruction.reg_name(destination.reg),
                                    'function': hex(function) if function else None,
                                    'size': size})
                    break
    return {'kind': 'slot-load-scan', 'executableBytes': total,
            'executableScanned': scanned, 'execTruncated': scanned < total,
            'slots': results}


def compact_xrefs(report):
    return {
        'symbolMatches': report.get('symbolMatches'),
        'directTailBranches': report['directTailBranches']['count'],
        'pcRelativeAddressPairs': report['pcRelativeAddressPairs']['count'],
        'matchingRelocations': report['matchingRelocations']['count'],
        'alignedPointerValues': report['alignedPointerValues']['count'],
        'executableBytes': report.get('executableBytes'),
        'executableScanned': report.get('executableScanned'),
        'execTruncated': report.get('execTruncated'),
        'allocatedDataBytes': report.get('allocatedDataBytes'),
        'allocatedDataScanned': report.get('allocatedDataScanned'),
        'dataTruncated': report.get('dataTruncated'),
        'unsupportedRelocationSections': report['matchingRelocations'].get('unsupportedRelocationSections', []),
        'limitations': report.get('limitations')}


def attributed_samples(report, frames, starts):
    rows = []
    for sample in report['pcRelativeAddressPairs']['samples']:
        site = int(sample['adrp'], 16)
        function, size = fde_for_site(frames, starts, site)
        rows.append({**sample, 'function': hex(function) if function else None,
                     'size': size})
    return rows


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


def slot_reference_report(path, slots=SLOTS):
    with Path(path).open('rb') as f:
        elf = ELFFile(f)
        if elf.elfclass != 64 or not elf.little_endian or elf['e_machine'] != 'EM_AARCH64':
            raise ValueError('Expected a little-endian ELF64 AArch64 library')
        frames, unwind_status = thunks.unwind_frames(elf)
        starts = [lo for lo, _ in frames]
    loads = executable_slot_loads(path, slots, frames, starts)
    rows = []
    for slot in slots:
        key = hex(slot)
        xref_report = xrefs.inspect(path, target=slot)
        add_samples = attributed_samples(xref_report, frames, starts)
        load_samples = loads['slots'][key]
        entries = [int(item['function'], 16) for item in add_samples + load_samples
                   if item.get('function')]
        fde_rows, fde_truncated = fde_reports(path, entries)
        rows.append({
            'slot': key, 'xrefs': compact_xrefs(xref_report),
            'adrpAddSamples': add_samples, 'adrpLdrSamples': load_samples,
            'fdeReports': fde_rows, 'fdeReportsTruncated': fde_truncated})
    return {'kind': 'worldbox-metadata-slot-probe', 'slots': list(map(hex, slots)),
            'unwindStatus': unwind_status, 'unwindRanges': len(frames),
            'slotLoadScan': {key: value for key, value in loads.items() if key != 'slots'},
            'rows': rows,
            'limitations': 'Linear instruction decoding identifies static ADRP+ADD and ADRP+LDR candidates, not executed control flow. Indirect references, packed relocations, GOT loads, writable globals and runtime-generated pointers are not fully modeled.'}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('elf')
    parser.add_argument('--slot', action='append', type=lambda value: int(value, 0))
    args = parser.parse_args()
    print(json.dumps(slot_reference_report(args.elf, tuple(args.slot) if args.slot else SLOTS),
                     separators=(',', ':')))


if __name__ == '__main__':
    main()

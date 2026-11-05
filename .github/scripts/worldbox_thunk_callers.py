#!/usr/bin/env python3
"""Bounded static references and data summaries for two observed ARM64 thunks.

Only aggregate counts, ELF-relative addresses, section names and safe string
categories are emitted. No game bytes, raw strings or recovered files leave the
analysis. References are static possibilities, not proof of executed control flow.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct

from elftools.dwarf.callframe import FDE
from elftools.elf.elffile import ELFFile

import worldbox_native_flow as flow
import worldbox_native_scan as triage
import worldbox_native_xrefs as xrefs

THUNKS = (0x3adeaf8, 0x3ae26c4)
STATIC_ADDRESSES = (0x410df08, 0x3e45c38)
MAX_SAMPLES = 8
MAX_SECTION = 96 * 1024 * 1024
STATIC_WINDOW = 128


def allocated_sections(elf):
    return [sec for sec in elf.iter_sections() if sec['sh_flags'] & 2]


def executable_sections(elf):
    return [sec for sec in allocated_sections(elf)
            if sec['sh_flags'] & 4 and sec['sh_type'] != 'SHT_NOBITS']


def section_containing(sections, address):
    return next((sec for sec in sections
                 if sec['sh_addr'] <= address < sec['sh_addr'] + sec['sh_size']), None)


def unwind_frames(elf):
    eh = elf.get_section_by_name('.eh_frame')
    if not eh or eh['sh_size'] > flow.MAX_EH_SIZE:
        return [], 'missing-or-too-large'
    dwarf = elf.get_dwarf_info()
    if not dwarf.has_EH_CFI():
        return [], 'no-cfi'
    frames = sorted((entry['initial_location'],
                     entry['initial_location'] + entry['address_range'])
                    for entry in dwarf.EH_CFI_entries()
                    if isinstance(entry, FDE) and entry['address_range'])
    return frames, 'parsed'


def describe_pointer(value, sections):
    sec = section_containing(sections, value)
    if sec is None:
        return None
    return {'section': sec.name, 'offset': hex(value - sec['sh_addr']),
            'writable': bool(sec['sh_flags'] & 1), 'executable': bool(sec['sh_flags'] & 4)}


def static_data_summary(f, sections, address):
    sec = section_containing(sections, address)
    if sec is None:
        return {'address': hex(address), 'status': 'not-in-allocated-section'}
    offset = address - sec['sh_addr']
    row = {'address': hex(address), 'section': sec.name, 'offset': hex(offset),
           'sectionSize': sec['sh_size'], 'writable': bool(sec['sh_flags'] & 1),
           'executable': bool(sec['sh_flags'] & 4),
           'sectionKind': 'nobits' if sec['sh_type'] == 'SHT_NOBITS' else 'file-backed'}
    if sec['sh_type'] == 'SHT_NOBITS':
        row['status'] = 'no-initial-file-bytes'
        return row
    f.seek(sec['sh_offset'] + offset)
    data = f.read(min(STATIC_WINDOW, sec['sh_size'] - offset))
    printable = 0
    while printable < len(data) and 32 <= data[printable] <= 126:
        printable += 1
    aligned = data[:len(data) & ~7]
    pointers = []
    for index, (value,) in enumerate(struct.iter_unpack('<Q', aligned)):
        if not value:
            continue
        described = describe_pointer(value, sections)
        if described:
            pointers.append({'wordOffset': hex(index * 8), **described})
        if len(pointers) >= 8:
            break
    row.update({'status': 'read', 'bytesRead': len(data),
                'sha256': hashlib.sha256(data).hexdigest(),
                'printablePrefixLength': printable, 'zeroBytes': data.count(0),
                'stringCategory': triage.string_category(data),
                'alignedWordsExamined': len(aligned) // 8,
                'pointerTargets': pointers,
                'pointerTargetsTruncated': len(pointers) >= 8})
    return row


def reference_report(path, thunks=THUNKS, static_addresses=STATIC_ADDRESSES):
    with Path(path).open('rb') as f:
        elf = ELFFile(f)
        if elf.elfclass != 64 or not elf.little_endian or elf['e_machine'] != 'EM_AARCH64':
            raise ValueError('Expected a little-endian ELF64 AArch64 library')
        sections = allocated_sections(elf)
        frames, unwind_status = unwind_frames(elf)
        starts = [lo for lo, _ in frames]
        refs = {hex(target): {'directCalls': 0, 'tailBranches': 0,
                              'alignedPointerValues': 0, 'sampleSites': []}
                for target in thunks}
        exec_scanned = exec_total = 0
        data_scanned = data_total = 0
        for sec in executable_sections(elf):
            exec_total += sec['sh_size']
            budget = max(0, MAX_SECTION - exec_scanned) & ~3
            if not budget:
                continue
            data = sec.data()[:budget]
            exec_scanned += len(data)
            for pc, word in triage.instructions(data, sec['sh_addr']):
                bl_target = triage.direct_branch(word, pc)
                b_target = xrefs.direct_tail(word, pc)
                for target in thunks:
                    if bl_target == target:
                        kind = 'directCalls'
                    elif b_target == target:
                        kind = 'tailBranches'
                    else:
                        continue
                    entry = refs[hex(target)]
                    entry[kind] += 1
                    if len(entry['sampleSites']) < MAX_SAMPLES:
                        frame = flow.frame_for_site(frames, starts, pc)
                        entry['sampleSites'].append({
                            'site': hex(pc), 'kind': kind,
                            'function': hex(frame[0]) if frame else None,
                            'size': frame[1] - frame[0] if frame else None})
        for sec in sections:
            if sec['sh_type'] == 'SHT_NOBITS':
                continue
            data_total += sec['sh_size']
            budget = max(0, MAX_SECTION - data_scanned)
            if not budget:
                continue
            data = sec.data()[:budget]
            data_scanned += len(data)
            first = (-sec['sh_addr']) % 8
            aligned = data[first:first + ((len(data) - first) // 8) * 8] if len(data) >= first else b''
            for value, in struct.iter_unpack('<Q', aligned):
                for target in thunks:
                    if value == target:
                        refs[hex(target)]['alignedPointerValues'] += 1
        static_rows = [static_data_summary(f, sections, address) for address in static_addresses]
    return {'kind': 'worldbox-thunk-references',
            'unwindStatus': unwind_status, 'unwindRanges': len(frames),
            'thunks': refs, 'staticData': static_rows,
            'executableBytes': exec_total, 'executableScanned': exec_scanned,
            'execTruncated': exec_scanned < exec_total,
            'allocatedDataBytes': data_total, 'allocatedDataScanned': data_scanned,
            'dataTruncated': data_scanned < data_total,
            'limitations': 'Linear instruction decoding and aligned-word matching identify static candidates, not executed control flow. Indirect references, packed relocations, runtime-generated pointers and writable globals are not fully modeled.'}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('elf')
    args = parser.parse_args()
    print(json.dumps(reference_report(args.elf), separators=(',', ':')))


if __name__ == '__main__':
    main()

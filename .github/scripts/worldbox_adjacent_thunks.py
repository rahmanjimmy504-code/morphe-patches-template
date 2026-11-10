#!/usr/bin/env python3
"""Bounded reference and exact-FDE report for selected ARM64 code targets.

Only aggregate counts, safe addresses, section names, FDE-relative addresses and
decoded ARM64 mnemonics/operands are emitted. No game bytes or unknown strings
leave the analysis. References are static candidates, not executed control flow.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from elftools.elf.elffile import ELFFile

import worldbox_native_flow as flow
import worldbox_native_xrefs as xrefs
import worldbox_thunk_callers as thunk_helpers

ADJACENT_THUNKS = (0x3ae2828, 0x3ae2594)
BRANCH_DESTINATIONS = (0x1890260, 0x3adec0c)
FILE_ADAPTER_CALLER = 0x1890260
FILE_ADAPTER_CALLEES = (0x18eb7a4, 0x18edbb8)
FILE_ADAPTER_TARGETS = (FILE_ADAPTER_CALLER,) + FILE_ADAPTER_CALLEES
FILE_ADAPTER_KIND = 'worldbox-file-adapter-callee-probe'
FILE_ADAPTER_TRACE_TARGETS = (
    '0x1890260', '0x18eb7a4', '0x18edbb8', '0x18eb1a0',
    '0x18ebcb4', '0x18ebe74', '0x18ebfac',
    '0x3bf8dd0', '0x3bf8de0',
    '0x3bf90c0', '0x3bf9030', '0x3bf9700', '0x3bf9710',
)
FILE_HELPER_TARGETS = (0x18d3bec, 0x18d3c20, 0x18ee1b8)
FILE_HELPER_KIND = 'worldbox-file-helper-callee-probe'
FILE_HELPER_TRACE_TARGETS = (
    '0x1890260', '0x18eb7a4', '0x18edbb8',
    '0x18d3bec', '0x18d3c20', '0x18ee1b8',
    '0x18eb1a0', '0x18ebcb4', '0x18ebe74', '0x18ebfac',
    '0x3bf8dd0', '0x3bf8de0',
    '0x3bf90c0', '0x3bf9030', '0x3bf9700', '0x3bf9710',
)
THUNKS = ADJACENT_THUNKS
DEFAULT_KIND = 'worldbox-adjacent-thunk-probe'
MAX_FDE_REPORTS = 4
MAX_FDE_SIZE = 32 * 1024
MAX_SAMPLES = 12


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


def attributed_site(site, frames, starts, extra=None):
    function, size = fde_for_site(frames, starts, site)
    row = {'site': hex(site), 'function': hex(function) if function else None, 'size': size}
    if extra:
        row.update(extra)
    return row


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


def reference_report(path, thunks=THUNKS, kind=DEFAULT_KIND):
    with Path(path).open('rb') as f:
        elf = ELFFile(f)
        if elf.elfclass != 64 or not elf.little_endian or elf['e_machine'] != 'EM_AARCH64':
            raise ValueError('Expected a little-endian ELF64 AArch64 library')
        frames, unwind_status = thunk_helpers.unwind_frames(elf)
        starts = [lo for lo, _ in frames]
    rows = []
    for target in thunks:
        xref_report = xrefs.inspect(path, target=target)
        fde_start, fde_size = fde_for_site(frames, starts, target)
        tail_samples = [attributed_site(int(site, 16), frames, starts, {'kind': 'tailBranch'})
                        for site in xref_report['directTailBranches']['sampleSites']][:MAX_SAMPLES]
        pair_samples = []
        for sample in xref_report['pcRelativeAddressPairs']['samples']:
            site = int(sample['adrp'], 16)
            function, size = fde_for_site(frames, starts, site)
            pair_samples.append({**sample, 'function': hex(function) if function else None,
                                 'size': size})
        reloc_samples = xref_report['matchingRelocations']['samples'][:MAX_SAMPLES]
        pointer_samples = xref_report['alignedPointerValues']['samples'][:MAX_SAMPLES]
        entries = []
        if fde_start:
            entries.append(fde_start)
        for item in tail_samples + pair_samples:
            if item.get('function'):
                entries.append(int(item['function'], 16))
        fde_rows, fde_truncated = fde_reports(path, entries)
        rows.append({'target': hex(target), 'fdeStart': hex(fde_start) if fde_start else None,
                     'fdeSize': fde_size, 'xrefs': compact_xrefs(xref_report),
                     'tailSamples': tail_samples, 'pcRelativeSamples': pair_samples,
                     'relocationSamples': reloc_samples, 'pointerSamples': pointer_samples,
                     'fdeReports': fde_rows, 'fdeReportsTruncated': fde_truncated})
    return {'kind': kind, 'targets': list(map(hex, thunks)),
            'unwindStatus': unwind_status, 'unwindRanges': len(frames), 'rows': rows,
            'limitations': 'Linear instruction decoding and aligned-word matching identify static candidates, not executed control flow. Indirect references, packed relocations, GOT loads, writable globals and runtime-generated pointers are not fully modeled.'}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('elf')
    parser.add_argument('--target', action='append', type=lambda value: int(value, 0))
    parser.add_argument('--kind', default=DEFAULT_KIND)
    args = parser.parse_args()
    print(json.dumps(reference_report(args.elf, tuple(args.target) if args.target else THUNKS,
                                     kind=args.kind), separators=(',', ':')))


if __name__ == '__main__':
    main()

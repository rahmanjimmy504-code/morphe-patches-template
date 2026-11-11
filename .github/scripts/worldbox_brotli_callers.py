#!/usr/bin/env python3
"""Bounded static callers of the hash-gated Brotli decompression wrapper.

Only safe addresses, counts, section names, FDE-relative addresses and decoded
ARM64 mnemonics/operands are emitted. No game bytes or unknown strings leave
the analysis. Direct BL/tail matches are static candidates, not executed flow.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from elftools.elf.elffile import ELFFile

import worldbox_native_flow as flow
import worldbox_native_scan as triage
import worldbox_native_xrefs as xrefs
import worldbox_thunk_callers as thunks
from worldbox_bounded_reference_report import annotation, emit_fde_instructions

KIND = 'worldbox-brotli-callers'
EXPECTED_IL2CPP = '1d644b98fec97a35630495c695515861acd2c18209beaae6471a650db65def87'
TARGETS = (0x189941c, 0x1913f84, 0x1914114)
TRACE_TARGETS = ('0x189941c', '0x1913f84', '0x1914114', '0x3bf9220',
                 '0x3bf90c0', '0x3bf9030', '0x3bf9700', '0x3bf9710',
                 '0x18904e0', '0x18eb1a0', '0x1890260', '0x18eb7a4',
                 '0x18edbb8', '0x18ee1b8')
MAX_SECTION = 96 * 1024 * 1024
MAX_SAMPLES = 12
MAX_FDE_REPORTS = 6
MAX_FDE_SIZE = 32 * 1024
MAX_GHIDRA_ADDRESSES = 6
LIMITATIONS = (
    'This bounded linear scan finds direct BL and tail-branch candidates to the Brotli wrapper and its two small state helpers in the hash-gated ARM64 libil2cpp.so. '
    'It does not model indirect calls, packed relocations, GOT loads, writable globals, runtime-generated pointers, or executed control flow. '
    'It emits no raw game bytes, unknown strings, metadata content, loader identification or Premium behavior.'
)


def sha256_file(path):
    with Path(path).open('rb') as handle:
        return hashlib.file_digest(handle, 'sha256').hexdigest()


def callers_report(path, expected_sha=EXPECTED_IL2CPP, targets=TARGETS):
    path = Path(path)
    sha = sha256_file(path)
    if expected_sha is not None and sha != expected_sha:
        raise ValueError('libil2cpp.so hash mismatch; refusing caller scan.')
    with path.open('rb') as handle:
        elf = ELFFile(handle)
        if elf.elfclass != 64 or not elf.little_endian or elf['e_machine'] != 'EM_AARCH64':
            raise ValueError('Expected a little-endian ELF64 AArch64 library')
        frames, unwind_status = thunks.unwind_frames(elf)
        starts = [low for low, _ in frames]
        exec_sections = [section for section in elf.iter_sections()
                         if section['sh_flags'] & 4 and section['sh_type'] != 'SHT_NOBITS']
        exec_total = sum(section['sh_size'] for section in exec_sections)
        scanned = 0
        samples = {target: [] for target in targets}
        counts = {target: 0 for target in targets}
        for section in exec_sections:
            budget = max(0, MAX_SECTION - scanned) & ~3
            if not budget:
                continue
            data = section.data()[:budget]
            scanned += len(data)
            section_name = section.name
            for pc, word in triage.instructions(data, section['sh_addr']):
                candidates = (('bl', triage.direct_branch(word, pc)),
                              ('tail', xrefs.direct_tail(word, pc)))
                for kind, target in candidates:
                    if target not in counts:
                        continue
                    counts[target] += 1
                    frame = flow.frame_for_site(frames, starts, pc)
                    function, size = (frame[0], frame[1] - frame[0]) if frame else (None, None)
                    if len(samples[target]) < MAX_SAMPLES:
                        samples[target].append({
                            'site': hex(pc), 'kind': kind, 'target': hex(target),
                            'section': section_name,
                            'function': hex(function) if function is not None else None,
                            'size': size,
                        })
                    break
    rows = []
    for target in targets:
        entries = []
        for item in samples[target]:
            if item['function'] and item['size'] is not None and item['size'] <= flow.MAX_FUNCTION:
                entries.append(int(item['function'], 16))
        fde_rows, truncated = fde_reports(path, entries)
        rows.append({
            'target': hex(target), 'directCallCount': counts[target],
            'callSamples': samples[target], 'fdeReports': fde_rows,
            'fdeReportEntries': [item.get('entry') for item in fde_rows],
            'fdeReportsTruncated': truncated,
        })
    addresses = []
    for row in rows:
        addresses.extend(int(item, 16) for item in row['fdeReportEntries']
                         if item and row['fdeReports'] and
                         any(fde.get('entry') == item and fde.get('status') != 'unavailable'
                             for fde in row['fdeReports']))
    all_addresses = sorted(set(addresses))
    ghidra_addresses = [hex(value) for value in all_addresses[:MAX_GHIDRA_ADDRESSES]]
    return {
        'kind': KIND,
        'library': 'libil2cpp.so', 'sha256': sha,
        'targets': [hex(target) for target in targets],
        'traceTargets': list(TRACE_TARGETS),
        'executableBytes': exec_total, 'executableScanned': scanned,
        'execTruncated': scanned < exec_total,
        'unwindStatus': unwind_status, 'unwindRanges': len(frames),
        'ghidraAddresses': ghidra_addresses,
        'ghidraAddressesTruncated': len(all_addresses) > len(ghidra_addresses),
        'rows': rows,
        'limitations': LIMITATIONS,
    }


def fde_reports(path, entries, max_reports=MAX_FDE_REPORTS):
    unique = sorted(set(entries))
    reports = []
    for entry in unique[:max_reports]:
        try:
            result = flow.disassemble_fde(path, entry, max_size=MAX_FDE_SIZE)
        except ValueError as exc:
            reports.append({'entry': hex(entry), 'status': 'unavailable',
                            'reason': str(exc)})
        else:
            reports.append(result)
    return reports, len(unique) > max_reports


def emit_callers_annotations(report):
    if report.get('kind') != KIND:
        raise RuntimeError('Unexpected WorldBox Brotli callers report.')
    print('WorldBox full Brotli callers report: ' +
          json.dumps(report, separators=(',', ':')))
    summary = {key: report[key] for key in
               ('library', 'sha256', 'targets', 'traceTargets',
                'executableBytes', 'executableScanned', 'execTruncated',
                'unwindStatus', 'unwindRanges', 'ghidraAddresses',
                'ghidraAddressesTruncated', 'limitations')}
    print('::warning title=WorldBox brotli callers summary::' +
          annotation(json.dumps(summary, separators=(',', ':'))))
    emitted = set()
    for row in report['rows']:
        compact = {key: row[key] for key in
                   ('target', 'directCallCount', 'callSamples',
                    'fdeReportEntries', 'fdeReportsTruncated')}
        print('::warning title=WorldBox brotli callers ' + row['target'] + '::' +
              annotation(json.dumps(compact, separators=(',', ':'))))
        for fde in row['fdeReports']:
            key = (fde.get('entry'), fde.get('size'), fde.get('status'))
            if key in emitted:
                continue
            emitted.add(key)
            emit_fde_instructions(fde, 'brotli callers')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('native')
    parser.add_argument('--expected-sha', default=EXPECTED_IL2CPP)
    args = parser.parse_args()
    print(json.dumps(callers_report(args.native, args.expected_sha),
                     separators=(',', ':')))


if __name__ == '__main__':
    main()

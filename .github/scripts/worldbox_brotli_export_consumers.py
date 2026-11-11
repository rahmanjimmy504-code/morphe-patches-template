#!/usr/bin/env python3
"""Bounded indirect-consumer model for the WorldBox Brotli export/state wrappers.

This hash-gated ARM64 probe combines static references, direct branch counts,
bounded ADRP+ADD / LDR-literal function-pointer models, exact predefined
Brotli API-name literals and FDE-bounded dynamic-loader call counts. It emits
no raw game bytes, unknown strings, metadata content or Premium behavior.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path

from elftools.elf.elffile import ELFFile

import worldbox_native_flow as flow
import worldbox_native_xrefs as xrefs
import worldbox_native_scan as triage
import worldbox_thunk_callers as thunks
import worldbox_native_literal_refs as refs
from worldbox_bounded_reference_report import annotation, emit_fde_instructions
from worldbox_brotli_callers import symbol_descriptors
from worldbox_metadata_slot_probe import compact_xrefs

KIND = 'worldbox-brotli-export-consumers'
EXPECTED_IL2CPP = '1d644b98fec97a35630495c695515861acd2c18209beaae6471a650db65def87'
TARGETS = {
    'brotli_decompress_export': 0x189941c,
    'state_create_caller': 0x189932c,
    'state_destroy_caller': 0x18993dc,
    'state_initialize_helper': 0x1913f84,
    'state_destroy_helper': 0x1914114,
}
INDIRECT_TARGETS = tuple(TARGETS.values())
NAME_NEEDLES = {
    'brotli_decompress_name': 'BrotliDecoderDecompress',
    'brotli_decompress_stream_name': 'BrotliDecoderDecompressStream',
}
DEFAULT_WATCHED_STUBS = {
    0x3bf9d50: 'dlopen',
    0x3bf9d60: 'dlerror',
    0x3bf9d70: 'dlsym',
    0x3bf9d80: 'dlclose',
    0x3bf9220: 'brotli-decompress-stream-import',
}
OBSERVABLE_STUB_LABELS = frozenset(DEFAULT_WATCHED_STUBS.values()) | frozenset({
    'dlopen', 'android_dlopen_ext', 'dlsym', 'dlerror', 'dlclose'})
TRACE_TARGETS = ('0x189941c', '0x189932c', '0x18993dc', '0x1913f84',
                 '0x1914114', '0x3bf9220', '0x3bf9d50', '0x3bf9d60',
                 '0x3bf9d70', '0x3bf9d80')
MAX_SECTION = 96 * 1024 * 1024
MAX_SAMPLES = 12
MAX_FDE_REPORTS = 6
MAX_FDE_SIZE = 32 * 1024
LIMITATIONS = (
    'Bounded linear static model of a predefined Brotli dynamic export, two state-lifecycle callers and their state helpers in the hash-gated ARM64 libil2cpp.so. '
    'It models exact static function pointers, simple ADRP+ADD or 64-bit LDR-literal address materialization followed by BLR/BR, exact predefined Brotli API-name literals, and direct calls to predefined dynamic-loader/Brotli import stubs inside unwind-bounded functions. '
    'It does not model arbitrary pointer arithmetic, runtime writes, packed relocations, JNI registration, dynamic symbol resolution or executed control flow; candidates are not proof of metadata loading or Premium behavior. '
    'Only predefined names, counts, safe addresses, section names and decoded mnemonics are emitted.'
)


def sha256_file(path):
    with Path(path).open('rb') as handle:
        return hashlib.file_digest(handle, 'sha256').hexdigest()


def observed_stub_labels(elf, watched):
    imports = xrefs.safe_import_plt(elf)
    result = {}
    for address in watched:
        name = imports.get(address, 'absent-or-unresolved')
        result[hex(address)] = name if name in OBSERVABLE_STUB_LABELS else 'other-import'
    return result


def direct_callers(path, targets, frames, starts, max_section=MAX_SECTION,
                   max_samples=MAX_SAMPLES):
    target_set = set(targets.values())
    counts = {label: 0 for label in targets}
    reverse = {value: label for label, value in targets.items()}
    samples = {label: [] for label in targets}
    function_addresses = []
    seen_functions = set()
    total = scanned = 0
    with Path(path).open('rb') as handle:
        elf = ELFFile(handle)
        sections = [sec for sec in elf.iter_sections()
                    if sec['sh_flags'] & 4 and sec['sh_type'] != 'SHT_NOBITS']
        for sec in sections:
            total += sec['sh_size']
            budget = max(0, max_section - scanned) & ~3
            if not budget:
                continue
            data = sec.data()[:budget]
            scanned += len(data)
            for offset, (word,) in enumerate(struct.iter_unpack('<I', data[:len(data) & ~3])):
                pc = sec['sh_addr'] + offset * 4
                destination = triage.direct_branch(word, pc)
                kind = 'bl'
                if destination not in target_set:
                    destination = xrefs.direct_tail(word, pc)
                    kind = 'tail'
                if destination not in target_set:
                    continue
                label = reverse[destination]
                counts[label] += 1
                frame = flow.frame_for_site(frames, starts, pc)
                function, size = (frame[0], frame[1] - frame[0]) if frame else (None, None)
                if function is not None and function not in seen_functions:
                    seen_functions.add(function)
                    function_addresses.append(function)
                if len(samples[label]) < max_samples:
                    samples[label].append({'site': hex(pc), 'kind': kind,
                                           'target': hex(destination),
                                           'section': sec.name,
                                           'function': hex(function) if function is not None else None,
                                           'size': size})
    return {'counts': counts, 'samples': samples,
            'samplesTruncated': {label: counts[label] > len(samples[label])
                                 for label in targets},
            'functionAddresses': [hex(value) for value in function_addresses],
            'executableBytes': total, 'executableScanned': scanned,
            'execTruncated': scanned < total}


def fde_reports(path, entries, max_reports=MAX_FDE_REPORTS):
    unique = sorted({int(value, 0) if isinstance(value, str) else value
                     for value in entries})
    rows = []
    for entry in unique[:max_reports]:
        try:
            rows.append(flow.disassemble_fde(path, entry, max_size=MAX_FDE_SIZE))
        except ValueError as exc:
            rows.append({'entry': hex(entry), 'status': 'unavailable',
                         'reason': str(exc)})
    return rows, len(unique) > max_reports


def export_consumers_report(path, expected_sha=EXPECTED_IL2CPP,
                            targets=TARGETS, watched_stubs=None):
    path = Path(path)
    sha = sha256_file(path)
    if expected_sha is not None and sha != expected_sha:
        raise ValueError('libil2cpp.so hash mismatch; refusing export-consumer scan.')
    watched = dict(DEFAULT_WATCHED_STUBS if watched_stubs is None else watched_stubs)
    with path.open('rb') as handle:
        elf = ELFFile(handle)
        if elf.elfclass != 64 or not elf.little_endian or elf['e_machine'] != 'EM_AARCH64':
            raise ValueError('Expected a little-endian ELF64 AArch64 library')
        frames, unwind_status = thunks.unwind_frames(elf)
        observed = observed_stub_labels(elf, watched)
    starts = [low for low, _ in frames]
    static = {}
    symbols = {}
    for label, address in targets.items():
        static[label] = compact_xrefs(xrefs.inspect(path, target=address))
        symbols[label] = symbol_descriptors(path, address)
    calls = direct_callers(path, targets, frames, starts)
    indirect = refs.indirect_call_sites(path, INDIRECT_TARGETS, frames, starts)
    literals = refs.literal_occurrences(path, NAME_NEEDLES)
    name_refs = refs.adrp_add_reference_sites(path, literals['referenceAddresses'],
                                              frames, starts)
    loader_calls = refs.function_direct_calls(path, name_refs['functionAddresses'],
                                              watched)
    anchors = []
    seen = set()
    for source in (calls['functionAddresses'], indirect['functionAddresses'],
                   name_refs['functionAddresses']):
        for item in source:
            if item not in seen:
                seen.add(item)
                anchors.append(item)
    ghidra_addresses = anchors[:MAX_FDE_REPORTS]
    fde_rows, fde_truncated = fde_reports(path, ghidra_addresses)
    return {
        'kind': KIND, 'library': 'libil2cpp.so', 'sha256': sha,
        'targets': {label: hex(address) for label, address in targets.items()},
        'nameNeedles': NAME_NEEDLES, 'watchedStubs': {
            hex(address): label for address, label in watched.items()},
        'observedStubLabels': observed,
        'traceTargets': list(TRACE_TARGETS),
        'unwindStatus': unwind_status, 'unwindRanges': len(frames),
        'staticReferences': static, 'symbolDescriptors': symbols,
        'directCallers': calls, 'indirectModel': indirect,
        'literalModel': literals, 'nameReferences': name_refs,
        'loaderCalls': loader_calls,
        'ghidraAddresses': ghidra_addresses,
        'ghidraAddressesTruncated': len(anchors) > len(ghidra_addresses),
        'fdeReports': fde_rows, 'fdeReportsTruncated': fde_truncated,
        'limitations': LIMITATIONS,
    }


def emit_export_consumer_annotations(report):
    if report.get('kind') != KIND:
        raise RuntimeError('Unexpected WorldBox Brotli export-consumer report.')
    print('WorldBox full Brotli export-consumer report: ' +
          json.dumps(report, separators=(',', ':')))
    summary = {key: report[key] for key in
               ('library', 'sha256', 'targets', 'nameNeedles', 'watchedStubs',
                'observedStubLabels', 'traceTargets', 'unwindStatus',
                'unwindRanges', 'ghidraAddresses',
                'ghidraAddressesTruncated', 'fdeReportsTruncated',
                'limitations')}
    print('::warning title=WorldBox Brotli export consumer summary::' +
          annotation(json.dumps(summary, separators=(',', ':'))))
    for label, target in report['targets'].items():
        payload = {'label': label, 'target': target,
                   'staticReferences': report['staticReferences'][label],
                   'symbolDescriptors': report['symbolDescriptors'][label],
                   'directCallCount': report['directCallers']['counts'][label],
                   'directSamples': report['directCallers']['samples'][label]}
        print('::warning title=WorldBox Brotli export consumer ' + label + '::' +
              annotation(json.dumps(payload, separators=(',', ':'))))
    print('::warning title=WorldBox Brotli export consumer indirect model::' +
          annotation(json.dumps({
              'counts': report['indirectModel']['counts'],
              'pointerLocations': report['indirectModel']['pointerLocations'],
              'materializationSamples': report['indirectModel']['materializationSamples'],
              'indirectCallSamples': report['indirectModel']['indirectCallSamples'],
              'samplesTruncated': report['indirectModel']['samplesTruncated'],
              'functionAddresses': report['indirectModel']['functionAddresses'],
              'executableScanned': report['indirectModel']['executableScanned'],
              'execTruncated': report['indirectModel']['execTruncated'],
          }, separators=(',', ':'))))
    print('::warning title=WorldBox Brotli export consumer literal model::' +
          annotation(json.dumps({
              'results': report['literalModel']['results'],
              'referenceAddresses': report['literalModel']['referenceAddresses'],
              'referenceAddressesTruncated': report['literalModel']['referenceAddressesTruncated'],
              'allocatedScanned': report['literalModel']['allocatedScanned'],
              'allocatedTruncated': report['literalModel']['allocatedTruncated'],
          }, separators=(',', ':'))))
    print('::warning title=WorldBox Brotli export consumer name references::' +
          annotation(json.dumps({
              'count': report['nameReferences']['count'],
              'sites': report['nameReferences']['sites'],
              'sitesTruncated': report['nameReferences']['sitesTruncated'],
              'functionAddresses': report['nameReferences']['functionAddresses'],
          }, separators=(',', ':'))))
    print('::warning title=WorldBox Brotli export consumer loader calls::' +
          annotation(json.dumps(report['loaderCalls'], separators=(',', ':'))))
    emitted = set()
    for fde in report['fdeReports']:
        key = (fde.get('entry'), fde.get('size'), fde.get('status'))
        if key in emitted:
            continue
        emitted.add(key)
        emit_fde_instructions(fde, 'Brotli export consumer')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('native')
    parser.add_argument('--expected-sha', default=EXPECTED_IL2CPP)
    args = parser.parse_args()
    print(json.dumps(export_consumers_report(args.native, args.expected_sha),
                     separators=(',', ':')))


if __name__ == '__main__':
    main()

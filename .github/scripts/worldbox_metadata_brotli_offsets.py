#!/usr/bin/env python3
"""Safe bounded Brotli start-offset trial for hash-gated metadata.

Only numeric offsets, codec statuses, output sizes/hashes, numeric header
words and aggregate entropy are emitted. Raw game bytes, decoded strings and
unknown symbol names never leave the analysis. This does not recover metadata
or identify a loader/decryptor.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import struct

import brotli

from worldbox_bounded_reference_report import annotation
from worldbox_metadata_stream_probe import (
    EXPECTED_METADATA_BYTES,
    EXPECTED_METADATA_SHA256,
    EXPECTED_VERSION,
    MAX_OUTPUT,
    STANDARD_MAGIC,
    output_descriptor,
    sha256_file,
)

KIND = 'worldbox-metadata-brotli-offsets'
MAX_PREFIX_BYTES = 64 * 1024
PREFIX_CHUNK = 1024
MAX_PREFIX_OUTPUT = 1024 * 1024
MIN_PREFIX_OUTPUT = 64
MAX_HEADER_INPUT = 16 * 1024
MAX_QUICK_CANDIDATES = 64
MAX_FULL_CANDIDATES = 8
FINE_OFFSETS = 4096
COARSE_LIMIT = 65536
COARSE_STEP = 64
LIMITATIONS = (
    'This bounded trial tests standard Brotli streams beginning at offsets 0 through 4095 and then every 64th offset through 65535, using a 64 KiB prefix filter, a 64-byte minimum prefix output (or decoder completion), a bounded 16 KiB header trial and a 64 MiB full-output cap. '
    'Full trials feed bytes one at a time so unrelated trailing bytes do not invalidate a decoded stream. '
    'It does not model custom dictionaries, nonstandard decoder parameters, concatenated streams, per-block keys, encryption, encoding, runtime transformation or a custom header layout. '
    'A candidate decompression is not proof of usable IL2CPP metadata; a failed trial does not prove the file is encrypted. '
    'This probe emits no raw game bytes, unknown strings, decoded method names, loader identification or Premium behavior.'
)


def scan_offsets():
    """Dense start near the file header, then a bounded coarse sweep."""
    return sorted(set(range(0, FINE_OFFSETS)) |
                  set(range(FINE_OFFSETS, COARSE_LIMIT, COARSE_STEP)))


def prefix_trial(data, offset, max_prefix=MAX_PREFIX_BYTES,
                 max_output=MAX_PREFIX_OUTPUT):
    decoder = brotli.Decompressor()
    produced = 0
    end = min(len(data), offset + max_prefix)
    for start in range(offset, end, PREFIX_CHUNK):
        chunk = data[start:start + PREFIX_CHUNK]
        try:
            produced += len(decoder.process(chunk))
        except brotli.error:
            # A valid stream can be followed by unrelated bytes; the decoder
            # may reject the trailing bytes while reporting itself finished.
            if decoder.is_finished():
                return {'status': 'ok', 'producedBytes': produced,
                        'finished': True, 'prefixBytes': end - offset,
                        'errorAfterFinish': True}
            return {'status': 'invalid', 'producedBytes': produced}
        if produced > max_output:
            return {'status': 'output-cap-exceeded', 'producedBytes': produced}
        if decoder.is_finished():
            break
    return {'status': 'ok', 'producedBytes': produced,
            'finished': decoder.is_finished(), 'prefixBytes': end - offset,
            'errorAfterFinish': False}


def header_trial(data, offset, max_input=MAX_HEADER_INPUT):
    """Bounded byte-at-a-time trial that checks only the first 16 output bytes."""
    decoder = brotli.Decompressor()
    output = bytearray()
    end = min(len(data), offset + max_input)
    for index in range(offset, end):
        try:
            output.extend(decoder.process(data[index:index + 1]))
        except brotli.error:
            if decoder.is_finished():
                break
            return {'status': 'invalid', 'producedBytes': len(output)}
        if len(output) >= 16:
            break
        if decoder.is_finished():
            break
    if len(output) < 16:
        return {'status': 'insufficient-output', 'producedBytes': len(output),
                'finished': decoder.is_finished()}
    words = struct.unpack_from('<4I', output)
    return {
        'status': 'header',
        'producedBytes': len(output),
        'headerNumericFields': {'word' + str(index): word
                                for index, word in enumerate(words)},
        'magicMatchesStandard': words[0] == STANDARD_MAGIC,
        'versionMatches31': words[1] == EXPECTED_VERSION,
        'metadataHeaderPlausible': (words[0] == STANDARD_MAGIC or
                                    words[1] == EXPECTED_VERSION),
    }


def full_trial(data, offset, max_output=MAX_OUTPUT):
    # Byte-at-a-time feeding stops exactly at the end of a valid Brotli stream,
    # so unrelated trailing bytes in the metadata file are not misinterpreted.
    decoder = brotli.Decompressor()
    output = bytearray()
    for index in range(offset, len(data)):
        try:
            output.extend(decoder.process(data[index:index + 1]))
        except brotli.error:
            if decoder.is_finished():
                break
            return {'status': 'invalid'}
        if len(output) > max_output:
            return {'status': 'output-cap-exceeded',
                    'partialBytes': len(output)}
        if decoder.is_finished():
            break
    if not decoder.is_finished():
        return {'status': 'truncated', 'partialBytes': len(output)}
    result = output_descriptor(bytes(output))
    result['offset'] = hex(offset)
    return result


def offset_report(path, expected_sha=EXPECTED_METADATA_SHA256,
                  expected_size=EXPECTED_METADATA_BYTES,
                  offsets=None, max_prefix=MAX_PREFIX_BYTES,
                  max_prefix_output=MAX_PREFIX_OUTPUT,
                  max_header_input=MAX_HEADER_INPUT,
                  max_full_output=MAX_OUTPUT,
                  max_quick_candidates=MAX_QUICK_CANDIDATES,
                  max_full_candidates=MAX_FULL_CANDIDATES):
    path = Path(path)
    sha = sha256_file(path)
    size = path.stat().st_size
    if expected_sha is not None and sha != expected_sha:
        raise ValueError('Metadata file hash mismatch; refusing offset trial.')
    if expected_size is not None and size != expected_size:
        raise ValueError('Metadata file size mismatch; refusing offset trial.')
    if offsets is None:
        offsets = scan_offsets()
    offsets = sorted({int(value) for value in offsets
                      if 0 <= int(value) < size})
    data = path.read_bytes()
    plausible = []
    prefix_statuses = {}
    for offset in offsets:
        prefix = prefix_trial(data, offset, max_prefix, max_prefix_output)
        prefix_statuses[prefix['status']] = prefix_statuses.get(prefix['status'], 0) + 1
        if prefix['status'] != 'ok':
            continue
        # Consuming bytes without producing output and without finishing is a
        # common property of arbitrary data; it is not a plausible stream start.
        if not (prefix.get('producedBytes', 0) >= MIN_PREFIX_OUTPUT or
                prefix.get('finished')):
            continue
        plausible.append({'offset': hex(offset), 'offsetBytes': offset,
                          'prefix': prefix})
    plausible.sort(key=lambda item: (-item['prefix'].get('producedBytes', 0),
                                     item['offsetBytes']))
    quick = plausible[:max_quick_candidates]
    quick_results = []
    header_statuses = {}
    for item in quick:
        header = header_trial(data, item['offsetBytes'], max_header_input)
        header_statuses[header['status']] = header_statuses.get(header['status'], 0) + 1
        quick_results.append({**item, 'header': header})
    header_candidates = [item for item in quick_results
                         if item['header'].get('metadataHeaderPlausible')]
    full_items = header_candidates[:max_full_candidates]
    candidates = []
    full_statuses = {}
    for item in full_items:
        full = full_trial(data, item['offsetBytes'], max_full_output)
        full_statuses[full['status']] = full_statuses.get(full['status'], 0) + 1
        candidates.append({**item, 'full': full})
    return {
        'kind': KIND,
        'metadataSha256': sha,
        'expectedMetadataSha256': expected_sha,
        'metadataBytes': size,
        'expectedMetadataBytes': expected_size,
        'offsetPolicy': {
            'offsetCount': len(offsets),
            'fineOffsetCount': FINE_OFFSETS,
            'coarseLimit': COARSE_LIMIT,
            'coarseStep': COARSE_STEP,
            'prefixBytes': max_prefix,
            'prefixChunkBytes': PREFIX_CHUNK,
            'prefixOutputCap': max_prefix_output,
            'minPrefixOutput': MIN_PREFIX_OUTPUT,
            'headerInputCap': max_header_input,
            'quickCandidateCap': max_quick_candidates,
            'fullCandidateCap': max_full_candidates,
            'fullOutputCap': max_full_output,
        },
        'prefixStatuses': prefix_statuses,
        'plausiblePrefixCount': len(plausible),
        'quickCandidateCount': len(quick),
        'quickCandidatesTruncated': len(plausible) > len(quick),
        'headerStatuses': header_statuses,
        'metadataHeaderCandidateCount': len(header_candidates),
        'fullCandidatesTruncated': len(header_candidates) > len(full_items),
        'fullStatuses': full_statuses,
        'candidateCount': len(candidates),
        'candidates': candidates,
        'quickResults': quick_results,
        'limitations': LIMITATIONS,
    }


def emit_offset_annotations(report):
    if report.get('kind') != KIND:
        raise RuntimeError('Unexpected WorldBox Brotli offset report.')
    print('WorldBox full metadata Brotli offset report: ' +
          json.dumps(report, separators=(',', ':')))
    summary = {key: report[key] for key in
               ('metadataSha256', 'expectedMetadataSha256',
                'metadataBytes', 'expectedMetadataBytes', 'offsetPolicy',
                'prefixStatuses', 'plausiblePrefixCount',
                'quickCandidateCount', 'quickCandidatesTruncated',
                'headerStatuses', 'metadataHeaderCandidateCount',
                'fullCandidatesTruncated', 'fullStatuses',
                'candidateCount', 'limitations')}
    print('::warning title=WorldBox metadata Brotli offsets summary::' +
          annotation(json.dumps(summary, separators=(',', ':'))))
    for candidate in report['candidates']:
        print('::warning title=WorldBox metadata Brotli offsets candidate ' +
              candidate['offset'] + '::' +
              annotation(json.dumps(candidate, separators=(',', ':'))))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('metadata')
    parser.add_argument('--expected-sha', default=EXPECTED_METADATA_SHA256)
    parser.add_argument('--expected-size', type=lambda value: int(value, 0),
                        default=EXPECTED_METADATA_BYTES)
    args = parser.parse_args()
    print(json.dumps(offset_report(args.metadata, args.expected_sha,
                                   args.expected_size), separators=(',', ':')))


if __name__ == '__main__':
    main()

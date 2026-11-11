#!/usr/bin/env python3
"""Safe decompression trials for the hash-gated metadata-file stream.

Only codec statuses, output sizes/hashes, numeric header words, aggregate
entropy and predefined limitations are emitted. Raw game bytes and decoded
strings never leave the analysis. This does not recover IL2CPP metadata or
identify a loader/decryptor.
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import json
import math
from pathlib import Path
import struct

import brotli
import zlib

from worldbox_bounded_reference_report import annotation

KIND = 'worldbox-metadata-stream-probe'
EXPECTED_METADATA_SHA256 = '0c843e9807d351f193580e178f4826845534cdcd86563e634ca8a48ad3b7bc88'
EXPECTED_METADATA_BYTES = 12_878_248
STANDARD_MAGIC = 0xFAB11BAF
EXPECTED_VERSION = 31
MAX_OUTPUT = 64 * 1024 * 1024
CHUNK = 64 * 1024
HEADER_WORDS = 4
LIMITATIONS = (
    'These bounded trials test Brotli, zlib, gzip and raw-deflate streams inferred from the first bytes of the hash-gated metadata file. '
    'They do not model custom encryption, per-block transforms, concatenated streams, container framing, runtime transformation or a custom header layout. '
    'A successful decompression is not proof of usable IL2CPP metadata; a failed trial does not prove the file is encrypted. '
    'This probe emits no raw game bytes, unknown strings, decoded method names, loader identification or Premium behavior.'
)


def sha256_file(path):
    with Path(path).open('rb') as handle:
        return hashlib.file_digest(handle, 'sha256').hexdigest()


def entropy(data):
    if not data:
        return 0.0
    counts = collections.Counter(data)
    total = len(data)
    return round(-sum((count / total) * math.log2(count / total)
                      for count in counts.values()), 4)


def output_descriptor(output):
    words = list(struct.unpack_from('<' + 'I' * HEADER_WORDS, output)) if len(output) >= 16 else None
    return {
        'status': 'decompressed',
        'decompressedBytes': len(output),
        'decompressedSha256': hashlib.sha256(output).hexdigest(),
        'headerNumericFields': ({'word' + str(index): word
                                for index, word in enumerate(words)}
                               if words is not None else None),
        'magicMatchesStandard': words is not None and words[0] == STANDARD_MAGIC,
        'versionMatches31': words is not None and words[1] == EXPECTED_VERSION,
        'entropyFirst4096': entropy(output[:4096]),
    }


def brotli_trial(data, max_output=MAX_OUTPUT):
    decoder = brotli.Decompressor()
    output = bytearray()
    try:
        for start in range(0, len(data), CHUNK):
            output.extend(decoder.process(data[start:start + CHUNK]))
            if len(output) > max_output:
                return {'status': 'output-cap-exceeded', 'partialBytes': len(output)}
        if not decoder.is_finished():
            return {'status': 'truncated', 'partialBytes': len(output)}
    except brotli.error:
        return {'status': 'invalid'}
    return output_descriptor(bytes(output))


def zlib_trial(data, wbits, max_output=MAX_OUTPUT):
    decoder = zlib.decompressobj(wbits)
    try:
        output = decoder.decompress(data, max_output + 1)
    except zlib.error:
        return {'status': 'invalid'}
    if len(output) > max_output or decoder.unconsumed_tail:
        return {'status': 'output-cap-exceeded', 'partialBytes': len(output)}
    if not decoder.eof:
        return {'status': 'truncated', 'partialBytes': len(output)}
    result = output_descriptor(output)
    result['trailingBytes'] = len(decoder.unused_data)
    return result


def stream_report(path, expected_sha=EXPECTED_METADATA_SHA256,
                  expected_size=EXPECTED_METADATA_BYTES, max_output=MAX_OUTPUT):
    path = Path(path)
    sha = sha256_file(path)
    size = path.stat().st_size
    if expected_sha is not None and sha != expected_sha:
        raise ValueError('Metadata file hash mismatch; refusing stream trial.')
    if expected_size is not None and size != expected_size:
        raise ValueError('Metadata file size mismatch; refusing stream trial.')
    data = path.read_bytes()
    codecs = {
        'brotli': brotli_trial(data, max_output),
        'zlib': zlib_trial(data, zlib.MAX_WBITS, max_output),
        'gzip': zlib_trial(data, 16 + zlib.MAX_WBITS, max_output),
        'raw-deflate': zlib_trial(data, -zlib.MAX_WBITS, max_output),
    }
    return {
        'kind': KIND,
        'metadataSha256': sha,
        'expectedMetadataSha256': expected_sha,
        'metadataBytes': size,
        'expectedMetadataBytes': expected_size,
        'maxOutputBytes': max_output,
        'codecs': codecs,
        'limitations': LIMITATIONS,
    }


def emit_stream_annotations(report):
    if report.get('kind') != KIND:
        raise RuntimeError('Unexpected WorldBox metadata stream report.')
    print('WorldBox full metadata stream report: ' +
          json.dumps(report, separators=(',', ':')))
    summary = {key: report[key] for key in
               ('metadataSha256', 'expectedMetadataSha256', 'metadataBytes',
                'expectedMetadataBytes', 'maxOutputBytes', 'limitations')}
    summary['codecStatuses'] = {name: row['status'] for name, row in report['codecs'].items()}
    print('::warning title=WorldBox metadata stream summary::' +
          annotation(json.dumps(summary, separators=(',', ':'))))
    for name, row in report['codecs'].items():
        print('::warning title=WorldBox metadata stream ' + name + '::' +
              annotation(json.dumps(row, separators=(',', ':'))))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('metadata')
    parser.add_argument('--expected-sha', default=EXPECTED_METADATA_SHA256)
    parser.add_argument('--expected-size', type=lambda value: int(value, 0),
                        default=EXPECTED_METADATA_BYTES)
    parser.add_argument('--max-output', type=lambda value: int(value, 0),
                        default=MAX_OUTPUT)
    args = parser.parse_args()
    print(json.dumps(stream_report(args.metadata, args.expected_sha,
                                   args.expected_size, args.max_output),
                     separators=(',', ':')))


if __name__ == '__main__':
    main()

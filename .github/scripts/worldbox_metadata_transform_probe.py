#!/usr/bin/env python3
"""Safe constant-transform test for the hash-gated metadata-file header.

Only hashes, sizes, numeric header words, derived transform keys/deltas and
aggregate header-plausibility counts are emitted. Raw game bytes and unknown
strings never leave the analysis. This tests a few simple transforms only; it
does not decrypt metadata or identify a loader.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import struct

from worldbox_bounded_reference_report import annotation

KIND = 'worldbox-metadata-transform-probe'
EXPECTED_METADATA_SHA256 = '0c843e9807d351f193580e178f4826845534cdcd86563e634ca8a48ad3b7bc88'
EXPECTED_METADATA_BYTES = 12_878_248
STANDARD_MAGIC = 0xFAB11BAF
EXPECTED_VERSION = 31
HEADER_BYTES = 256
HEADER_WORDS = HEADER_BYTES // 4
STANDARD_MAGIC_BYTES = STANDARD_MAGIC.to_bytes(4, 'little')
EXPECTED_VERSION_BYTES = EXPECTED_VERSION.to_bytes(4, 'little')
MASK32 = 0xffffffff
LIMITATIONS = (
    'This bounded test checks constant 32-bit XOR, constant 32-bit additive/subtractive deltas, and a repeating 4-byte XOR '
    'inferred from the first eight header bytes. It does not model arbitrary encryption, compression, encoding, per-block keys, '
    'runtime transformation, or a custom header layout; it does not recover metadata, identify a decryptor, or establish Premium behavior.'
)


def sha256_file(path: Path) -> str:
    with Path(path).open('rb') as handle:
        return hashlib.file_digest(handle, 'sha256').hexdigest()


def pair_stats(words, total_size, transform=None):
    pairs = []
    for index in range(2, min(len(words), HEADER_WORDS) - 1, 2):
        offset = words[index]
        size = words[index + 1]
        if transform is not None:
            offset = transform(offset)
            size = transform(size)
        pairs.append((offset, size))
    return {
        'pairCount': len(pairs),
        'plausibleOffsetCount': sum(1 for offset, _ in pairs
                                    if offset == 0 or 8 <= offset <= total_size),
        'plausibleSizeCount': sum(1 for _, size in pairs if size <= total_size),
        'boundedPairCount': sum(1 for offset, size in pairs
                                if offset == 0 or (8 <= offset and offset + size <= total_size)),
        'alignedOffsetCount': sum(1 for offset, _ in pairs if offset % 4 == 0),
        'nonDecreasingOffsetCount': sum(1 for index in range(1, len(pairs))
                                        if pairs[index][0] >= pairs[index - 1][0]),
    }


def transform_report(path, expected_sha=EXPECTED_METADATA_SHA256,
                     expected_size=EXPECTED_METADATA_BYTES):
    path = Path(path)
    sha = sha256_file(path)
    size = path.stat().st_size
    if expected_sha is not None and sha != expected_sha:
        raise ValueError('Metadata file hash mismatch; refusing transform test.')
    if expected_size is not None and size != expected_size:
        raise ValueError('Metadata file size mismatch; refusing transform test.')
    with path.open('rb') as handle:
        header = handle.read(HEADER_BYTES)
    if len(header) < HEADER_BYTES:
        raise ValueError('Metadata header is too short for the bounded transform test.')
    words = list(struct.unpack_from('<' + 'I' * HEADER_WORDS, header))
    magic_le, version_le = words[0], words[1]
    xor_key_magic = magic_le ^ STANDARD_MAGIC
    xor_key_version = version_le ^ EXPECTED_VERSION
    xor_keys_match = xor_key_magic == xor_key_version
    additive_delta_magic = (magic_le - STANDARD_MAGIC) & MASK32
    additive_delta_version = (version_le - EXPECTED_VERSION) & MASK32
    additive_deltas_match = additive_delta_magic == additive_delta_version
    subtractive_delta_magic = (STANDARD_MAGIC - magic_le) & MASK32
    subtractive_delta_version = (EXPECTED_VERSION - version_le) & MASK32
    subtractive_deltas_match = subtractive_delta_magic == subtractive_delta_version
    repeating_key_from_magic = [header[index] ^ STANDARD_MAGIC_BYTES[index] for index in range(4)]
    repeating_key_from_version = [header[4 + index] ^ EXPECTED_VERSION_BYTES[index] for index in range(4)]
    repeating_keys_match = repeating_key_from_magic == repeating_key_from_version
    repeating_key_word = int.from_bytes(bytes(repeating_key_from_magic), 'little')
    transformed_version = bytes(header[4 + index] ^ repeating_key_from_magic[index] for index in range(4))
    repeating_version_le = int.from_bytes(transformed_version, 'little')
    return {
        'kind': KIND,
        'status': 'ok',
        'metadataSha256': sha,
        'expectedMetadataSha256': expected_sha,
        'metadataBytes': size,
        'expectedMetadataBytes': expected_size,
        'headerNumericFields': {'magicLE': magic_le, 'versionLE': version_le},
        'constant32BitXor': {
            'keyFromMagic': xor_key_magic,
            'keyFromVersion': xor_key_version,
            'keysMatch': xor_keys_match,
            'transformedPairStats': pair_stats(words, size, lambda value: value ^ xor_key_magic)
                                    if xor_keys_match else None,
        },
        'constant32BitAdditive': {
            'deltaFromMagic': additive_delta_magic,
            'deltaFromVersion': additive_delta_version,
            'deltasMatch': additive_deltas_match,
            'transformedPairStats': pair_stats(words, size,
                                              lambda value: (value - additive_delta_magic) & MASK32)
                                    if additive_deltas_match else None,
        },
        'constant32BitSubtractive': {
            'deltaFromMagic': subtractive_delta_magic,
            'deltaFromVersion': subtractive_delta_version,
            'deltasMatch': subtractive_deltas_match,
            'transformedPairStats': pair_stats(words, size,
                                              lambda value: (value + subtractive_delta_magic) & MASK32)
                                    if subtractive_deltas_match else None,
        },
        'repeating4ByteXor': {
            'keysMatch': repeating_keys_match,
            'versionMatchesExpected': repeating_version_le == EXPECTED_VERSION,
            'transformedPairStats': pair_stats(words, size,
                                              lambda value: value ^ repeating_key_word)
                                    if repeating_keys_match else None,
        },
        'limitations': LIMITATIONS,
    }


def emit_transform_annotations(report):
    if report.get('kind') != KIND:
        raise RuntimeError('Unexpected WorldBox metadata-transform report.')
    print('WorldBox full metadata transform report: ' +
          json.dumps(report, separators=(',', ':')))
    summary = {key: value for key, value in report.items()
               if key not in ('constant32BitXor', 'constant32BitAdditive',
                              'constant32BitSubtractive', 'repeating4ByteXor')}
    for key in ('constant32BitXor', 'constant32BitAdditive',
                'constant32BitSubtractive', 'repeating4ByteXor'):
        summary[key] = {name: value for name, value in report[key].items()
                        if name != 'transformedPairStats'}
    print('::warning title=WorldBox metadata transform summary::' +
          annotation(json.dumps(summary, separators=(',', ':'))))
    pair_payload = {key: report[key].get('transformedPairStats')
                    for key in ('constant32BitXor', 'constant32BitAdditive',
                                'constant32BitSubtractive', 'repeating4ByteXor')}
    print('::warning title=WorldBox metadata transform pair stats::' +
          annotation(json.dumps(pair_payload, separators=(',', ':'))))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('metadata')
    parser.add_argument('--expected-sha', default=EXPECTED_METADATA_SHA256)
    parser.add_argument('--expected-size', type=lambda value: int(value, 0),
                        default=EXPECTED_METADATA_BYTES)
    args = parser.parse_args()
    print(json.dumps(transform_report(args.metadata, args.expected_sha,
                                      args.expected_size), separators=(',', ':')))


if __name__ == '__main__':
    main()

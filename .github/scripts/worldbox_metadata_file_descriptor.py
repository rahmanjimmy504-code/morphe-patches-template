#!/usr/bin/env python3
"""Safe, hash-gated descriptor for the WorldBox global-metadata.dat APK entry.

Only hashes, sizes, numeric header fields, aggregate byte/entropy properties,
predefined magic/container signatures and bounded offsets are emitted. Raw game
bytes and unknown literal strings never leave the analysis. This is a static
descriptor, not proof of a loader, decryption routine, or Premium behavior.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import math
from pathlib import Path
import struct
import zlib
import zipfile

from worldbox_bounded_reference_report import annotation

KIND = 'worldbox-metadata-file-descriptor'
EXPECTED_BASE = 'ab7c6bab7d2233c26a9e18426aa58dd60fa0ae0ad9be6fa0b2a6673dd8f89c3f'
EXPECTED_ENTRY = 'assets/bin/Data/Managed/Metadata/global-metadata.dat'
EXPECTED_METADATA_BYTES = 12_878_248
IL2CPP_MAGIC = 0xFAB11BAF
EXPECTED_METADATA_VERSION = 31
MAX_METADATA_BYTES = 32 * 1024 * 1024
HEADER_BYTES = 256
FIRST_BLOCK_BYTES = 4096
MAX_MAGIC_OFFSETS = 12
MAX_MAGIC_OCCURRENCES = 10_000

STANDARD_LE = IL2CPP_MAGIC.to_bytes(4, 'little')
STANDARD_BE = IL2CPP_MAGIC.to_bytes(4, 'big')
COMPLEMENT_LE = bytes(255 - byte for byte in STANDARD_LE)
COMPLEMENT_BE = bytes(255 - byte for byte in STANDARD_BE)

MAGIC_CANDIDATES = {
    'standard-le': STANDARD_LE,
    'standard-be': STANDARD_BE,
    'complement-standard-le': COMPLEMENT_LE,
    'complement-standard-be': COMPLEMENT_BE,
}
for rotation in range(1, 4):
    MAGIC_CANDIDATES[f'standard-le-rotation-{rotation}'] = (
        STANDARD_LE[rotation:] + STANDARD_LE[:rotation])

CONTAINER_SIGNATURES = (
    ('zip', b'PK\x03\x04'),
    ('gzip', b'\x1f\x8b'),
    ('zlib-78-01', b'\x78\x01'),
    ('zlib-78-9c', b'\x78\x9c'),
    ('zlib-78-da', b'\x78\xda'),
    ('lz4-frame', b'\x04\x22\x4d\x18'),
    ('zstd-frame', b'\x28\xb5\x2f\xfd'),
    ('xz', b'\xfd7zXZ\x00'),
    ('bzip2', b'BZh'),
    ('unityfs', b'UnityFS\x00'),
    ('unityweb', b'UnityWeb'),
    ('elf', b'\x7fELF'),
    ('dex', b'dex\n'),
)

LIMITATIONS = (
    'This is a bounded static descriptor of one hash-gated APK entry. It does not emit raw game bytes or unknown strings, '
    'prove runtime use, identify a metadata loader or decryptor, establish a Premium entitlement check, or recover IL2CPP metadata. '
    'Predefined magic candidates cover the standard IL2CPP magic, byte-order/complement/rotation transforms and a header-derived '
    'single-byte XOR only; arbitrary encryption, encoding, compression, or runtime transformation is not modeled.'
)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    with Path(path).open('rb') as handle:
        return hashlib.file_digest(handle, 'sha256').hexdigest()


def ratio(part: int, total: int) -> float:
    return round(part / total, 6) if total else 0.0


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return round(-sum((count / length) * math.log2(count / length)
                      for count in counts.values()), 4)


def byte_distribution(data: bytes) -> dict:
    counts = Counter(data)
    total = len(data)
    printable = sum(counts[value] for value in range(0x20, 0x7f))
    high = sum(counts[value] for value in range(0x80, 0x100))
    nul = counts[0]
    control_or_other = total - printable - high
    return {
        'bytes': total,
        'distinctByteValues': len(counts),
        'printableAsciiCount': printable,
        'printableAsciiRatio': ratio(printable, total),
        'highByteCount': high,
        'highByteRatio': ratio(high, total),
        'nulCount': nul,
        'nulRatio': ratio(nul, total),
        'controlOrOtherCount': control_or_other,
        'controlOrOtherRatio': ratio(control_or_other, total),
    }


def single_byte_xor_key(prefix: bytes, reference: bytes):
    if len(prefix) < len(reference):
        return None
    key = prefix[0] ^ reference[0]
    if key == 0:
        return None
    for index in range(1, len(reference)):
        if prefix[index] ^ reference[index] != key:
            return None
    return key


def header_numeric_fields(data: bytes) -> dict:
    prefix = data[:8]
    magic_le = int.from_bytes(prefix[:4], 'little')
    magic_be = int.from_bytes(prefix[:4], 'big')
    version_le = int.from_bytes(prefix[4:8], 'little')
    version_be = int.from_bytes(prefix[4:8], 'big')
    first16 = data[:16]
    key_le = single_byte_xor_key(prefix[:4], STANDARD_LE)
    key_be = single_byte_xor_key(prefix[:4], STANDARD_BE)
    return {
        'magicLE': magic_le,
        'magicBE': magic_be,
        'versionLE': version_le,
        'versionBE': version_be,
        'standardMagicLEAtHeader': magic_le == IL2CPP_MAGIC,
        'standardMagicBEAtHeader': magic_be == IL2CPP_MAGIC,
        'versionEqualsExpectedLE': version_le == EXPECTED_METADATA_VERSION,
        'versionEqualsExpectedBE': version_be == EXPECTED_METADATA_VERSION,
        'headerSingleByteXorKeyFromStandardLE': key_le,
        'headerSingleByteXorKeyFromStandardBE': key_be,
        'headerComplementOfStandardLE': prefix[:4] == COMPLEMENT_LE,
        'headerComplementOfStandardBE': prefix[:4] == COMPLEMENT_BE,
        'headerFirst16AllZero': bool(first16) and all(byte == 0 for byte in first16),
        'headerFirst16DistinctByteValues': len(set(first16)),
    }


def header_pair_stats(data: bytes, total_size: int) -> dict:
    pairs = []
    limit = min(len(data), HEADER_BYTES)
    for offset in range(8, limit - 7, 8):
        value = int.from_bytes(data[offset:offset + 4], 'little')
        size = int.from_bytes(data[offset + 4:offset + 8], 'little')
        pairs.append((value, size))
    return {
        'pairCount': len(pairs),
        'plausibleOffsetCount': sum(1 for value, _ in pairs
                                    if value == 0 or 8 <= value <= total_size),
        'plausibleSizeCount': sum(1 for _, size in pairs if size <= total_size),
        'boundedPairCount': sum(1 for value, size in pairs
                                if value == 0 or (8 <= value and value + size <= total_size)),
        'alignedOffsetCount': sum(1 for value, _ in pairs if value % 4 == 0),
        'nonDecreasingOffsetCount': sum(1 for index in range(1, len(pairs))
                                        if pairs[index][0] >= pairs[index - 1][0]),
    }


def magic_occurrences(data: bytes, needle: bytes) -> dict:
    count = 0
    offsets = []
    start = 0
    truncated = False
    while True:
        position = data.find(needle, start)
        if position < 0:
            break
        count += 1
        if len(offsets) < MAX_MAGIC_OFFSETS:
            offsets.append(hex(position))
        if count >= MAX_MAGIC_OCCURRENCES:
            truncated = True
            break
        start = position + 1
    return {'count': count, 'offsets': offsets,
            'firstOffset': offsets[0] if offsets else None,
            'truncated': truncated, 'atHeader': data.startswith(needle)}


def magic_candidate_report(data: bytes) -> dict:
    candidates = dict(MAGIC_CANDIDATES)
    key_le = single_byte_xor_key(data[:4], STANDARD_LE)
    key_be = single_byte_xor_key(data[:4], STANDARD_BE)
    dynamic_key = key_le if key_le is not None else key_be
    dynamic_reference = STANDARD_LE if key_le is not None else STANDARD_BE
    dynamic_label = None
    if dynamic_key is not None:
        dynamic_label = 'header-single-byte-xor'
        candidates[dynamic_label] = bytes(byte ^ dynamic_key for byte in dynamic_reference)
    report = {label: magic_occurrences(data, needle)
              for label, needle in candidates.items()}
    return {'labels': sorted(candidates), 'dynamicLabel': dynamic_label,
            'dynamicKey': dynamic_key, 'candidates': report}


def container_signature_report(data: bytes) -> dict:
    at_start = []
    first_occurrence = {}
    for label, signature in CONTAINER_SIGNATURES:
        if data.startswith(signature):
            at_start.append(label)
        position = data.find(signature)
        if position >= 0:
            first_occurrence[label] = hex(position)
    return {'predefinedLabels': [label for label, _ in CONTAINER_SIGNATURES],
            'atStart': at_start, 'signatureAtStartCount': len(at_start),
            'firstOccurrenceOffsets': first_occurrence}


def descriptor(data: bytes) -> dict:
    return {
        'sha256': sha256_bytes(data),
        'crc32': hex(zlib.crc32(data)),
        'bytes': len(data),
        'header': header_numeric_fields(data),
        'entropy': {
            'fullShannonBitsPerByte': entropy(data),
            'firstBlockShannonBitsPerByte': entropy(data[:FIRST_BLOCK_BYTES]),
            'headerShannonBitsPerByte': entropy(data[:HEADER_BYTES]),
            'normalizedFullEntropy': round(entropy(data) / 8, 6),
        },
        'byteDistribution': byte_distribution(data),
        'headerPairStats': header_pair_stats(data, len(data)),
        'containerSignatures': container_signature_report(data),
        'magicCandidates': magic_candidate_report(data),
    }


def metadata_file_report(base_apk, metadata_path=None,
                         expected_base_hash=EXPECTED_BASE,
                         expected_size=EXPECTED_METADATA_BYTES) -> dict:
    base_apk = Path(base_apk)
    base_hash = sha256_file(base_apk)
    if expected_base_hash is not None and base_hash != expected_base_hash:
        raise ValueError('Base APK hash mismatch; refusing metadata-file descriptor.')
    base = {
        'kind': KIND,
        'status': 'ok',
        'baseApkSha256': base_hash,
        'expectedBaseApkSha256': expected_base_hash,
        'baseApkHashGated': expected_base_hash is not None,
        'entryName': EXPECTED_ENTRY,
        'expectedMetadataBytes': expected_size,
        'maxMetadataBytes': MAX_METADATA_BYTES,
        'limitations': LIMITATIONS,
    }
    with zipfile.ZipFile(base_apk) as archive:
        matches = [info for info in archive.infolist()
                   if not info.is_dir() and info.filename == EXPECTED_ENTRY]
        if len(matches) != 1:
            return {**base, 'status': 'entry-not-found' if not matches else 'multiple-entries',
                    'matchingEntryCount': len(matches),
                    'observedEntrySizes': [info.file_size for info in matches[:16]]}
        info = matches[0]
        observed = {
            'entryFileSize': info.file_size,
            'entryCompressedSize': info.compress_size,
            'entryCompressType': int(info.compress_type),
            'entryCrc32': hex(info.CRC),
            'sizeMatchesExpected': info.file_size == expected_size,
        }
        if info.file_size != expected_size:
            return {**base, **observed, 'status': 'size-mismatch'}
        if info.file_size > MAX_METADATA_BYTES:
            return {**base, **observed, 'status': 'too-large'}
        with archive.open(info) as source:
            data = source.read(expected_size + 1)
        if len(data) != info.file_size:
            return {**base, **observed, 'status': 'read-mismatch',
                    'readBytes': len(data)}
        extracted = None
        if metadata_path is not None:
            extracted_path = Path(metadata_path)
            if extracted_path.is_file():
                extracted_sha = sha256_file(extracted_path)
                extracted = {
                    'extractedMetadataPresent': True,
                    'extractedMetadataBytes': extracted_path.stat().st_size,
                    'extractedMetadataSha256': extracted_sha,
                    'metadataMatchesExtractedFile': extracted_sha == sha256_bytes(data),
                }
            else:
                extracted = {'extractedMetadataPresent': False,
                             'metadataMatchesExtractedFile': None}
        return {**base, **observed, **(extracted or {}), **descriptor(data)}


def emit_metadata_file_annotations(report: dict) -> None:
    if report.get('kind') != KIND:
        raise RuntimeError('Unexpected WorldBox metadata-file descriptor report.')
    print('WorldBox full metadata file descriptor report: ' +
          json.dumps(report, separators=(',', ':')))
    summary = {key: value for key, value in report.items()
               if key != 'magicCandidates'}
    print('::warning title=WorldBox metadata file descriptor summary::' +
          annotation(json.dumps(summary, separators=(',', ':'))))
    print('::warning title=WorldBox metadata file descriptor magic candidates::' +
          annotation(json.dumps({'status': report.get('status'),
                                 'metadataSha256': report.get('sha256'),
                                 'magicCandidates': report.get('magicCandidates', {})},
                                separators=(',', ':'))))
    if report.get('status') != 'ok':
        print('::notice title=WorldBox metadata file descriptor unavailable::' +
              annotation(json.dumps({'status': report.get('status'),
                                     'entryFileSize': report.get('entryFileSize')},
                                    separators=(',', ':'))))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('--base-apk', required=True)
    parser.add_argument('--metadata')
    parser.add_argument('--expected-base-hash', default=EXPECTED_BASE)
    parser.add_argument('--expected-size', type=lambda value: int(value, 0),
                        default=EXPECTED_METADATA_BYTES)
    args = parser.parse_args()
    print(json.dumps(metadata_file_report(args.base_apk, args.metadata,
                                          args.expected_base_hash,
                                          args.expected_size),
                     separators=(',', ':')))


if __name__ == '__main__':
    main()

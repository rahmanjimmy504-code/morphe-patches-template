#!/usr/bin/env python3
"""Bounded APK entry-header inventory for possible Unity bundles/serialized files.

Only the first 64 uncompressed bytes of each entry are inspected; no asset data
is exported and no nested archives are decompressed. These are format clues.
"""
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import struct
import sys
import zipfile

HEADER = 64
MAX_ENTRIES = 30000
MAX_SAMPLES = 32
SIGNATURES = ((b'UnityFS\0', 'unity-fs'), (b'UnityRaw\0', 'unity-raw'),
              (b'UnityWeb\0', 'unity-web'), (b'UnityWebData', 'unity-web-data'),
              (b'TuanjieWebData', 'tuanjie-web-data'), (b'\xfa' * 8 + b'\0', 'unity-cn'))


def classify(data, size, name):
    for signature, label in SIGNATURES:
        if data.startswith(signature):
            return label
    # Basic SerializedFile header validity; still only a heuristic until parsed.
    if len(data) >= 16:
        metadata, filesize, version, offset = struct.unpack_from('>IIII', data)
        if 22 <= version <= 30 and len(data) >= 48:
            metadata, filesize, offset = struct.unpack_from('>IQQ', data, 20)
        if 9 <= version <= 30 and metadata and filesize == size and metadata <= size and 0 < offset <= size:
            return 'serialized-file-candidate'
    # Generic compressed or nested containers inside assets may hold anything.
    if name.lower().startswith('assets/'):
        if data.startswith(b'PK\x03\x04'): return 'nested-zip'
        if data.startswith(b'\x1f\x8b'): return 'gzip-container'
        if len(data) >= 0x26 and data[0x20:0x26] == b'brotli': return 'brotli-container'
    return None


def safe(name):
    return name if re.fullmatch(r'[A-Za-z0-9_./-]{1,240}', name, re.ASCII) else '<redacted>'


def inspect(path):
    path = Path(path)
    with path.open('rb') as f:
        sha = hashlib.file_digest(f, 'sha256').hexdigest()
    counts, samples, errors = Counter(), [], Counter()
    with zipfile.ZipFile(path) as apk:
        entries = [entry for entry in apk.infolist() if not entry.is_dir()]
        scanned = 0
        bytes_read = 0
        for info in entries[:MAX_ENTRIES]:
            if info.flag_bits & 1:
                errors['encrypted'] += 1
                continue
            try:
                with apk.open(info) as f:
                    header = f.read(min(HEADER, info.file_size))
                if len(header) != min(HEADER, info.file_size):
                    raise ValueError('short header read')
            except Exception as exc:
                errors[type(exc).__name__] += 1
                continue
            scanned += 1
            bytes_read += len(header)
            category = classify(header, info.file_size, info.filename)
            if category:
                counts[category] += 1
                if len(samples) < MAX_SAMPLES:
                    samples.append({'entry': safe(info.filename), 'format': category,
                                    'uncompressedBytes': info.file_size, 'compressedBytes': info.compress_size})
    return {'apk': safe(path.name), 'sha256': sha, 'entryCount': len(entries),
            'entriesScanned': scanned, 'headerBytesRead': bytes_read,
            'entryLimitReached': len(entries) > MAX_ENTRIES, 'readErrors': dict(errors),
            'counts': dict(counts), 'samplesTruncated': sum(counts.values()) > len(samples), 'samples': samples}


if __name__ == '__main__':
    print(json.dumps({'kind': 'worldbox-bundle-inventory',
                      'apks': [inspect(p) for p in sys.argv[1:]]}, separators=(',', ':')))

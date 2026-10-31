#!/usr/bin/env python3
"""Bounded raw keyword search in Unity data entries from a local base APK.

Only APK ZIP decompression is performed. Unity bundle compression and asset
serialization are not decoded. Output contains counts, offsets and entry names,
never the contents of game assets.
"""
import hashlib
import json
import re
import sys
from pathlib import Path
import zipfile

CHUNK = 1024 * 1024
MAX_TOTAL = 512 * 1024 * 1024
MAX_ENTRY = 128 * 1024 * 1024
MAX_ENTRIES = 4000
SAMPLE_LIMIT = 4
TERMS = {'premium': 'premium', 'purchase': 'purchase', 'product': 'product',
         'metadata-name': 'global-metadata.dat'}
ENCODINGS = {'ascii': 'ascii', 'utf16le': 'utf-16le', 'utf16be': 'utf-16be'}
PATTERNS = {(term, encoding): word.encode(codec) for term, word in TERMS.items()
            for encoding, codec in ENCODINGS.items()}
MAX_PATTERN = max(map(len, PATTERNS.values()))


def target_entry(info):
    name = info.filename.lower()
    if info.is_dir() or not name.startswith('assets/bin/data/'):
        return False
    # Protected metadata already scanned separately and is not a Unity asset.
    if name.endswith('/metadata/global-metadata.dat'):
        return False
    base = name.rsplit('/', 1)[-1]
    return (name.endswith(('.assets', '.bundle', '.unity3d', '.resource', '.ress')) or
            base == 'globalgamemanagers' or re.fullmatch(r'level[0-9]+', base) is not None or
            '/streamingassets/' in name)


def priority(info):
    name = info.filename.lower()
    base = name.rsplit('/', 1)[-1]
    if base == 'globalgamemanagers': return (0, name)
    if base == 'resources.assets': return (1, name)
    if base.startswith('sharedassets') and base.endswith('.assets'): return (2, name)
    return (3, name)


def scan_stream(stream, length, chunk=CHUNK):
    """Read at most length bytes; count occurrences across chunk boundaries once."""
    results = {key: {'count': 0, 'sampleOffsets': []} for key in PATTERNS}
    carry = b''
    read = 0
    while read < length:
        block = stream.read(min(chunk, length - read))
        if not block:
            raise ValueError('Unexpected end of APK entry')
        buf = (carry + block).lower()
        prefix = len(carry)
        base = read - prefix
        for key, pattern in PATTERNS.items():
            offset = 0
            while True:
                index = buf.find(pattern, offset)
                if index < 0:
                    break
                if index + len(pattern) > prefix:
                    row = results[key]
                    row['count'] += 1
                    if len(row['sampleOffsets']) < SAMPLE_LIMIT:
                        row['sampleOffsets'].append(base + index)
                offset = index + 1
        read += len(block)
        carry = buf[-(MAX_PATTERN - 1):]
    return results, read


def safe_name(name, index):
    # Avoid printing control characters and arbitrary oversized ZIP names.
    return name if re.fullmatch(r'[a-zA-Z0-9_./-]{1,240}', name) else f'<redacted-entry-{index}>'


def inspect(path, max_total=MAX_TOTAL, max_entry=MAX_ENTRY, max_entries=MAX_ENTRIES, chunk=CHUNK):
    path = Path(path)
    with path.open('rb') as f:
        sha256 = hashlib.file_digest(f, 'sha256').hexdigest()
    results = []
    with zipfile.ZipFile(path) as apk:
        entries = sorted((item for item in apk.infolist() if target_entry(item)), key=priority)
        if any(item.flag_bits & 1 for item in entries):
            raise ValueError('Encrypted APK entries not supported')
        total_eligible = sum(item.file_size for item in entries)
        total_scanned = 0
        for i, item in enumerate(entries[:max_entries]):
            budget = min(item.file_size, max_entry, max_total - total_scanned)
            if budget <= 0:
                if item.file_size == 0:
                    continue
                break
            with apk.open(item) as stream:
                hits, read = scan_stream(stream, budget, chunk)
            total_scanned += read
            nonzero = [{'category': k[0], 'encoding': k[1], **v,
                        'samplesTruncated': v['count'] > len(v['sampleOffsets'])}
                       for k, v in hits.items() if v['count']]
            results.append({'entry': safe_name(item.filename, i), 'uncompressedBytes': item.file_size,
                            'scannedBytes': read, 'truncated': read < item.file_size, 'matches': nonzero})
        return {'kind': 'worldbox-unity-asset-leads', 'baseApkSha256': sha256,
                'eligibleEntries': len(entries), 'entriesScanned': len(results),
                'eligibleBytes': total_eligible, 'scannedBytes': total_scanned,
                'entriesLimitReached': len(entries) > max_entries,
                'truncated': len(entries) > max_entries or total_scanned < total_eligible,
                'results': results}


if __name__ == '__main__':
    print(json.dumps(inspect(Path(sys.argv[1])), separators=(',', ':')))

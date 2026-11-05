#!/usr/bin/env python3
"""Bounded exact metadata-path search in Android DEX files.

Only predefined needle labels, aggregate counts, DEX string indices, class and
method names, entry names and offsets are emitted. No unknown literal strings
or DEX file bytes leave the analysis. Static string and const-string matches
are not proof of executed path construction or metadata loading.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import sys
import zipfile
from pathlib import Path
from typing import Iterable

NEEDLES = {
    'metadata_filename': 'global-metadata.dat',
    'unity_metadata_path': 'assets/bin/Data/Managed/Metadata/global-metadata.dat',
    'metadata_relative_path': 'Metadata/global-metadata.dat',
}
ENCODINGS = ('ascii', 'utf16le')
CHUNK_SIZE = 1024 * 1024
MAX_EXAMPLES = 12


def encoded_needles(text):
    return {'ascii': text.encode('ascii'), 'utf16le': text.encode('utf-16le')}


def needle_in_stream(handle, needle, location_fields=None, chunk_size=CHUNK_SIZE,
                     max_examples=MAX_EXAMPLES, base_offset=0):
    count = 0
    examples = []
    tail = b''
    absolute = base_offset
    carry = len(needle) - 1
    while True:
        chunk = handle.read(chunk_size)
        if not chunk:
            break
        buffer = tail + chunk
        start = 0
        while True:
            position = buffer.find(needle, start)
            if position < 0:
                break
            count += 1
            if len(examples) < max_examples:
                example = {'offset': hex(absolute + position)}
                if location_fields:
                    example.update(location_fields)
                examples.append(example)
            start = position + 1
        tail = buffer[-carry:] if carry else b''
        absolute += len(buffer) - len(tail)
    return count, examples


def needle_in_bytes(data, needle, location_fields=None, base_offset=0):
    return needle_in_stream(io.BytesIO(data), needle, location_fields,
                            chunk_size=max(CHUNK_SIZE, len(data) or 1),
                            base_offset=base_offset)


def raw_dex_scan(data, needles=NEEDLES):
    results = {}
    for label, text in needles.items():
        per_encoding = {}
        for encoding, needle in encoded_needles(text).items():
            count, examples = needle_in_bytes(data, needle, {'kind': 'dex-content'})
            per_encoding[encoding] = {
                'count': count, 'examples': examples[:MAX_EXAMPLES],
                'examplesTruncated': len(examples) > MAX_EXAMPLES}
        results[label] = per_encoding
    return {'kind': 'dex-raw-string-scan', 'bytes': len(data), 'results': results}


def java_name(value):
    return value.strip(';L').replace('/', '.')


def dex_parse_report(data, needles=NEEDLES):
    if not data.startswith(b'dex\n'):
        return {'status': 'not-a-dex'}
    try:
        from androguard.core.dex import DEX
        dex = DEX(data)
    except Exception as exc:
        return {'status': 'parse-failed', 'reason': type(exc).__name__}
    try:
        strings = dex.get_strings()
        string_matches = []
        for index, value in enumerate(strings):
            for label, text in needles.items():
                if text in value:
                    string_matches.append({'stringIndex': index, 'needle': label,
                                           'stringLength': len(value)})
        const_string_methods = []
        for cls in dex.get_classes():
            class_name = java_name(cls.get_name())
            for method in cls.get_methods():
                code = method.get_code()
                if code is None:
                    continue
                matched = set()
                for instruction in code.get_bc().get_instructions():
                    if not instruction.get_name().startswith('const-string'):
                        continue
                    output = instruction.get_output()
                    for label, text in needles.items():
                        if text in output:
                            matched.add(label)
                if matched:
                    const_string_methods.append({
                        'class': class_name, 'method': method.get_name(),
                        'descriptor': method.get_descriptor(),
                        'needles': sorted(matched)})
        return {'status': 'parsed', 'stringCount': len(strings),
                'stringTableMatches': len(string_matches),
                'stringMatches': string_matches[:MAX_EXAMPLES],
                'stringMatchesTruncated': len(string_matches) > MAX_EXAMPLES,
                'constStringMethodMatches': len(const_string_methods),
                'constStringMethods': const_string_methods[:MAX_EXAMPLES],
                'constStringMethodsTruncated': len(const_string_methods) > MAX_EXAMPLES}
    except Exception as exc:
        return {'status': 'parse-failed', 'reason': type(exc).__name__}


def analyze_apks(paths: Iterable[Path], needles=NEEDLES):
    rows = []
    for path in paths:
        path = Path(path)
        with zipfile.ZipFile(path) as apk:
            names = sorted(name for name in apk.namelist()
                           if name.lower().endswith('.dex') and not name.endswith('/'))
            for name in names:
                data = apk.read(name)
                rows.append({
                    'apk': path.name, 'dex': name, 'bytes': len(data),
                    'sha256': hashlib.sha256(data).hexdigest(),
                    'raw': raw_dex_scan(data, needles),
                    'parsed': dex_parse_report(data, needles)})
    return {'kind': 'worldbox-metadata-java-probe', 'needles': needles,
            'encodings': ENCODINGS, 'dexFiles': rows,
            'limitations': 'Exact predefined ASCII/UTF-16LE DEX byte counts, DEX string-table entries and const-string instruction contexts only. Encrypted, encoded, split, constructed, native, asset or runtime-generated path strings are not excluded by zero counts. Static matches are not proof of executed path construction or metadata loading.'}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('apks', nargs='+', type=Path)
    args = parser.parse_args()
    try:
        report = analyze_apks(args.apks)
    except Exception as exc:
        print(f'Metadata Java probe failed: {type(exc).__name__}: {exc}', file=sys.stderr)
        return 1
    print(json.dumps(report, separators=(',', ':')))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

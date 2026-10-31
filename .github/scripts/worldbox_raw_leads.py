#!/usr/bin/env python3
"""Scan bounded ELF file bytes for predefined names without emitting input data.

Matches are byte-sequence occurrences, not evidence of strings or execution.
"""
import hashlib
import json
from pathlib import Path
import sys
from elftools.elf.elffile import ELFFile

MAX_FILE = 96 * 1024 * 1024
SAMPLE_LIMIT = 4
TERMS = {'global-metadata-name': 'global-metadata.dat', 'metadata-name': 'metadata.dat',
         'premium-keyword': 'premium'}
ENCODINGS = {'ascii': 'ascii', 'utf16le': 'utf-16le', 'utf16be': 'utf-16be'}


def scan_bytes(data):
    """Case-insensitive ASCII-code-point terms, including UTF-16 byte encodings.

    Includes overlapping categories, but each individual pattern has no
    self-overlap. No terminator, alignment or character context is assumed.
    """
    folded = data.lower()
    result = {}
    for category, term in TERMS.items():
        for name, encoding in ENCODINGS.items():
            pattern = term.encode(encoding)
            total = folded.count(pattern)
            samples = []
            offset = 0
            while len(samples) < min(total, SAMPLE_LIMIT):
                offset = folded.find(pattern, offset)
                if offset < 0:
                    raise AssertionError('Inconsistent byte count')
                samples.append(offset)
                offset += 1
            result[(category, name)] = {'count': total, 'offsets': samples, 'length': len(pattern)}
    return result


def section_location(sections, offset, length):
    """Only map a sample fully contained in a file-backed ELF section."""
    matches = []
    for sec in sections:
        lo, hi = sec['sh_offset'], sec['sh_offset'] + sec['sh_size']
        if sec['sh_type'] == 'SHT_NOBITS' or not (lo <= offset and offset + length <= hi):
            continue
        flags = sec['sh_flags']
        item = {'allocated': bool(flags & 2), 'writable': bool(flags & 1), 'executable': bool(flags & 4)}
        if flags & 2:
            item['vaddr'] = hex(sec['sh_addr'] + offset - lo)
        matches.append(item)
    return matches[:4], len(matches) > 4


def inspect(path):
    path = Path(path)
    with path.open('rb') as f:
        elf = ELFFile(f)
        if elf.elfclass != 64 or not elf.little_endian or elf['e_machine'] != 'EM_AARCH64':
            raise ValueError('Expected little-endian ELF64 AArch64')
        sections = list(elf.iter_sections())
        f.seek(0)
        digest = hashlib.file_digest(f, 'sha256').hexdigest()
        size = path.stat().st_size
        f.seek(0)
        data = f.read(min(size, MAX_FILE))
        if len(data) != min(size, MAX_FILE):
            raise ValueError('Short file read')
        rows = []
        for (category, encoding), hit in scan_bytes(data).items():
            samples = []
            for offset in hit['offsets']:
                mappings, truncated = section_location(sections, offset, hit['length'])
                samples.append({'fileOffset': hex(offset), 'sectionMappings': mappings,
                                'sectionMappingsTruncated': truncated})
            rows.append({'category': category, 'encoding': encoding, 'count': hit['count'],
                         'samplesTruncated': hit['count'] > len(samples), 'samples': samples})
        return {'kind': 'arm64-raw-name-leads', 'sha256': digest, 'fileBytes': size,
                'scannedBytes': len(data), 'truncated': len(data) < size, 'results': rows}


if __name__ == '__main__':
    print(json.dumps(inspect(sys.argv[1]), separators=(',', ':')))

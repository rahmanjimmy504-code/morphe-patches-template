#!/usr/bin/env python3
"""Bounded descriptor for one known static ELF literal address.

Only the address, safe section metadata, aggregate byte properties, hashes and
predefined metadata-path needle relationships are emitted. Unknown literal bytes
or game strings never leave the analysis. This is a static descriptor, not proof
that the literal is used at runtime or that it is a metadata path.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from elftools.elf.elffile import ELFFile

from worldbox_bounded_reference_report import annotation
from worldbox_metadata_path_probe import NEEDLES, encoded_needles

STATIC_LITERAL_ADDRESS = 0xb0ed1c
STATIC_LITERAL_KIND = 'worldbox-static-literal-probe'
MAX_LITERAL_BYTES = 128
PRINTABLE_ASCII = set(range(0x20, 0x7f)) | {0x09, 0x0a, 0x0d}
PATH_SEPARATOR_BYTES = (b'/', b'\\', b'.', b':')


def utf16le_prefix(raw):
    """Return a validated UTF-16LE prefix ending at an aligned double NUL."""
    for position in range(0, len(raw) - 1, 2):
        if raw[position] == 0 and raw[position + 1] == 0:
            candidate = raw[:position]
            if len(candidate) % 2:
                return b'', False
            if all(candidate[index + 1] == 0 for index in range(0, len(candidate), 2)):
                return candidate, True
            return b'', False
    return b'', False


def needle_relations(literal, raw, utf16le_literal, needles):
    relations = {}
    for label, text in needles.items():
        encodings = encoded_needles(text)
        ascii_needle = encodings['ascii']
        utf16le_needle = encodings['utf16le']
        relations[label] = {
            'literalEqualsNeedle': literal == ascii_needle,
            'literalContainsNeedle': bool(ascii_needle) and ascii_needle in literal,
            'needleContainsLiteral': bool(literal) and literal in ascii_needle,
            'utf16leLiteralEqualsNeedle': bool(utf16le_literal) and utf16le_literal == utf16le_needle,
            'utf16leWindowContainsNeedle': utf16le_needle in raw,
        }
    return relations


def literal_category(literal, printable_ascii):
    if not literal:
        return 'empty'
    if not printable_ascii:
        return 'mixed-bytes'
    if len(literal) == 1:
        return 'single-printable-ascii'
    return 'printable-ascii-string'


def literal_report(path, address=STATIC_LITERAL_ADDRESS, needles=None, max_bytes=MAX_LITERAL_BYTES):
    if not 1 <= max_bytes <= 256:
        raise ValueError('max_bytes must be between 1 and 256')
    needle_map = NEEDLES if needles is None else needles
    base = {
        'kind': STATIC_LITERAL_KIND,
        'address': hex(address),
        'maxBytes': max_bytes,
        'needleLabels': sorted(needle_map),
        'limitations': 'This is a bounded static byte descriptor at one known address. It does not emit unknown literal bytes, prove runtime use, or establish metadata loading.'}
    with Path(path).open('rb') as handle:
        elf = ELFFile(handle)
        if elf.elfclass != 64 or not elf.little_endian or elf['e_machine'] != 'EM_AARCH64':
            raise ValueError('Expected a little-endian ELF64 AArch64 library')
        sections = [section for section in elf.iter_sections()
                    if section['sh_flags'] & 2 and section['sh_type'] != 'SHT_NOBITS']
        section = next((item for item in sections
                        if item['sh_addr'] <= address < item['sh_addr'] + item['sh_size']), None)
        if section is None:
            return {**base, 'status': 'not-found'}
        if section['sh_flags'] & 0x800:
            return {**base, 'status': 'compressed-section',
                    'sectionName': section.name}
        remaining = section['sh_addr'] + section['sh_size'] - address
        count = min(max_bytes, remaining)
        file_offset = section['sh_offset'] + address - section['sh_addr']
        handle.seek(file_offset)
        raw = handle.read(count)
        ascii_end = raw.find(b'\0')
        zero_terminated = ascii_end >= 0
        literal = raw[:ascii_end] if zero_terminated else raw
        printable_ascii = all(byte in PRINTABLE_ASCII for byte in literal)
        non_printable = sum(byte not in PRINTABLE_ASCII for byte in literal)
        utf16le_literal, utf16le_candidate = utf16le_prefix(raw)
        relations = needle_relations(literal, raw, utf16le_literal, needle_map)
        match = any(value for row in relations.values() for key, value in row.items()
                    if key != 'needleContainsLiteral')
        return {
            **base,
            'status': 'ok',
            'sectionName': section.name,
            'sectionType': str(section['sh_type']),
            'sectionFlags': int(section['sh_flags']),
            'sectionAddress': hex(section['sh_addr']),
            'sectionOffset': hex(section['sh_offset']),
            'sectionSize': int(section['sh_size']),
            'sectionEndRemaining': remaining,
            'fileOffset': hex(file_offset),
            'readLength': len(raw),
            'byteLength': len(literal),
            'zeroTerminated': zero_terminated,
            'truncated': not zero_terminated and remaining > count,
            'printableAscii': printable_ascii,
            'nonPrintableByteCount': non_printable,
            'literalCategory': literal_category(literal, printable_ascii),
            'singleCharacter': len(literal) == 1,
            'pathSeparatorLike': literal in PATH_SEPARATOR_BYTES,
            'endsWithDatExtension': literal.endswith(b'.dat'),
            'literalSha256': hashlib.sha256(literal).hexdigest(),
            'windowSha256': hashlib.sha256(raw).hexdigest(),
            'utf16leCandidate': utf16le_candidate,
            'utf16leByteLength': len(utf16le_literal),
            'needleRelations': relations,
            'matchesMetadataPathNeedle': match}


def emit_literal_annotations(report, label='static literal'):
    if report.get('kind') != STATIC_LITERAL_KIND:
        raise RuntimeError('Unexpected ' + label + ' report.')
    print('WorldBox full ' + label + ' report: ' +
          json.dumps(report, separators=(',', ':')))
    print('::warning title=WorldBox ' + label + ' descriptor::' +
          annotation(json.dumps(report, separators=(',', ':'))))
    if report.get('status') != 'ok':
        print('::notice title=WorldBox ' + label + ' unavailable::' +
              annotation(json.dumps({'status': report.get('status'),
                                     'sectionName': report.get('sectionName')},
                                    separators=(',', ':'))))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('elf')
    parser.add_argument('--address', type=lambda value: int(value, 0),
                        default=STATIC_LITERAL_ADDRESS)
    parser.add_argument('--max-bytes', type=int, default=MAX_LITERAL_BYTES)
    args = parser.parse_args()
    print(json.dumps(literal_report(args.elf, address=args.address,
                                    max_bytes=args.max_bytes), separators=(',', ':')))


if __name__ == '__main__':
    main()

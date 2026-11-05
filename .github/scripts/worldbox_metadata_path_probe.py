#!/usr/bin/env python3
"""Bounded exact metadata-path search and ELF section-context summaries.

Only predefined needle labels, aggregate counts, ELF-relative addresses,
section names, APK entry names and safe string categories are emitted. No game
file bytes or unknown literal strings leave the analysis. Counts are static
occurrences, not proof of executed control flow or metadata use.
"""
import argparse
import hashlib
import io
import json
from pathlib import Path
import struct
import zipfile

from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from elftools.elf.sections import SymbolTableSection

import worldbox_native_scan as triage
import worldbox_thunk_callers as thunks

NEEDLES = {
    'metadata_filename': 'global-metadata.dat',
    'unity_metadata_path': 'assets/bin/Data/Managed/Metadata/global-metadata.dat',
    'metadata_relative_path': 'Metadata/global-metadata.dat',
}
ENCODINGS = ('ascii', 'utf16le')
CHUNK_SIZE = 1024 * 1024
MAX_EXAMPLES = 12
MAX_SECTION = 96 * 1024 * 1024
CONTEXT_BEFORE = 64
CONTEXT_AFTER = 128
MAX_POINTERS = 8
CONTEXT_ADDRESSES = (0x40f1f70, 0x40f1f78, 0x3e45c38)


def encoded_needles(text):
    return {'ascii': text.encode('ascii'), 'utf16le': text.encode('utf-16le')}


def needle_in_stream(handle, needle, location_fields=None, chunk_size=CHUNK_SIZE,
                     max_examples=MAX_EXAMPLES, base_offset=0):
    """Count overlapping needle occurrences across chunk boundaries.

    ``base_offset`` is the absolute offset of the first byte in the stream.
    The carry is shorter than the needle, so a match cannot be counted twice.
    """
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


def elf_string_scan(path, needles=NEEDLES):
    with Path(path).open('rb') as f:
        elf = ELFFile(f)
        if elf.elfclass != 64 or not elf.little_endian or elf['e_machine'] != 'EM_AARCH64':
            raise ValueError('Expected a little-endian ELF64 AArch64 library')
        sections = [sec for sec in elf.iter_sections() if sec['sh_type'] != 'SHT_NOBITS']
        scanned = skipped = 0
        results = {}
        for label, text in needles.items():
            per_encoding = {}
            for encoding, needle in encoded_needles(text).items():
                count = 0
                examples = []
                for sec in sections:
                    if sec['sh_size'] > MAX_SECTION:
                        skipped += 1
                        continue
                    data = sec.data()
                    scanned += len(data)
                    fields = {'section': sec.name, 'sectionAddress': hex(sec['sh_addr'])}
                    found, found_examples = needle_in_bytes(
                        data, needle, fields, base_offset=sec['sh_addr'])
                    count += found
                    examples.extend(found_examples)
                per_encoding[encoding] = {
                    'count': count, 'examples': examples[:MAX_EXAMPLES],
                    'examplesTruncated': len(examples) > MAX_EXAMPLES}
            results[label] = per_encoding
    return {'kind': 'elf-string-scan', 'scannedSectionBytes': scanned,
            'sectionsSkippedAsTooLarge': skipped, 'results': results}


def apk_string_scan(path, needles=NEEDLES):
    with zipfile.ZipFile(path) as apk:
        entries = [info for info in apk.infolist() if not info.is_dir()]
        scanned = sum(info.file_size for info in entries)
        results = {}
        for label, text in needles.items():
            per_encoding = {}
            for encoding, needle in encoded_needles(text).items():
                count = 0
                examples = []
                # Entry names are checked first so a known metadata path is not
                # crowded out by later content matches.
                for info in entries:
                    fields = {'entry': info.filename, 'kind': 'entry-name'}
                    found, found_examples = needle_in_bytes(
                        info.filename.encode('utf-8', errors='replace'), needle, fields)
                    count += found
                    examples.extend(found_examples)
                for info in entries:
                    fields = {'entry': info.filename, 'kind': 'content'}
                    with apk.open(info) as handle:
                        remaining = max(0, MAX_EXAMPLES - len(examples))
                        found, found_examples = needle_in_stream(
                            handle, needle, fields, max_examples=remaining)
                    count += found
                    examples.extend(found_examples)
                per_encoding[encoding] = {
                    'count': count, 'examples': examples[:MAX_EXAMPLES],
                    'examplesTruncated': len(examples) > MAX_EXAMPLES}
            results[label] = per_encoding
    return {'kind': 'apk-string-scan', 'entriesScanned': len(entries),
            'entryContentBytesScanned': scanned, 'results': results}


def relocation_addend(elf, sec):
    if not isinstance(sec, RelocationSection) or not sec.is_RELA():
        return None, False
    symbols = elf.get_section(sec['sh_link'])
    for rel in sec.iter_relocations():
        kind, addend = rel['r_info_type'], rel['r_addend']
        value = None
        if kind == 1027:
            value = addend
        elif kind in (257, 1025) and isinstance(symbols, SymbolTableSection):
            index = rel['r_info_sym']
            if index < symbols.num_symbols():
                value = symbols.get_symbol(index)['st_value'] + addend
        yield rel['r_offset'], kind, value


def section_context_summary(path, address):
    with Path(path).open('rb') as f:
        elf = ELFFile(f)
        sections = thunks.allocated_sections(elf)
        sec = thunks.section_containing(sections, address)
        if sec is None:
            return {'address': hex(address), 'status': 'not-in-allocated-section'}
        row = thunks.static_data_summary(f, sections, address)
        start = max(sec['sh_addr'], address - CONTEXT_BEFORE)
        end = min(sec['sh_addr'] + sec['sh_size'], address + CONTEXT_AFTER)
        row.update({'sectionAddress': hex(sec['sh_addr']),
                    'sectionOffset': hex(sec['sh_offset']),
                    'sectionType': str(sec['sh_type']),
                    'sectionFlags': sec['sh_flags']})
        if sec['sh_type'] != 'SHT_NOBITS':
            f.seek(sec['sh_offset'] + (start - sec['sh_addr']))
            window = f.read(end - start)
            printable = 0
            while printable < len(window) and 32 <= window[printable] <= 126:
                printable += 1
            aligned = window[:len(window) & ~7]
            pointers = []
            for index, (value,) in enumerate(struct.iter_unpack('<Q', aligned)):
                if not value:
                    continue
                described = thunks.describe_pointer(value, sections)
                if described:
                    pointers.append({'wordOffset': hex(index * 8), **described})
                if len(pointers) >= MAX_POINTERS:
                    break
            row['contextWindow'] = {
                'start': hex(start), 'end': hex(end), 'bytesRead': len(window),
                'sha256': hashlib.sha256(window).hexdigest(),
                'zeroBytes': window.count(0), 'printablePrefixLength': printable,
                'stringCategory': triage.string_category(window),
                'alignedWordsExamined': len(aligned) // 8,
                'pointerTargets': pointers,
                'pointerTargetsTruncated': len(pointers) >= MAX_POINTERS}
        else:
            row['contextWindow'] = {'start': hex(start), 'end': hex(end),
                                    'status': 'no-initial-file-bytes'}
        neighbors = []
        unsupported = []
        for rel_sec in elf.iter_sections():
            if not isinstance(rel_sec, RelocationSection):
                continue
            if not rel_sec.is_RELA():
                unsupported.append(rel_sec.name)
                continue
            for slot, kind, value in relocation_addend(elf, rel_sec):
                if not (start <= slot < end):
                    continue
                described = thunks.describe_pointer(value, sections) if value is not None else None
                neighbors.append({
                    'section': rel_sec.name, 'slot': hex(slot), 'type': kind,
                    'valueSection': described['section'] if described else None,
                    'valueOffset': described['offset'] if described else None,
                    'valueIsThunkTarget': value in thunks.THUNKS})
                if len(neighbors) >= MAX_EXAMPLES:
                    break
            if len(neighbors) >= MAX_EXAMPLES:
                break
        row['neighborRelocations'] = neighbors
        row['neighborRelocationsTruncated'] = len(neighbors) >= MAX_EXAMPLES
        row['unsupportedRelocationSections'] = sorted(set(unsupported))
        return row


def build_report(native, unity, base_apk):
    files = []
    for role, path in (('libil2cpp', native), ('libunity', unity), ('base.apk', base_apk)):
        path = Path(path)
        if not path.is_file():
            raise FileNotFoundError(f'Missing required bundle member: {role}')
        with path.open('rb') as f:
            digest = hashlib.file_digest(f, 'sha256').hexdigest()
        scan = apk_string_scan(path, NEEDLES) if role == 'base.apk' else elf_string_scan(path, NEEDLES)
        files.append({'role': role, 'sha256': digest, 'bytes': path.stat().st_size, 'scan': scan})
    contexts = [section_context_summary(native, address) for address in CONTEXT_ADDRESSES]
    return {'kind': 'worldbox-metadata-path-probe',
            'needles': NEEDLES, 'encodings': ENCODINGS, 'files': files,
            'sectionContexts': contexts,
            'limitations': 'Exact predefined ASCII/UTF-16LE substring counts and bounded ELF/APK section summaries only. Encrypted, encoded, constructed, compressed, runtime-generated or non-UTF-16LE path strings are not excluded by zero counts. Section context and relocation addends are static structure, not executed control flow.'}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--native', required=True)
    parser.add_argument('--unity', required=True)
    parser.add_argument('--base-apk', required=True)
    args = parser.parse_args()
    print(json.dumps(build_report(args.native, args.unity, args.base_apk), separators=(',', ':')))


if __name__ == '__main__':
    main()

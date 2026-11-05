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

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from elftools.elf.sections import SymbolTableSection

import worldbox_native_flow as flow
import worldbox_native_scan as triage
import worldbox_native_xrefs as xrefs
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
MAX_REFS = 12
ADRP_WINDOW = 36
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


def in_ranges(value, ranges):
    return value is not None and any(lo <= value < hi for lo, hi in ranges)


def section_characterization(path, section_name='il2cpp'):
    """Bounded structural summary of a named ELF section and static references."""
    with Path(path).open('rb') as f:
        elf = ELFFile(f)
        sections = thunks.allocated_sections(elf)
        target_sections = [sec for sec in elf.iter_sections() if sec.name == section_name]
        ranges = [(sec['sh_addr'], sec['sh_addr'] + sec['sh_size']) for sec in target_sections]
        inventory = []
        for sec in target_sections:
            row = {'name': sec.name, 'type': str(sec['sh_type']), 'flags': sec['sh_flags'],
                   'sectionAddress': hex(sec['sh_addr']), 'sectionOffset': hex(sec['sh_offset']),
                   'sectionSize': sec['sh_size'], 'link': sec['sh_link'], 'info': sec['sh_info'],
                   'alignment': sec['sh_addralign'], 'entrySize': sec['sh_entsize'],
                   'writable': bool(sec['sh_flags'] & 1),
                   'executable': bool(sec['sh_flags'] & 4),
                   'sectionKind': 'nobits' if sec['sh_type'] == 'SHT_NOBITS' else 'file-backed'}
            if sec['sh_type'] != 'SHT_NOBITS' and sec['sh_size'] <= MAX_SECTION:
                data = sec.data()
                printable = 0
                while printable < len(data) and 32 <= data[printable] <= 126:
                    printable += 1
                aligned = data[:len(data) & ~7]
                pointers = []
                for index, (value,) in enumerate(struct.iter_unpack('<Q', aligned)):
                    if not value:
                        continue
                    described = thunks.describe_pointer(value, sections)
                    if described:
                        pointers.append({'wordOffset': hex(index * 8), **described})
                    if len(pointers) >= MAX_POINTERS:
                        break
                row['dataSummary'] = {
                    'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(),
                    'zeroBytes': data.count(0), 'printablePrefixLength': printable,
                    'stringCategory': triage.string_category(data),
                    'alignedWordsExamined': len(aligned) // 8,
                    'pointerTargets': pointers,
                    'pointerTargetsTruncated': len(pointers) >= MAX_POINTERS}
            inventory.append(row)

        frames, unwind_status = thunks.unwind_frames(elf)
        starts = [lo for lo, _ in frames]
        decoder = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
        decoder.detail = True
        adrp_add_count = direct_call_count = tail_branch_count = 0
        adrp_add_samples = []
        direct_samples = []
        tail_samples = []
        exec_scanned = exec_total = 0
        for sec in thunks.executable_sections(elf):
            exec_total += sec['sh_size']
            budget = max(0, MAX_SECTION - exec_scanned) & ~3
            if not budget:
                continue
            data = sec.data()[:budget]
            exec_scanned += len(data)
            words = list(struct.iter_unpack('<I', data[:len(data) & ~3]))
            for index, (word,) in enumerate(words):
                off = index * 4
                pc = sec['sh_addr'] + off
                for target, count_key, samples in (
                        (triage.direct_branch(word, pc), 'direct_call', direct_samples),
                        (xrefs.direct_tail(word, pc), 'tail_branch', tail_samples)):
                    if in_ranges(target, ranges):
                        if count_key == 'direct_call':
                            direct_call_count += 1
                        else:
                            tail_branch_count += 1
                        if len(samples) < MAX_REFS:
                            frame = flow.frame_for_site(frames, starts, pc)
                            samples.append({'site': hex(pc), 'kind': count_key,
                                            'function': hex(frame[0]) if frame else None,
                                            'size': frame[1] - frame[0] if frame else None})
                page = xrefs.adrp_value(word, pc)
                if page is None or page[1] == 31:
                    continue
                for nextoff in range(off + 4, min(off + ADRP_WINDOW, len(data)), 4):
                    following = struct.unpack_from('<I', data, nextoff)[0]
                    add = xrefs.add_value(following)
                    if not add or add[0] != page[1]:
                        continue
                    value = page[0] + add[1]
                    if not in_ranges(value, ranges):
                        continue
                    if not xrefs.verify_adrp_add(decoder, data[off:nextoff + 4], pc,
                                                 page[1], sec['sh_addr'] + nextoff):
                        continue
                    adrp_add_count += 1
                    if len(adrp_add_samples) < MAX_REFS:
                        frame = flow.frame_for_site(frames, starts, pc)
                        adrp_add_samples.append({
                            'adrp': hex(pc), 'add': hex(sec['sh_addr'] + nextoff),
                            'value': hex(value),
                            'function': hex(frame[0]) if frame else None,
                            'size': frame[1] - frame[0] if frame else None})
                    break

        data_pointer_count = 0
        data_pointer_samples = []
        data_scanned = data_total = 0
        for sec in sections:
            if sec['sh_type'] == 'SHT_NOBITS' or isinstance(sec, RelocationSection):
                continue
            data_total += sec['sh_size']
            budget = max(0, MAX_SECTION - data_scanned)
            if not budget:
                continue
            data = sec.data()[:budget]
            data_scanned += len(data)
            first = (-sec['sh_addr']) % 8
            aligned = data[first:first + ((len(data) - first) // 8) * 8] if len(data) >= first else b''
            for index, (value,) in enumerate(struct.iter_unpack('<Q', aligned)):
                if not in_ranges(value, ranges):
                    continue
                data_pointer_count += 1
                if len(data_pointer_samples) < MAX_REFS:
                    described = thunks.describe_pointer(value, sections)
                    data_pointer_samples.append({
                        'section': sec.name,
                        'location': hex(sec['sh_addr'] + first + index * 8),
                        'pointerTarget': described})

        relocation_count = 0
        relocation_samples = []
        unsupported = []
        for rel_sec in elf.iter_sections():
            if not isinstance(rel_sec, RelocationSection):
                continue
            if not rel_sec.is_RELA():
                unsupported.append(rel_sec.name)
                continue
            for slot, kind, value in relocation_addend(elf, rel_sec):
                if not in_ranges(value, ranges):
                    continue
                relocation_count += 1
                if len(relocation_samples) < MAX_REFS:
                    described = thunks.describe_pointer(value, sections) if value is not None else None
                    relocation_samples.append({
                        'section': rel_sec.name, 'slot': hex(slot), 'type': kind,
                        'valueSection': described['section'] if described else None,
                        'valueOffset': described['offset'] if described else None,
                        'valueIsThunkTarget': value in thunks.THUNKS})
        return {'sectionName': section_name, 'sectionCount': len(target_sections),
                'sections': inventory,
                'unwindStatus': unwind_status, 'unwindRanges': len(frames),
                'executableBytes': exec_total, 'executableScanned': exec_scanned,
                'execTruncated': exec_scanned < exec_total,
                'allocatedDataBytes': data_total, 'allocatedDataScanned': data_scanned,
                'dataTruncated': data_scanned < data_total,
                'adrpAddReferences': {'count': adrp_add_count, 'samples': adrp_add_samples,
                                      'samplesTruncated': len(adrp_add_samples) >= MAX_REFS},
                'directCalls': {'count': direct_call_count, 'samples': direct_samples,
                                'samplesTruncated': len(direct_samples) >= MAX_REFS},
                'tailBranches': {'count': tail_branch_count, 'samples': tail_samples,
                                 'samplesTruncated': len(tail_samples) >= MAX_REFS},
                'dataPointers': {'count': data_pointer_count, 'samples': data_pointer_samples,
                                 'samplesTruncated': len(data_pointer_samples) >= MAX_REFS},
                'relocationAddends': {'count': relocation_count, 'samples': relocation_samples,
                                      'samplesTruncated': len(relocation_samples) >= MAX_REFS},
                'unsupportedRelocationSections': sorted(set(unsupported)),
                'limitations': 'Linear instruction decoding, aligned-word matching and RELA addends identify static candidates, not executed control flow. Indirect references, packed relocations and runtime-generated pointers are not fully modeled.'}


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
    characterization = section_characterization(native, 'il2cpp')
    return {'kind': 'worldbox-metadata-path-probe',
            'needles': NEEDLES, 'encodings': ENCODINGS, 'files': files,
            'sectionContexts': contexts, 'sectionCharacterization': characterization,
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

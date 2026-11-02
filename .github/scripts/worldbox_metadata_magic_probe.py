#!/usr/bin/env python3
"""Hash-gated IL2CPP metadata-magic scan and bounded Ghidra xref follow-up.

Only offsets, ELF-relative addresses, and aggregate/decompiler-safe summaries are
emitted. No native bytes, arbitrary strings, or game files leave the runner.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

from elftools.elf.elffile import ELFFile
import worldbox_native_xrefs as xrefs

EXPECTED_SHA256 = '1d644b98fec97a35630495c695515861acd2c18209beaae6471a650db65def87'
MAGIC = b'\xaf\x1b\xb1\xfa'  # IL2CPP metadata magic 0xFAB11BAF in little-endian form
MAX_BINARY = 256 * 1024 * 1024
MAX_HITS = 128
MAX_XREFS = 12


def occurrences(data, needle=MAGIC, limit=MAX_HITS):
    """Return bounded offsets for every occurrence, including overlapping ones."""
    found = []
    start = 0
    while len(found) < limit:
        offset = data.find(needle, start)
        if offset < 0:
            return found, False
        found.append(offset)
        start = offset + 1
    return found, data.find(needle, start) >= 0


def scan_binary(path):
    path = Path(path)
    size = path.stat().st_size
    if size > MAX_BINARY:
        raise ValueError('Native library exceeds the bounded scan size')
    with path.open('rb') as handle:
        digest = hashlib.file_digest(handle, 'sha256').hexdigest()
    if digest != EXPECTED_SHA256:
        raise ValueError('ARM64 library hash does not match the observed WorldBox 0.51.4 sample; refusing analysis')
    data = path.read_bytes()
    offsets, truncated = occurrences(data)
    with path.open('rb') as handle:
        elf = ELFFile(handle)
        if elf.elfclass != 64 or not elf.little_endian or elf['e_machine'] != 'EM_AARCH64':
            raise ValueError('Expected a little-endian ELF64 AArch64 library')
        sections = [section for section in elf.iter_sections()
                    if section['sh_type'] != 'SHT_NOBITS' and section['sh_flags'] & 2]
        hits = []
        for offset in offsets:
            section = next((item for item in sections
                            if item['sh_offset'] <= offset and offset + len(MAGIC) <= item['sh_offset'] + item['sh_size']), None)
            hits.append({'fileOffset': hex(offset),
                         'virtualAddress': hex(section['sh_addr'] + offset - section['sh_offset']) if section else None,
                         'section': section.name if section else None,
                         'executable': bool(section and section['sh_flags'] & 4)})
        return {'sha256': digest, 'fileSize': size, 'hitCount': len(offsets),
                'hitsTruncated': truncated, 'hits': hits}


def address_references(path, targets):
    """Find bounded ADRP+ADD references into target data and return caller anchors."""
    refs = []
    with Path(path).open('rb') as handle:
        elf = ELFFile(handle)
        for target in sorted(set(targets)):
            for section in elf.iter_sections():
                if not section['sh_flags'] & 4 or section['sh_type'] == 'SHT_NOBITS':
                    continue
                count, _tails, _pairs, pairs = xrefs.executable_refs(section.data(), section['sh_addr'], target)
                del count, _tails
                for pair in pairs:
                    if len(refs) >= MAX_XREFS:
                        return refs, True
                    refs.append({'target': hex(target), 'anchor': pair['adrp'], 'add': pair['add']})
    return refs, False


def inspect(path, headless=None):
    scan = scan_binary(path)
    data_targets = sorted({int(hit['virtualAddress'], 16) for hit in scan['hits']
                           if hit['virtualAddress'] and not hit['executable']})
    refs, refs_truncated = address_references(path, data_targets) if data_targets else ([], False)
    report = {'kind': 'worldbox-il2cpp-metadata-magic-probe', 'scan': scan,
              'dataTargets': [hex(value) for value in data_targets],
              'referenceCount': len(refs), 'referencesTruncated': refs_truncated,
              'references': refs, 'ghidra': None}
    if refs and headless:
        addresses = sorted({int(item['anchor'], 16) for item in refs})
        command = [sys.executable, '.github/scripts/worldbox_ghidra_callees.py',
                   '--headless', headless, '--binary', str(path)]
        for address in addresses:
            command += ['--address', hex(address)]
        result = subprocess.run(command, capture_output=True, text=True, timeout=1000)
        if result.returncode:
            raise RuntimeError('Address-targeted Ghidra probe failed: ' + (result.stderr or result.stdout)[-1200:])
        ghidra = json.loads(result.stdout)
        if ghidra.get('kind') != 'ghidra-callees-probe':
            raise RuntimeError('Unexpected address-targeted Ghidra report')
        report['ghidra'] = ghidra
    report['limitations'] = ('Magic-byte matches are signatures only, not proof of a metadata loader. Reference scanning recognizes '
                             'bounded ADRP+ADD patterns only; other addressing forms and indirect references may be missed. '
                             'Ghidra output is heuristic and does not prove runtime use.')
    return report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', required=True)
    parser.add_argument('--headless')
    args = parser.parse_args()
    try:
        print(json.dumps(inspect(args.binary, args.headless), separators=(',', ':')))
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
        print('Metadata magic probe failed: ' + str(exc), file=sys.stderr)
        raise SystemExit(1)


if __name__ == '__main__':
    main()

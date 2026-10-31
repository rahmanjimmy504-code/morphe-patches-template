#!/usr/bin/env python3
"""Bounded ARM64 callsite and argument triage; publishes categories only.

Direct branches are candidates from an executable-section sweep. The small CFG
model is not a recovered call graph, runtime trace, or proof of file access.
"""
import argparse
import json
from pathlib import Path

from elftools.dwarf.callframe import FDE
from elftools.elf.elffile import ELFFile
import worldbox_native_flow as flow
import worldbox_native_scan as scan
import worldbox_native_xrefs as refs

TARGET = 0x18fac60
MAX_EXEC = 96 * 1024 * 1024
SAMPLE_LIMIT = 8


def inspect(path, target=TARGET):
    with Path(path).open('rb') as handle:
        elf = ELFFile(handle)
        if elf.elfclass != 64 or not elf.little_endian or elf['e_machine'] != 'EM_AARCH64':
            raise ValueError('Expected a little-endian ELF64 AArch64 library')
        executable = [s for s in elf.iter_sections() if s['sh_flags'] & 4 and s['sh_type'] != 'SHT_NOBITS']
        constants = [s for s in elf.iter_sections() if s['sh_flags'] & 2 and not s['sh_flags'] & (1 | 4)
                     and s['sh_type'] != 'SHT_NOBITS']
        imports = refs.safe_import_plt(elf)
        counts = {'directCalls': 0, 'directTailBranches': 0}
        samples = []
        total = sum(sec['sh_size'] for sec in executable)
        scanned = 0
        for sec in executable:
            budget = max(0, MAX_EXEC - scanned) & ~3
            if not budget:
                break
            data = sec.data()[:budget]
            scanned += len(data) & ~3
            for site, word in scan.instructions(data, sec['sh_addr']):
                kind = None
                if scan.direct_branch(word, site) == target:
                    kind = 'directCalls'
                elif refs.direct_tail(word, site) == target:
                    kind = 'directTailBranches'
                if kind:
                    counts[kind] += 1
                    if len(samples) < SAMPLE_LIMIT:
                        samples.append({'site': site, 'kind': kind})
        eh = elf.get_section_by_name('.eh_frame')
        unwind_status, frames = 'missing', []
        if eh and eh['sh_size'] > flow.MAX_EH_SIZE:
            unwind_status = 'too-large'
        elif eh:
            try:
                dwarf = elf.get_dwarf_info()
                if dwarf.has_EH_CFI():
                    frames = sorted((e['initial_location'], e['initial_location'] + e['address_range'])
                                    for e in dwarf.EH_CFI_entries() if isinstance(e, FDE) and e['address_range'])
                    unwind_status = 'parsed'
                else:
                    unwind_status = 'no-cfi'
            except Exception as exc:
                unwind_status = 'parse-error-' + type(exc).__name__
        starts = [lo for lo, _ in frames]

        def classify(value):
            section = next((s for s in constants if s['sh_addr'] <= value < s['sh_addr'] + s['sh_size']), None)
            if section is None:
                return 'small-constant' if 0 <= value <= 4096 else 'other-constant'
            offset = value - section['sh_addr']
            handle.seek(section['sh_offset'] + offset)
            return scan.string_category(handle.read(min(128, section['sh_size'] - offset))) or 'other-constant'

        examples = []
        for sample in samples:
            site = sample['site']
            row = {'site': hex(site), 'kind': sample['kind']}
            frame = flow.frame_for_site(frames, starts, site)
            if frame is None:
                row['status'] = 'no-unwind-range'
                examples.append(row)
                continue
            lo, hi = frame
            sec = next((s for s in executable if s['sh_addr'] <= lo and hi <= s['sh_addr'] + s['sh_size']), None)
            if sec is None or hi - lo > flow.MAX_FUNCTION or lo % 4:
                row['status'] = 'unusable-or-too-large-range'
                examples.append(row)
                continue
            handle.seek(sec['sh_offset'] + lo - sec['sh_addr'])
            # Treat the known target as an artificial function marker, not a verified ABI or name.
            plt = dict(imports)
            plt[target] = 'source-helper'
            result = flow.analyze_window(handle.read(hi - lo), lo, plt, {site: 'source-helper'}, classify)
            call = result['calls'][0]
            x0 = call.get('arguments', {}).get('x0', [])
            origin_sites = {item.rsplit('@', 1)[1] for item in x0 if '@' in item}
            origins = [item for item in call.get('callOrigins', []) if item['site'] in origin_sites]
            row.update({'function': hex(lo), 'status': 'modeled', 'reachedInModel': call['reachedInModel'],
                        'x0': x0, 'x0CallOrigins': origins, 'callOriginsTruncated': call['callOriginsTruncated'],
                        'workLimitReached': result['workLimitReached']})
            examples.append(row)
        return {'target': hex(target), 'executableBytesTotal': total, 'executableBytesScanned': scanned,
                'execTruncated': scanned < total, 'directCalls': counts['directCalls'],
                'directTailBranches': counts['directTailBranches'], 'sampleLimit': SAMPLE_LIMIT,
                'samplesTruncated': sum(counts.values()) > len(samples), 'unwindStatus': unwind_status,
                'examples': examples,
                'limitation': 'Linear-sweep candidates and bounded may-provenance do not prove code reachability, memory contents, actual file access or metadata use.'}


def annotation_payloads(report):
    summary = {key: value for key, value in report.items() if key != 'examples'}
    examples = report.get('examples', [])[:SAMPLE_LIMIT]
    texts = [json.dumps(summary, separators=(',', ':'))]
    texts.extend(json.dumps(row, separators=(',', ':')) for row in examples)
    if any(len(text) > 3800 for text in texts):
        raise ValueError('Upstream report exceeds annotation safety bounds')
    return texts


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('elf')
    args = parser.parse_args()
    print(json.dumps(inspect(args.elf), separators=(',', ':')))

if __name__ == '__main__':
    main()

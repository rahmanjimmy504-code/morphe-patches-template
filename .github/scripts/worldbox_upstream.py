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


def reference_summary(path, target):
    """Summarize candidate address references without publishing section names or code."""
    report = refs.inspect(path, target)
    pairs = report['pcRelativeAddressPairs']
    relocations = report['matchingRelocations']
    pointers = report['alignedPointerValues']
    return {
        'symbolMatches': report['symbolMatches'],
        'pcRelativePairs': {'count': pairs['count'], 'sampleSites': pairs['samples'][:4]},
        'relocations': {'count': relocations['count'],
                        'sampleSlots': [item['slot'] for item in relocations['samples'][:4]],
                        'sampleTypes': [item['type'] for item in relocations['samples'][:4]],
                        'unsupportedSectionCount': len(relocations['unsupportedRelocationSections'])},
        'alignedPointers': {'count': pointers['count'],
                            'samples': [{'location': item['location'],
                                         'sectionKind': 'relocation-section' if item['section'].startswith(('.rel', '.android.rel'))
                                                        else 'other-allocated-section'} for item in pointers['samples'][:4]]},
        'executableBytesScanned': report['executableScanned'], 'execTruncated': report['execTruncated'],
        'allocatedDataBytesScanned': report['allocatedDataScanned'], 'dataTruncated': report['dataTruncated'],
        'limitation': 'Static references are candidates, not proof of runtime calls; indirect values and packed relocations may be missed.'}


def trace_origin(path, target, caller, caller_kind='direct'):
    """Trace a verified BL or B target within its bounded unwind body."""
    if caller_kind not in ('direct', 'tail'):
        raise ValueError('Expected direct or tail branch kind')
    with Path(path).open('rb') as handle:
        elf = ELFFile(handle)
        if elf.elfclass != 64 or not elf.little_endian or elf['e_machine'] != 'EM_AARCH64':
            raise ValueError('Expected a little-endian ELF64 AArch64 library')
        executable = [s for s in elf.iter_sections() if s['sh_flags'] & 4 and s['sh_type'] != 'SHT_NOBITS']
        sec = next((s for s in executable if s['sh_addr'] <= caller and caller + 4 <= s['sh_addr'] + s['sh_size']), None)
        if sec is None:
            raise ValueError('Origin caller is not executable')
        handle.seek(sec['sh_offset'] + caller - sec['sh_addr'])
        raw = handle.read(4)
        decode = scan.direct_branch if caller_kind == 'direct' else refs.direct_tail
        if len(raw) != 4 or decode(int.from_bytes(raw, 'little'), caller) != target:
            raise ValueError('Origin caller is not the expected ' + caller_kind + ' branch')
        eh = elf.get_section_by_name('.eh_frame')
        if eh is None or eh['sh_size'] > flow.MAX_EH_SIZE:
            return {'target': hex(target), 'caller': hex(caller), 'status': 'unwind-unavailable'}
        dwarf = elf.get_dwarf_info()
        if not dwarf.has_EH_CFI():
            return {'target': hex(target), 'caller': hex(caller), 'status': 'no-cfi'}
        frames = sorted((e['initial_location'], e['initial_location'] + e['address_range'])
                        for e in dwarf.EH_CFI_entries() if isinstance(e, FDE) and e['address_range'])
        frame = flow.frame_for_site(frames, [lo for lo, _ in frames], target)
        if frame is None or frame[0] != target or frame[1] - frame[0] > flow.MAX_FUNCTION:
            return {'target': hex(target), 'caller': hex(caller), 'status': 'unusable-unwind-range'}
        lo, hi = frame
        sec = next((s for s in executable if s['sh_addr'] <= lo and hi <= s['sh_addr'] + s['sh_size']), None)
        if sec is None:
            return {'target': hex(target), 'caller': hex(caller), 'status': 'non-executable-range'}
        constants = [s for s in elf.iter_sections() if s['sh_flags'] & 2 and not s['sh_flags'] & (1 | 4)
                     and s['sh_type'] != 'SHT_NOBITS']
        def classify(value):
            section = next((s for s in constants if s['sh_addr'] <= value < s['sh_addr'] + s['sh_size']), None)
            if section is None:
                return 'small-constant' if 0 <= value <= 4096 else 'other-constant'
            offset = value - section['sh_addr']
            handle.seek(section['sh_offset'] + offset)
            return scan.string_category(handle.read(min(128, section['sh_size'] - offset))) or 'other-constant'
        imports = refs.safe_import_plt(elf)
        handle.seek(sec['sh_offset'] + lo - sec['sh_addr'])
        flow_result = flow.analyze_window(handle.read(hi - lo), lo, imports, {}, classify, capture_returns=True)
        caller_info = {'status': 'no-unwind-range'}
        caller_frame = flow.frame_for_site(frames, [frame_lo for frame_lo, _ in frames], caller)
        if caller_frame is not None:
            caller_lo, caller_hi = caller_frame
            caller_sec = next((s for s in executable if s['sh_addr'] <= caller_lo and caller_hi <= s['sh_addr'] + s['sh_size']), None)
            if caller_sec is None or caller_hi - caller_lo > flow.MAX_FUNCTION or caller_lo % 4:
                caller_info = {'status': 'unusable-or-too-large-range'}
            else:
                handle.seek(caller_sec['sh_offset'] + caller_lo - caller_sec['sh_addr'])
                caller_bytes = handle.read(caller_hi - caller_lo)
                caller_imports = dict(imports)
                caller_imports[target] = 'source-helper'
                caller_result = flow.analyze_window(caller_bytes, caller_lo, caller_imports,
                                                    {caller: 'source-helper'}, classify)
                call = caller_result['calls'][0]
                arguments = {reg: call.get('arguments', {}).get(reg, []) for reg in ('x0', 'x1', 'x2')}
                origin_sites = {value.rsplit('@', 1)[1] for values in arguments.values() for value in values if '@' in value}
                origins = [item for item in call.get('callOrigins', []) if item['site'] in origin_sites]
                caller_info = {'status': 'modeled', 'function': hex(caller_lo),
                               'reachedInModel': call['reachedInModel'], 'arguments': arguments,
                               'callOrigins': origins[:4],
                               'callOriginsTruncated': call.get('callOriginsTruncated', False) or len(origins) > 4,
                               'workLimitReached': caller_result['workLimitReached']}
        returns = []
        for item in flow_result['returns'][:4]:
            entry = dict(item)
            entry['callOrigins'] = entry.get('callOrigins', [])[:4]
            entry['callOriginsTruncated'] = item.get('callOriginsTruncated', False) or len(item.get('callOrigins', [])) > 4
            returns.append(entry)
        transfers = flow_result['tailTransfers'][:4]
        return {'target': hex(target), 'caller': hex(caller), 'callerKind': caller_kind, 'status': 'modeled', 'fdeBytes': hi - lo,
                'callerInputs': caller_info,
                'decodedInstructions': flow_result['decodedInstructions'], 'visitedInstructions': flow_result['visitedInstructions'],
                'workLimitReached': flow_result['workLimitReached'], 'returns': returns,
                'returnsTruncated': flow_result['returnsTruncated'] or len(flow_result['returns']) > 4,
                'tailTransfers': transfers,
                'tailTransfersTruncated': flow_result['tailTransfersTruncated'] or len(flow_result['tailTransfers']) > 4,
                'limitation': 'Static register origins and transfers do not establish runtime values, reachability, or entitlement behavior.'}


def inspect_many(path, targets, references=False, origin=None):
    """Evaluate at most two distinct bounded upstream targets."""
    if (not 1 <= len(targets) <= 2 or len(set(targets)) != len(targets) or
            any(not isinstance(value, int) or value < 0 or value > 0xffffffffffffffff or value % 4
                for value in targets)):
        raise ValueError('Expected one or two distinct aligned ARM64 targets')
    reports = []
    for target in targets:
        row = inspect(path, target)
        if references:
            row['referenceSummary'] = reference_summary(path, target)
        reports.append(row)
    result = {'kind': 'arm64-upstream-multi', 'reports': reports}
    if origin is not None:
        result['origin'] = trace_origin(path, *origin)
    return result


def multi_annotation_payloads(report):
    """Emit at most ten short warnings, explicitly reporting hidden samples."""
    reports = report.get('reports', [])
    if report.get('kind') != 'arm64-upstream-multi' or not 1 <= len(reports) <= 2:
        raise ValueError('Unexpected upstream multi-target report')
    entries = []
    for item in reports:
        examples = item.get('examples', [])
        selected = examples[:3 if report.get('origin') is not None else 4]
        summary = {key: value for key, value in item.items() if key != 'examples'}
        summary['annotationExamplesAvailable'] = len(examples)
        summary['annotationExamplesEmitted'] = len(selected)
        summary['annotationExamplesTruncated'] = len(examples) > len(selected)
        entries.append(('summary', json.dumps(summary, separators=(',', ':'))))
        for example in selected:
            entries.append(('example', json.dumps({'target': item['target'], **example}, separators=(',', ':'))))
    if report.get('origin') is not None:
        entries.append(('origin', json.dumps(report['origin'], separators=(',', ':'))))
    if len(entries) > 10 or any(len(text) > 3800 for _, text in entries):
        raise ValueError('Upstream multi-target report exceeds annotation bounds')
    return entries


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('elf')
    parser.add_argument('--target', action='append', type=lambda value: int(value, 0))
    parser.add_argument('--references', action='store_true')
    parser.add_argument('--trace-origin', type=lambda value: int(value, 0))
    parser.add_argument('--caller', type=lambda value: int(value, 0))
    parser.add_argument('--caller-kind', choices=('direct', 'tail'), default='direct')
    parser.add_argument('--only-origin', action='store_true')
    args = parser.parse_args()
    if args.references and not args.target:
        parser.error('--references requires one or two explicit targets')
    if (args.trace_origin is None) != (args.caller is None):
        parser.error('--trace-origin and --caller require each other')
    if args.only_origin:
        if args.trace_origin is None or args.target or args.references:
            parser.error('--only-origin requires an origin and excludes targets and references')
        result = {'kind': 'arm64-upstream-origin',
                  'origin': trace_origin(args.elf, args.trace_origin, args.caller, args.caller_kind)}
    else:
        if args.trace_origin is not None and not args.target:
            parser.error('--trace-origin requires explicit targets unless --only-origin is set')
        origin = (args.trace_origin, args.caller, args.caller_kind) if args.trace_origin is not None else None
        result = inspect_many(args.elf, args.target, args.references, origin) if args.target else inspect(args.elf)
    print(json.dumps(result, separators=(',', ':')))

if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""Bounded, aggregate-only Ghidra inspection of two candidate stack-window callees."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

from elftools.dwarf.callframe import FDE
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from elftools.elf.sections import SymbolTableSection
import worldbox_ghidra_probe as previous
import worldbox_native_flow as flow
import worldbox_native_scan as triage
import worldbox_native_xrefs as xrefs

# These sites were independently reported by the prior bounded stack probe.
GAME_CALLS = {0x1891c34: (0x18a8b08, 0x18facb8, 0x1902178, 0x1902260),
              0x18914e8: (0x19021d4, 0x19022b4)}
ORIGIN_CALLS = {0x1903990: (0x3995fc4,)}
MARKER = 'WB_GHIDRA_CALLEES:'


def parse_report(lines):
    reports = []
    for line in lines:
        if MARKER not in line or len(line) > 100000:
            continue
        try:
            obj, _ = json.JSONDecoder().raw_decode(line.split(MARKER, 1)[1].lstrip())
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict) and obj.get('kind') == 'ghidra-callees-probe':
            reports.append(obj)
    if len(reports) != 1:
        raise RuntimeError('Ghidra did not emit exactly one callee report')
    return reports[0]


def import_category(name):
    # Never expose arbitrary imported symbols or app-specific C++ names.
    if name in xrefs.SAFE_IMPORTS or name in {'memcmp', 'memchr', 'strchr', 'strrchr', 'strcat', 'strncat'}:
        return name
    std_prefixes = ('_ZNSt6__ndk1', '_ZNKSt6__ndk1', '_ZNSt3__1', '_ZNKSt3__1')
    if name.startswith(std_prefixes):
        return 'cpp-standard-library-string' if 'basic_string' in name else 'cpp-standard-library-other'
    if name.startswith('__cxa_'):
        return 'cpp-abi-other'
    return 'other-import'


def categorized_imports(elf):
    relocs = {}
    for section in elf.iter_sections():
        if not isinstance(section, RelocationSection) or '.plt' not in section.name:
            continue
        symbols = elf.get_section(section['sh_link'])
        if not isinstance(symbols, SymbolTableSection):
            continue
        for rel in section.iter_relocations():
            index = rel['r_info_sym']
            if index < symbols.num_symbols():
                relocs[rel['r_offset']] = import_category(symbols.get_symbol(index).name)
    return triage.plt_targets(elf, relocs)[0]


def target_plan(path, fixture=False, origin=False):
    if fixture:
        plan = previous.targets(path, fixture=True)
        item = plan['targets'][0]
        return {'imageBase': plan['imageBase'], 'functions': [{'entry': item['entry'], 'size': item['size']}],
                'expected': plan['helper']}
    with Path(path).open('rb') as handle:
        elf = ELFFile(handle)
        if elf.elfclass != 64 or not elf.little_endian or elf['e_machine'] != 'EM_AARCH64':
            raise ValueError('Expected little-endian ELF64 AArch64')
        loads = [p['p_vaddr'] for p in elf.iter_segments() if p['p_type'] == 'PT_LOAD']
        if not loads:
            raise ValueError('ELF has no loadable segments')
        sections = [s for s in elf.iter_sections() if s['sh_flags'] & 4 and s['sh_type'] != 'SHT_NOBITS']
        dwarf = elf.get_dwarf_info()
        if not dwarf.has_EH_CFI():
            raise ValueError('No EH-frame unwind information')
        frames = sorted((e['initial_location'], e['initial_location'] + e['address_range'])
                        for e in dwarf.EH_CFI_entries() if isinstance(e, FDE) and e['address_range'])
        starts = [lo for lo, _ in frames]
        selected = []
        for entry, sites in (ORIGIN_CALLS if origin else GAME_CALLS).items():
            frame = flow.frame_for_site(frames, starts, entry)
            if not frame or frame[0] != entry or frame[1] - frame[0] > flow.MAX_FUNCTION:
                raise ValueError('Target is not the entry of a bounded unwind function')
            if not any(s['sh_addr'] <= entry and frame[1] <= s['sh_addr'] + s['sh_size'] for s in sections):
                raise ValueError('Target range is not executable')
            for site in sites:
                sec = next((s for s in sections if s['sh_addr'] <= site and site + 4 <= s['sh_addr'] + s['sh_size']), None)
                if sec is None:
                    raise ValueError('Caller site is not executable')
                handle.seek(sec['sh_offset'] + site - sec['sh_addr'])
                raw = handle.read(4)
                if len(raw) != 4 or triage.direct_branch(int.from_bytes(raw, 'little'), site) != entry:
                    raise ValueError('Selected caller is not a direct call to expected target')
            selected.append({'entry': entry, 'size': frame[1] - entry})
        return {'imageBase': min(loads), 'functions': selected}


def run_probe(headless, binary, fixture=False, origin=False):
    plan = target_plan(binary, fixture, origin)
    scripts = Path(__file__).resolve().parents[2] / 'docs/worldbox'
    base = Path(os.environ.get('RUNNER_TEMP', tempfile.gettempdir()))
    with tempfile.TemporaryDirectory(prefix='worldbox-ghidra-callees-', dir=base) as td:
        args = [str(headless), td, 'worldbox', '-import', str(Path(binary).resolve()), '-noanalysis',
                '-scriptPath', str(scripts), '-postScript', 'WorldboxProbe.java', 'callees', hex(plan['imageBase'])]
        args += [f"{f['entry']:x}:{f['size']:x}" for f in plan['functions']]
        args += ['-deleteProject', '-max-cpu', '2']
        with (Path(td) / 'headless.log').open('w+', encoding='utf-8') as log:
            run = subprocess.run(args, stdout=log, stderr=subprocess.STDOUT, text=True, timeout=900)
            log.seek(0)
            lines = log.readlines()
            try:
                report = parse_report(lines)
            except RuntimeError as exc:
                diagnostics = [line.strip()[:300] for line in lines
                               if 'WorldboxProbe.java' in line and ('error:' in line.lower() or 'ERROR' in line)]
                raise RuntimeError(str(exc) + (': ' + '; '.join(diagnostics[:3]) if diagnostics else '')) from exc
        if run.returncode:
            raise RuntimeError(f'Ghidra headless exited with status {run.returncode}')
    rows = report.get('functions', [])
    if len(rows) != len(plan['functions']):
        raise RuntimeError('Ghidra did not report every planned function')
    with Path(binary).open('rb') as handle:
        elf = ELFFile(handle)
        imports = categorized_imports(elf)
        sections = [s for s in elf.iter_sections() if s['sh_flags'] & 4 and s['sh_type'] != 'SHT_NOBITS']
        for row in rows:
            for call in row.get('calls', []):
                try:
                    pc, target = int(call['site'], 16), int(call['target'], 16)
                    sec = next((s for s in sections if s['sh_addr'] <= pc and pc + 4 <= s['sh_addr'] + s['sh_size']), None)
                    if sec is None:
                        call['verifiedDirect'] = False
                        continue
                    handle.seek(sec['sh_offset'] + pc - sec['sh_addr'])
                    raw = handle.read(4)
                    call['verifiedDirect'] = len(raw) == 4 and triage.direct_branch(int.from_bytes(raw, 'little'), pc) == target
                    if call['verifiedDirect'] and target in imports:
                        call['importCategory'] = imports[target]
                except (ValueError, KeyError):
                    call['verifiedDirect'] = False
    if fixture and (not rows[0].get('decompiled') or
                    not any(call.get('target') == hex(plan['expected']) and call.get('verifiedDirect')
                            for call in rows[0].get('calls', []))):
        raise RuntimeError('Synthetic Ghidra callee probe failed to recover the expected direct call: ' +
                           json.dumps(rows[0], separators=(',', ':'))[:2800])
    return report


def compact_callee(row):
    """Keep calls and bounded return categories within one safe annotation."""
    row = dict(row)
    graphs = []
    for graph in row.get('returnGraphs', []):
        graphs.append({'roots': graph.get('rootKinds', []), 'strings': graph.get('stringCategories', []),
                       'operations': sorted(graph.get('operationCounts', {})), 'nodes': graph.get('nodes', 0),
                       'limited': bool(graph.get('nodeLimitReached') or graph.get('depthLimitReached'))})
    row['returnGraphs'] = graphs
    calls = []
    for call in row.get('calls', []):
        call = dict(call)
        graph = call.get('firstArgumentGraph')
        if graph is not None:
            call['firstArgumentGraph'] = {'roots': graph.get('rootKinds', []),
                                          'inputRegisters': graph.get('inputRegisters', []),
                                          'operations': sorted(graph.get('operationCounts', {})),
                                          'strings': graph.get('stringCategories', []),
                                          'nodes': graph.get('nodes', 0),
                                          'limited': bool(graph.get('nodeLimitReached') or graph.get('depthLimitReached'))}
        calls.append(call)
    row['calls'] = calls
    text = json.dumps(row, separators=(',', ':'))
    if len(text) > 3800:
        raise ValueError('Ghidra callee summary exceeds the annotation safety bound')
    return text


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--headless', required=True)
    parser.add_argument('--binary', required=True)
    parser.add_argument('--fixture', action='store_true')
    parser.add_argument('--origin', action='store_true')
    args = parser.parse_args()
    try:
        print(json.dumps(run_probe(args.headless, args.binary, args.fixture, args.origin), separators=(',', ':')))
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        if args.fixture and os.environ.get('GITHUB_ACTIONS') == 'true':
            message = str(exc).replace('%', '%25').replace('\r', '%0D').replace('\n', '%0A')
            print('::error title=Synthetic Ghidra callee fixture::' + message[:3000])
        print('Ghidra callee probe failed: ' + str(exc), file=sys.stderr)
        raise SystemExit(1)

if __name__ == '__main__':
    main()

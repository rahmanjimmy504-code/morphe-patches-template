#!/usr/bin/env python3
"""Run a bounded Ghidra probe without publishing binary or decompiled code."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

from elftools.dwarf.callframe import FDE
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

import worldbox_native_flow as flow
import worldbox_native_scan as triage

HELPER = 0x18eb1a0
WORLD_SITES = (0x18a8b28, 0x18fad1c, 0x19021f0, 0x19022d0, 0x1902fa4)
MARKER = 'WB_GHIDRA_JSON:'
MAX_LOG_LINE = 100000


def marked_report(lines):
    found = []
    for line in lines:
        if MARKER not in line or len(line) > MAX_LOG_LINE:
            continue
        try:
            item, _ = json.JSONDecoder().raw_decode(line.split(MARKER, 1)[1].lstrip())
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict) and item.get('kind') == 'ghidra-bounded-probe':
            found.append(item)
    if len(found) != 1:
        raise RuntimeError('Ghidra did not emit exactly one valid bounded report')
    return found[0]


def targets(path, fixture=False):
    with Path(path).open('rb') as f:
        elf = ELFFile(f)
        if elf.elfclass != 64 or not elf.little_endian or elf['e_machine'] != 'EM_AARCH64':
            raise ValueError('Expected little-endian ELF64 AArch64')
        loads = [segment['p_vaddr'] for segment in elf.iter_segments() if segment['p_type'] == 'PT_LOAD']
        if not loads:
            raise ValueError('ELF has no loadable segments')
        sections = [s for s in elf.iter_sections() if s['sh_flags'] & 4 and s['sh_type'] != 'SHT_NOBITS']
        dwarf = elf.get_dwarf_info()
        if not dwarf.has_EH_CFI():
            raise ValueError('No EH-frame unwind information')
        frames = sorted((e['initial_location'], e['initial_location'] + e['address_range'])
                        for e in dwarf.EH_CFI_entries() if isinstance(e, FDE) and e['address_range'])
        starts = [lo for lo, _ in frames]
        if fixture:
            table = elf.get_section_by_name('.symtab')
            if not isinstance(table, SymbolTableSection):
                raise ValueError('Synthetic fixture is missing symbols')
            symbols = {s.name: s['st_value'] for s in table.iter_symbols() if s.name in ('fixture_helper', 'fixture_caller')}
            if set(symbols) != {'fixture_helper', 'fixture_caller'}:
                raise ValueError('Synthetic fixture symbols missing')
            helper = symbols['fixture_helper']
            caller = symbols['fixture_caller']
            cf = flow.frame_for_site(frames, starts, caller)
            if not cf or cf[0] != caller:
                raise ValueError('Synthetic caller has no matching unwind range')
            sec = next((s for s in sections if s['sh_addr'] <= caller and cf[1] <= s['sh_addr'] + s['sh_size']), None)
            if not sec:
                raise ValueError('Synthetic caller is not executable')
            f.seek(sec['sh_offset'] + caller - sec['sh_addr'])
            sites = [pc for pc, word in triage.instructions(f.read(cf[1] - caller), caller)
                     if triage.direct_branch(word, pc) == helper]
            if len(sites) != 1:
                raise ValueError('Synthetic fixture must contain exactly one direct helper call')
        else:
            helper, sites = HELPER, WORLD_SITES
        helper_frame = flow.frame_for_site(frames, starts, helper)
        if not helper_frame or helper_frame[0] != helper or helper_frame[1] - helper > flow.MAX_FUNCTION:
            raise ValueError('Helper unwind range missing or too large')
        selected = []
        for site in sites:
            frame = flow.frame_for_site(frames, starts, site)
            if not frame or frame[1] - frame[0] > flow.MAX_FUNCTION:
                raise ValueError('Target caller unwind range missing or too large')
            sec = next((s for s in sections if s['sh_addr'] <= frame[0] and frame[1] <= s['sh_addr'] + s['sh_size']), None)
            if not sec:
                raise ValueError('Target caller range is not executable')
            f.seek(sec['sh_offset'] + site - sec['sh_addr'])
            raw = f.read(4)
            if len(raw) != 4 or triage.direct_branch(int.from_bytes(raw, 'little'), site) != helper:
                raise ValueError('Target call is not a direct branch to the expected helper')
            selected.append({'entry': frame[0], 'size': frame[1] - frame[0], 'site': site})
        return {'imageBase': min(loads), 'helper': helper, 'helperSize': helper_frame[1] - helper, 'targets': selected}


def run_probe(headless, path, fixture=False):
    plan = targets(path, fixture)
    scripts = Path(__file__).resolve().parents[2] / 'docs/worldbox'
    base = Path(os.environ.get('RUNNER_TEMP', tempfile.gettempdir()))
    with tempfile.TemporaryDirectory(prefix='worldbox-ghidra-', dir=base) as td:
        args = [str(headless), td, 'worldbox', '-import', str(Path(path).resolve()), '-noanalysis',
                '-scriptPath', str(scripts), '-postScript', 'WorldboxProbe.java',
                hex(plan['imageBase']), hex(plan['helper']), str(plan['helperSize'])]
        args += [f"{item['entry']:x}:{item['size']:x}:{item['site']:x}" for item in plan['targets']]
        args += ['-deleteProject', '-max-cpu', '2']
        log_path = Path(td) / 'headless.log'
        with log_path.open('w+', encoding='utf-8') as log:
            result = subprocess.run(args, stdout=log, stderr=subprocess.STDOUT, text=True, timeout=900)
            log.seek(0)
            lines = log.readlines()
            try:
                report = marked_report(lines)
            except RuntimeError as exc:
                # Diagnostic lines concern our Java probe; never print decompiled code.
                diagnostics = [line.strip()[:300] for line in lines
                               if 'WorldboxProbe.java' in line and ('error:' in line.lower() or 'ERROR' in line)]
                detail = '; '.join(diagnostics[:3])
                raise RuntimeError(str(exc) + (': ' + detail if detail else '')) from exc
        if result.returncode:
            raise RuntimeError(f'Ghidra headless exited with status {result.returncode}')
        if len(report.get('sites', [])) != len(plan['targets']):
            raise RuntimeError('Ghidra did not report every planned call site')
        if fixture and (not report.get('helperSignatureApplied') or
                        not all(row.get('decompiled') and row.get('callFound') and row.get('argumentAvailable')
                                for row in report['sites'])):
            raise RuntimeError('Ghidra synthetic fixture failed to recover the expected call and argument')
        if fixture:
            evidence = report['sites'][0].get('stackEvidence', {})
            offsets = {row['relativeOffset'] for row in evidence.get('writes', [])}
            if not evidence.get('stackAddressResolved') or not {0, 8}.issubset(offsets):
                raise RuntimeError('Ghidra fixture failed to recover the expected stack-object writes: ' + json.dumps(evidence, separators=(',', ':')))
        return report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--headless', required=True)
    parser.add_argument('--binary', required=True)
    parser.add_argument('--fixture', action='store_true')
    args = parser.parse_args()
    try:
        print(json.dumps(run_probe(args.headless, args.binary, args.fixture), separators=(',', ':')))
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        print('Ghidra probe failed: ' + str(exc), file=sys.stderr)
        raise SystemExit(1)

if __name__ == '__main__':
    main()

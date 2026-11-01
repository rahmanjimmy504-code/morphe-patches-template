#!/usr/bin/env python3
"""Bounded Ghidra probe for the ARMv7 libil2cpp JNI_OnLoad function."""
import argparse
import json
from pathlib import Path
import subprocess
import tempfile

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

MARKER = 'WB_ARMV7_JNI:'


def jni_symbol(path):
    with Path(path).open('rb') as handle:
        elf = ELFFile(handle)
        if elf.elfclass != 32 or not elf.little_endian or elf['e_machine'] != 'EM_ARM':
            raise ValueError('Expected little-endian ELF32 ARM library')
        dynsym = elf.get_section_by_name('.dynsym')
        if not isinstance(dynsym, SymbolTableSection):
            raise ValueError('No dynamic symbol table')
        rows = [symbol for symbol in dynsym.iter_symbols()
                if symbol.name == 'JNI_OnLoad' and symbol['st_shndx'] != 'SHN_UNDEF'
                and symbol['st_info']['type'] == 'STT_FUNC' and symbol['st_value']]
        if len(rows) != 1:
            raise ValueError('Expected one defined dynamic JNI_OnLoad function')
        size = int(rows[0]['st_size'])
        if size < 4 or size > 512:
            raise ValueError('JNI_OnLoad symbol size outside the 4..512 byte bound')
        return size


def parse_report(lines):
    reports = []
    for line in lines:
        if MARKER not in line or len(line) > 100_000:
            continue
        try:
            obj, _ = json.JSONDecoder().raw_decode(line.split(MARKER, 1)[1].lstrip())
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict) and obj.get('kind') == 'worldbox-armv7-jni':
            reports.append(obj)
    if len(reports) != 1:
        raise RuntimeError('Ghidra did not emit exactly one ARMv7 JNI report')
    return reports[0]


def run_probe(headless, binary, fixture=False):
    size = jni_symbol(binary)
    scripts = Path(__file__).resolve().parents[2] / 'docs/worldbox'
    with tempfile.TemporaryDirectory(prefix='worldbox-armv7-ghidra-') as td:
        args = [str(headless), td, 'worldbox-armv7', '-import', str(Path(binary).resolve()),
                '-noanalysis', '-scriptPath', str(scripts), '-postScript',
                'WorldboxArmv7JniProbe.java', str(size), str(fixture).lower(),
                '-deleteProject', '-max-cpu', '2']
        log_path = Path(td) / 'headless.log'
        with log_path.open('w+', encoding='utf-8') as log:
            result = subprocess.run(args, stdout=log, stderr=subprocess.STDOUT,
                                    text=True, timeout=600)
            log.seek(0)
            lines = log.readlines()
        if result.returncode:
            diagnostics = [line.strip()[:300] for line in lines
                           if 'WorldboxArmv7JniProbe.java' in line and
                           ('error:' in line.lower() or 'ERROR' in line)]
            detail = '; '.join(diagnostics[:3])
            raise RuntimeError('Ghidra ARMv7 headless failed' + (': ' + detail if detail else ''))
        report = parse_report(lines)
        if report.get('size') != size:
            raise RuntimeError('Ghidra report size did not match the bounded ELF symbol')
        if fixture and not report.get('registerNatives'):
            raise RuntimeError('Synthetic fixture failed to recover RegisterNatives call')
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
        if args.fixture:
            print('Synthetic ARMv7 Ghidra fixture failed: ' + str(exc))
        raise SystemExit(1)


if __name__ == '__main__':
    main()

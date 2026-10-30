#!/usr/bin/env python3
"""Bounded static references to a known ARM64 file-mapping function.

Only aggregate counts and ELF-relative virtual locations are emitted; no code,
file paths, process memory or game files are exported. All references are clues,
not proof of executed control flow or metadata use.
"""
import argparse
import json
from pathlib import Path
import struct

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from elftools.elf.elffile import ELFFile
from elftools.dwarf.callframe import FDE
from elftools.elf.relocation import RelocationSection
from elftools.elf.sections import SymbolTableSection

import worldbox_native_scan as triage
import worldbox_native_flow as flow

TARGET = 0x18d3fd0  # Unwind-derived shared file-mapping parent, 0.51.4 ARM64.
MAX_EXEC = 96 * 1024 * 1024
MAX_DATA = 96 * 1024 * 1024
SAMPLES = 12


def direct_tail(word, pc):
    if word & 0xfc000000 != 0x14000000:  # B, not BL
        return None
    imm = word & 0x03ffffff
    if imm & 0x02000000:
        imm -= 0x04000000
    return pc + (imm << 2)


def adrp_value(word, pc):
    if word & 0x9f000000 != 0x90000000:
        return None
    imm = ((word >> 5) & 0x7ffff) << 2 | ((word >> 29) & 3)
    if imm & (1 << 20):
        imm -= 1 << 21
    return (pc & ~0xfff) + (imm << 12), word & 31


def add_value(word):
    if word & 0xff000000 != 0x91000000:  # 64-bit ADD immediate, no flags
        return None
    imm = (word >> 10) & 0xfff
    if word & (1 << 22): imm <<= 12
    return (word >> 5) & 31, imm


def verify_adrp_add(decoder, data, start, base_reg, add_site):
    """Reject intervening register writes; this still isn't a CFG proof."""
    expected = f'x{base_reg}'
    aliases = {expected, f'w{base_reg}'}
    if base_reg == 29: aliases.add('fp')
    if base_reg == 30: aliases.add('lr')
    decoded = list(decoder.disasm(data, start))
    if not decoded or decoded[-1].address != add_site:
        return False
    for ins in decoded[1:-1]:
        if ins.mnemonic in ('b', 'bl', 'br', 'blr', 'ret') or ins.mnemonic.startswith('b.') or ins.mnemonic in ('cbz', 'cbnz', 'tbz', 'tbnz'):
            return False
        try:
            written = {ins.reg_name(r) for r in ins.regs_access()[1]}
        except Exception:
            return False
        if aliases & written:
            return False
    return True


def executable_refs(data, base, target):
    """Linear sweep; candidate ADRP+ADD pairs require no intervening clobber."""
    data = data[:len(data) & ~3]
    decoder = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    decoder.detail = True
    tails, adrp_add = [], []
    tail_count = pair_count = 0
    for index, (word,) in enumerate(struct.iter_unpack('<I', data)):
        off = index * 4
        pc = base + off
        if direct_tail(word, pc) == target:
            tail_count += 1
            if len(tails) < SAMPLES: tails.append(hex(pc))
        page = adrp_value(word, pc)
        if page is None or page[1] == 31 or page[0] != (target & ~0xfff):
            continue
        for nextoff in range(off + 4, min(off + 36, len(data)), 4):
            following = struct.unpack_from('<I', data, nextoff)[0]
            add = add_value(following)
            if add and add[0] == page[1] and page[0] + add[1] == target:
                if verify_adrp_add(decoder, data[off:nextoff + 4], pc, page[1], base + nextoff):
                    pair_count += 1
                    if len(adrp_add) < SAMPLES:
                        adrp_add.append({'adrp': hex(pc), 'add': hex(base + nextoff)})
                break
    return tail_count, tails, pair_count, adrp_add


def is_packed_relocation_type(section_type):
    # Android APS2 and RELR need separate decoding; never silently treat them as ordinary RELA.
    return section_type in (0x60000001, 0x60000002, 19, 0x6fffff00) or (
        isinstance(section_type, str) and
        (('ANDROID' in section_type.upper() and 'REL' in section_type.upper()) or 'RELR' in section_type.upper())
    )


SAFE_IMPORTS = triage.WATCHED | frozenset({
    'malloc', 'calloc', 'realloc', 'free', 'posix_memalign', 'aligned_alloc',
    'strlen', 'strnlen', 'strcpy', 'strncpy', 'strdup', 'strstr', 'strcmp', 'strncmp',
    'wcslen', 'wcstombs', 'mbstowcs', 'iconv', 'iconv_open', 'iconv_close',
    '__strlen_chk', '__memcpy_chk', '__memmove_chk', '__strcpy_chk', '__strncpy_chk',
    '_Znwm', '_Znam', '_ZdlPv', '_ZdaPv', '__cxa_allocate_exception', '__cxa_throw',
})


def safe_import_plt(elf):
    """Match import stubs but emit names only from a predefined system API list."""
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
                name = symbols.get_symbol(index).name
                relocs[rel['r_offset']] = name if name in SAFE_IMPORTS else 'other-import'
    return triage.plt_targets(elf, relocs)[0]


def inspect(path, target=TARGET):
    with Path(path).open('rb') as f:
        elf = ELFFile(f)
        if elf.elfclass != 64 or not elf.little_endian or elf['e_machine'] != 'EM_AARCH64':
            raise ValueError('Expected a little-endian ELF64 AArch64 library')
        exec_total = exec_scanned = data_total = data_scanned = 0
        tail_count = pair_count = pointer_count = reloc_count = 0
        tail_samples, pair_samples, pointer_samples, reloc_samples = [], [], [], []
        unsupported_relocations = []
        target_symbol_count = 0
        for sec in elf.iter_sections():
            if isinstance(sec, SymbolTableSection):
                for sym in sec.iter_symbols():
                    if sym['st_value'] == target and sym['st_shndx'] != 'SHN_UNDEF' and sym['st_info']['type'] == 'STT_FUNC':
                        target_symbol_count += 1
            if isinstance(sec, RelocationSection):
                symbols = elf.get_section(sec['sh_link'])
                if not sec.is_RELA():
                    unsupported_relocations.append(sec.name)
                else:
                    for rel in sec.iter_relocations():
                        kind, addend = rel['r_info_type'], rel['r_addend']
                        value = None
                        if kind == 1027:  # R_AARCH64_RELATIVE
                            value = addend
                        elif kind in (257, 1025) and isinstance(symbols, SymbolTableSection):  # ABS64/GLOB_DAT
                            idx = rel['r_info_sym']
                            if idx < symbols.num_symbols():
                                value = symbols.get_symbol(idx)['st_value'] + addend
                        if value == target:
                            reloc_count += 1
                            if len(reloc_samples) < SAMPLES:
                                reloc_samples.append({'section': sec.name, 'slot': hex(rel['r_offset']), 'type': kind})
            elif is_packed_relocation_type(sec['sh_type']):
                unsupported_relocations.append(sec.name)
            if sec['sh_type'] == 'SHT_NOBITS':
                continue
            size = sec['sh_size']
            if sec['sh_flags'] & 4:
                exec_total += size
                budget = max(0, MAX_EXEC - exec_scanned) & ~3
                if not budget: continue
                data = sec.data()[:budget]
                count, tails, pairs, samples = executable_refs(data, sec['sh_addr'], target)
                tail_count += count; pair_count += pairs
                tail_samples.extend(tails[:max(0, SAMPLES - len(tail_samples))])
                pair_samples.extend(samples[:max(0, SAMPLES - len(pair_samples))])
                exec_scanned += len(data)
            elif sec['sh_flags'] & 2:
                data_total += size
                budget = max(0, MAX_DATA - data_scanned)
                if not budget: continue
                data = sec.data()[:budget]
                first = (-sec['sh_addr']) % 8
                aligned = data[first:first + ((len(data) - first) // 8) * 8] if len(data) >= first else b''
                for index, (value,) in enumerate(struct.iter_unpack('<Q', aligned)):
                    if value == target:
                        pointer_count += 1
                        if len(pointer_samples) < SAMPLES:
                            pointer_samples.append({'section': sec.name, 'location': hex(sec['sh_addr'] + first + index * 8)})
                data_scanned += len(data)
        tail_traces = []
        tail_callers = {}
        unwind_status = 'not-needed'
        if tail_samples:
            unwind_status = 'missing'
            eh = elf.get_section_by_name('.eh_frame')
            frames = []
            if eh and eh['sh_size'] > flow.MAX_EH_SIZE:
                unwind_status = 'too-large'
            elif eh:
                try:
                    dwarf = elf.get_dwarf_info()
                    if dwarf.has_EH_CFI():
                        frames = sorted((entry['initial_location'], entry['initial_location'] + entry['address_range'])
                                        for entry in dwarf.EH_CFI_entries() if isinstance(entry, FDE) and entry['address_range'])
                        unwind_status = 'parsed'
                    else:
                        unwind_status = 'no-cfi'
                except Exception as exc:
                    unwind_status = 'parse-error-' + type(exc).__name__
            starts = [lo for lo, _ in frames]
            executable = [s for s in elf.iter_sections() if s['sh_flags'] & 4 and s['sh_type'] != 'SHT_NOBITS']
            constants = [s for s in elf.iter_sections() if s['sh_flags'] & 2 and not s['sh_flags'] & (1 | 4) and s['sh_type'] != 'SHT_NOBITS']
            def classify(value):
                sec = next((s for s in constants if s['sh_addr'] <= value < s['sh_addr'] + s['sh_size']), None)
                if not sec:
                    return 'small-constant' if 0 <= value <= 4096 else 'other-constant'
                offset = value - sec['sh_addr']
                f.seek(sec['sh_offset'] + offset)
                raw = f.read(min(128, sec['sh_size'] - offset))
                category = triage.string_category(raw)
                if category: return category
                text = raw.split(b'\0', 1)[0]
                return 'other-static-string' if text and all(32 <= c <= 126 for c in text) else 'static-data-address'
            targets = set()
            for site_hex in tail_samples:
                site = int(site_hex, 16)
                frame = flow.frame_for_site(frames, starts, site)
                if not frame:
                    tail_traces.append({'site': site_hex, 'status': 'no-unwind-range'})
                    continue
                lo, hi = frame
                sec = next((part for part in executable if part['sh_addr'] <= lo and hi <= part['sh_addr'] + part['sh_size']), None)
                if not sec or hi - lo > flow.MAX_FUNCTION or lo % 4:
                    tail_traces.append({'site': site_hex, 'status': 'unusable-or-too-large-range'})
                    continue
                targets.add(lo)
                f.seek(sec['sh_offset'] + lo - sec['sh_addr'])
                result = flow.analyze_window(f.read(hi - lo), lo, {target: 'tail-mapparent'}, {site: 'tail-mapparent'}, classify)
                tail_traces.append({'site': site_hex, 'function': hex(lo), 'size': hi - lo,
                                    'workLimitReached': result['workLimitReached'], 'call': result['calls'][0]})
            tail_callers = {hex(addr): {'directCalls': 0, 'directTailBranches': 0, 'sampleSites': []} for addr in targets}
            remaining = MAX_EXEC
            for sec in executable if targets else ():
                if remaining < 4: break
                data = sec.data()[:remaining & ~3]
                remaining -= len(data)
                for pc, word in triage.instructions(data, sec['sh_addr']):
                    destination = triage.direct_branch(word, pc)
                    call_type = 'directCalls'
                    if destination not in targets:
                        destination = direct_tail(word, pc)
                        call_type = 'directTailBranches'
                    if destination in targets:
                        entry = tail_callers[hex(destination)]
                        entry[call_type] += 1
                        if len(entry['sampleSites']) < SAMPLES:
                            entry['sampleSites'].append({'site': hex(pc), 'kind': call_type})
            # Model up to four enclosing callers per tail function.  This is
            # bounded intraprocedural dataflow, not a proven call chain.
            for target_hex, info in tail_callers.items():
                destination = int(target_hex, 16)
                info['argumentExamples'] = []
                for sample in info['sampleSites'][:4]:
                    site = int(sample['site'], 16)
                    frame = flow.frame_for_site(frames, starts, site)
                    if not frame:
                        info['argumentExamples'].append({'site': sample['site'], 'status': 'no-unwind-range'})
                        continue
                    lo, hi = frame
                    sec = next((part for part in executable if part['sh_addr'] <= lo and hi <= part['sh_addr'] + part['sh_size']), None)
                    if not sec or hi - lo > flow.MAX_FUNCTION or lo % 4:
                        info['argumentExamples'].append({'site': sample['site'], 'status': 'unusable-or-too-large-range'})
                        continue
                    f.seek(sec['sh_offset'] + lo - sec['sh_addr'])
                    result = flow.analyze_window(f.read(hi - lo), lo, {destination: 'tail-parent-caller'},
                                                 {site: 'tail-parent-caller'}, classify)
                    info['argumentExamples'].append({'site': sample['site'], 'function': hex(lo),
                                                     'workLimitReached': result['workLimitReached'],
                                                     'call': result['calls'][0]})
            # Follow only unique direct call origins associated with x0 at the
            # sampled mapping-wrapper calls. Never assume a matching name or path.
            origin_targets = set()
            for info in tail_callers.values():
                for example in info.get('argumentExamples', []):
                    call = example.get('call', {})
                    x0_sites = {item.rsplit('@', 1)[1] for item in call.get('arguments', {}).get('x0', []) if '@' in item}
                    for origin in call.get('callOrigins', []):
                        if origin['site'] in x0_sites and origin.get('kind') == 'direct' and origin.get('target'):
                            origin_targets.add(int(origin['target'], 16))
            source_callees = {'uniqueTargets': len(origin_targets), 'sampleLimit': 4, 'examples': []}
            imports = safe_import_plt(elf)
            for destination in sorted(origin_targets)[:4]:
                frame = flow.frame_for_site(frames, starts, destination)
                if not frame:
                    source_callees['examples'].append({'target': hex(destination), 'status': 'no-unwind-range'})
                    continue
                lo, hi = frame
                sec = next((part for part in executable if part['sh_addr'] <= lo and hi <= part['sh_addr'] + part['sh_size']), None)
                if not sec or sec.name.startswith('.plt') or hi - destination > flow.MAX_FUNCTION or destination % 4:
                    source_callees['examples'].append({'target': hex(destination), 'status': 'unusable-or-too-large-range'})
                    continue
                f.seek(sec['sh_offset'] + destination - sec['sh_addr'])
                result = flow.analyze_window(f.read(hi - destination), destination, imports, {}, classify, capture_returns=True)
                source_callees['examples'].append({'target': hex(destination), 'unwindStart': hex(lo),
                                                   'workLimitReached': result['workLimitReached'],
                                                   'returns': result['returns'], 'returnsTruncated': result['returnsTruncated'],
                                                   'tailTransfers': result['tailTransfers'],
                                                   'tailTransfersTruncated': result['tailTransfersTruncated']})
        else:
            source_callees = {'uniqueTargets': 0, 'sampleLimit': 4, 'examples': []}
        return {
            'kind': 'arm64-static-xrefs', 'target': hex(target),
            'symbolMatches': target_symbol_count,
            'directTailBranches': {'count': tail_count, 'sampleSites': tail_samples,
                                   'unwindStatus': unwind_status, 'traces': tail_traces,
                                   'enclosingFunctionCallers': tail_callers, 'argumentSourceCallees': source_callees},
            'pcRelativeAddressPairs': {'count': pair_count, 'samples': pair_samples},
            'matchingRelocations': {'count': reloc_count, 'samples': reloc_samples,
                                    'unsupportedRelocationSections': sorted(set(unsupported_relocations))},
            'alignedPointerValues': {'count': pointer_count, 'samples': pointer_samples},
            'executableBytes': exec_total, 'executableScanned': exec_scanned, 'execTruncated': exec_scanned < exec_total,
            'allocatedDataBytes': data_total, 'allocatedDataScanned': data_scanned, 'dataTruncated': data_scanned < data_total,
            'limitations': 'Linear decoding may identify data or unreachable code; address pairs and pointer values are not proof of execution. Indirect targets, packed relocations, runtime-generated references and noncanonical instruction sequences may be missed.',
        }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('elf')
    args = parser.parse_args()
    print(json.dumps(inspect(args.elf), separators=(',', ':')))

if __name__ == '__main__': main()

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
from elftools.elf.relocation import RelocationSection
from elftools.elf.sections import SymbolTableSection

import worldbox_native_scan as triage

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
        return {
            'kind': 'arm64-static-xrefs', 'target': hex(target),
            'symbolMatches': target_symbol_count,
            'directTailBranches': {'count': tail_count, 'sampleSites': tail_samples},
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

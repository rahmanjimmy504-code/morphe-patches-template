#!/usr/bin/env python3
"""Bounded ARM64 literal-pointer and indirect-call models for WorldBox probes.

Only predefined needle labels, aggregate counts, ELF-relative addresses,
section names and decoded instruction mnemonics/operands leave this module. It
never emits unknown strings or raw game bytes. Static approximations are not
proof of executed control flow, dynamic symbol resolution or metadata access.
"""
from __future__ import annotations

import hashlib
import struct
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_OP_REG
from elftools.elf.elffile import ELFFile

import worldbox_native_flow as flow
import worldbox_native_xrefs as xrefs

MAX_SECTION = 96 * 1024 * 1024
MAX_SAMPLES = 12
MAX_REFERENCE_ADDRESSES = 128
MAX_POINTER_LOCATIONS = 256
MAX_SITES = 128
MAX_FDE_REPORTS = 6
MAX_FDE_SIZE = 32 * 1024
ADRP_WINDOW = 36
FOLLOW_WINDOW = 64


def hash_text(value):
    return hashlib.sha256(str(value).encode('utf-8', 'replace')).hexdigest()


def encoded_needles(needles):
    result = {}
    for label, text in needles.items():
        result[label] = {'ascii': text.encode('ascii'),
                         'utf16le': text.encode('utf-16le')}
    return result


def _find_all(data, needle, base, label, encoding, section, max_examples):
    count = 0
    samples = []
    start = 0
    while True:
        position = data.find(needle, start)
        if position < 0:
            break
        count += 1
        if len(samples) < max_examples:
            samples.append({'address': hex(base + position), 'section': section,
                            'needle': label, 'encoding': encoding})
        start = position + 1
    return count, samples


def literal_occurrences(path, needles, max_section=MAX_SECTION,
                        max_examples=MAX_SAMPLES,
                        max_reference_addresses=MAX_REFERENCE_ADDRESSES):
    """Find exact predefined ASCII/UTF-16LE needles in allocated ELF sections."""
    encoded = encoded_needles(needles)
    results = {label: {name: {'count': 0, 'samples': []}
                       for name in ('ascii', 'utf16le')} for label in needles}
    addresses = []
    seen_addresses = set()
    addresses_truncated = False
    total = scanned = 0
    with Path(path).open('rb') as handle:
        elf = ELFFile(handle)
        if elf.elfclass != 64 or not elf.little_endian or elf['e_machine'] != 'EM_AARCH64':
            raise ValueError('Expected a little-endian ELF64 AArch64 library')
        sections = [sec for sec in elf.iter_sections()
                    if sec['sh_flags'] & 2 and sec['sh_type'] != 'SHT_NOBITS']
        for sec in sections:
            total += sec['sh_size']
            budget = max(0, max_section - scanned)
            if not budget:
                continue
            data = sec.data()[:budget]
            scanned += len(data)
            for label, encodings in encoded.items():
                for encoding, needle in encodings.items():
                    row = results[label][encoding]
                    count, samples = _find_all(data, needle, sec['sh_addr'],
                                               label, encoding, sec.name,
                                               max_examples)
                    row['count'] += count
                    row['samples'].extend(samples[:max(0, max_examples - len(row['samples']))])
                    for sample in samples:
                        address = int(sample['address'], 16)
                        if address in seen_addresses:
                            continue
                        if len(addresses) < max_reference_addresses:
                            seen_addresses.add(address)
                            addresses.append(address)
                        else:
                            addresses_truncated = True
    for label, encodings in results.items():
        for encoding, row in encodings.items():
            row['samplesTruncated'] = row['count'] > len(row['samples'])
    return {'needles': needles, 'results': results,
            'referenceAddresses': [hex(value) for value in addresses],
            'referenceAddressesTruncated': addresses_truncated,
            'allocatedBytes': total, 'allocatedScanned': scanned,
            'allocatedTruncated': scanned < total}


def pointer_locations(path, targets, max_section=MAX_SECTION,
                      max_locations=MAX_POINTER_LOCATIONS,
                      max_examples=MAX_SAMPLES):
    """Locate aligned static 64-bit words equal to known function addresses."""
    target_set = set(targets)
    counts = {hex(target): 0 for target in targets}
    samples = {hex(target): [] for target in targets}
    by_location = {}
    total = scanned = 0
    truncated = False
    with Path(path).open('rb') as handle:
        elf = ELFFile(handle)
        if elf.elfclass != 64 or not elf.little_endian or elf['e_machine'] != 'EM_AARCH64':
            raise ValueError('Expected a little-endian ELF64 AArch64 library')
        sections = [sec for sec in elf.iter_sections()
                    if sec['sh_flags'] & 2 and sec['sh_type'] != 'SHT_NOBITS']
        for sec in sections:
            total += sec['sh_size']
            budget = max(0, max_section - scanned) & ~7
            if not budget:
                continue
            data = sec.data()[:budget]
            scanned += len(data)
            first = (-sec['sh_addr']) % 8
            aligned = data[first:first + ((len(data) - first) // 8) * 8]
            for offset, (value,) in enumerate(struct.iter_unpack('<Q', aligned)):
                if value not in target_set:
                    continue
                location = sec['sh_addr'] + first + offset * 8
                key = hex(value)
                counts[key] += 1
                if len(samples[key]) < max_examples:
                    samples[key].append({'section': sec.name,
                                         'location': hex(location),
                                         'value': hex(value)})
                if location not in by_location and len(by_location) < max_locations:
                    by_location[location] = value
                elif location not in by_location:
                    truncated = True
    return {'targets': [hex(value) for value in targets],
            'counts': counts, 'samples': samples,
            'byLocation': {hex(location): hex(value)
                           for location, value in by_location.items()},
            'locationCount': len(by_location), 'locationsTruncated': truncated,
            'allocatedBytes': total, 'allocatedScanned': scanned,
            'allocatedTruncated': scanned < total}


def _fde_for_site(frames, starts, site):
    frame = flow.frame_for_site(frames, starts, site)
    if not frame:
        return None, None
    return frame[0], frame[1] - frame[0]


def _follow_indirect_register(decoder, data, offset, address, register,
                              target, follow_window=FOLLOW_WINDOW):
    registers = {register}
    follow = data[offset:offset + follow_window]
    for instruction in decoder.disasm(follow, address):
        operands = instruction.operands
        if instruction.mnemonic in ('blr', 'br') and operands and operands[0].type == ARM64_OP_REG:
            used = instruction.reg_name(operands[0].reg)
            if used in registers:
                return {'site': hex(instruction.address), 'kind': instruction.mnemonic,
                        'register': used, 'target': hex(target)}
        if (instruction.mnemonic in ('ret', 'b', 'bl') or
                instruction.mnemonic.startswith('b.') or
                instruction.mnemonic in ('cbz', 'cbnz', 'tbz', 'tbnz')):
            break
        if (instruction.mnemonic == 'mov' and len(operands) >= 2 and
                operands[0].type == ARM64_OP_REG and operands[1].type == ARM64_OP_REG):
            source = instruction.reg_name(operands[1].reg)
            written = instruction.reg_name(operands[0].reg)
            if source in registers:
                registers.add(written)
            else:
                registers.discard(written)
            continue
        try:
            written = {instruction.reg_name(reg)
                       for reg in instruction.regs_access()[1]}
        except Exception:
            written = set()
        registers -= written
        if not registers:
            break
    return None


def adrp_add_reference_sites(path, addresses, frames, starts,
                             max_sites=MAX_SITES, max_section=MAX_SECTION,
                             follow_window=ADRP_WINDOW):
    """Find simple ADRP+ADD materializations of exact static addresses."""
    targets = sorted({int(value, 0) if isinstance(value, str) else value
                      for value in addresses})
    target_set = set(targets)
    pages = {}
    for target in targets:
        pages.setdefault(target & ~0xfff, []).append(target)
    sites = []
    materialization_count = 0
    truncated = False
    function_addresses = []
    seen_functions = set()
    total = scanned = 0
    decoder = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    decoder.detail = True
    with Path(path).open('rb') as handle:
        elf = ELFFile(handle)
        if elf.elfclass != 64 or not elf.little_endian or elf['e_machine'] != 'EM_AARCH64':
            raise ValueError('Expected a little-endian ELF64 AArch64 library')
        sections = [sec for sec in elf.iter_sections()
                    if sec['sh_flags'] & 4 and sec['sh_type'] != 'SHT_NOBITS']
        for sec in sections:
            total += sec['sh_size']
            budget = max(0, max_section - scanned) & ~3
            if not budget:
                continue
            data = sec.data()[:budget]
            scanned += len(data)
            words = list(struct.iter_unpack('<I', data[:len(data) & ~3]))
            for index, (word,) in enumerate(words):
                off = index * 4
                pc = sec['sh_addr'] + off
                page = xrefs.adrp_value(word, pc)
                if page is None or page[1] == 31 or page[0] not in pages:
                    continue
                for nextoff in range(off + 4, min(off + follow_window, len(data)), 4):
                    add = xrefs.add_value(int.from_bytes(data[nextoff:nextoff + 4], 'little'))
                    if not add or add[0] != page[1]:
                        continue
                    target = page[0] + add[1]
                    if target not in target_set:
                        continue
                    add_pc = sec['sh_addr'] + nextoff
                    if not xrefs.verify_adrp_add(decoder, data[off:nextoff + 4],
                                                 pc, page[1], add_pc):
                        continue
                    materialization_count += 1
                    function, size = _fde_for_site(frames, starts, pc)
                    if function is not None and function not in seen_functions:
                        seen_functions.add(function)
                        function_addresses.append(function)
                    if len(sites) < max_sites:
                        sites.append({'adrp': hex(pc), 'add': hex(add_pc),
                                      'target': hex(target),
                                      'register': f'x{page[1]}',
                                      'section': sec.name,
                                      'function': hex(function) if function is not None else None,
                                      'size': size})
                    else:
                        truncated = True
                    break
    return {'targets': [hex(value) for value in targets], 'count': materialization_count,
            'sites': sites, 'sitesTruncated': truncated,
            'functionAddresses': [hex(value) for value in function_addresses],
            'executableBytes': total, 'executableScanned': scanned,
            'execTruncated': scanned < total}


def indirect_call_sites(path, targets, frames, starts,
                        max_sites=MAX_SITES, max_section=MAX_SECTION,
                        follow_window=FOLLOW_WINDOW):
    """Model ADRP+ADD or LDR-literal function addresses followed by BLR/BR."""
    target_set = {int(value, 0) if isinstance(value, str) else value
                  for value in targets}
    pointers = pointer_locations(path, target_set, max_section=max_section)
    by_location = {int(location, 16): int(value, 16)
                   for location, value in pointers['byLocation'].items()}
    pages = {}
    for target in target_set:
        pages.setdefault(target & ~0xfff, []).append(target)
    counts = {hex(target): {'materializationCount': 0, 'indirectCallCount': 0}
              for target in sorted(target_set)}
    materializations = []
    calls = []
    function_addresses = []
    seen_functions = set()
    truncated = False
    total = scanned = 0
    decoder = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    decoder.detail = True
    with Path(path).open('rb') as handle:
        elf = ELFFile(handle)
        if elf.elfclass != 64 or not elf.little_endian or elf['e_machine'] != 'EM_AARCH64':
            raise ValueError('Expected a little-endian ELF64 AArch64 library')
        sections = [sec for sec in elf.iter_sections()
                    if sec['sh_flags'] & 4 and sec['sh_type'] != 'SHT_NOBITS']
        for sec in sections:
            total += sec['sh_size']
            budget = max(0, max_section - scanned) & ~3
            if not budget:
                continue
            data = sec.data()[:budget]
            scanned += len(data)
            words = list(struct.iter_unpack('<I', data[:len(data) & ~3]))
            for index, (word,) in enumerate(words):
                off = index * 4
                pc = sec['sh_addr'] + off
                candidates = []
                page = xrefs.adrp_value(word, pc)
                if page and page[1] != 31 and page[0] in pages:
                    for nextoff in range(off + 4, min(off + ADRP_WINDOW, len(data)), 4):
                        add = xrefs.add_value(int.from_bytes(data[nextoff:nextoff + 4], 'little'))
                        if not add or add[0] != page[1]:
                            continue
                        target = page[0] + add[1]
                        if target not in target_set:
                            continue
                        add_pc = sec['sh_addr'] + nextoff
                        if not xrefs.verify_adrp_add(decoder, data[off:nextoff + 4],
                                                     pc, page[1], add_pc):
                            continue
                        candidates.append((add_pc, nextoff + 4, f'x{page[1]}',
                                           target, 'adrp-add'))
                        break
                if word & 0xff000000 == 0x58000000:  # 64-bit LDR literal
                    displacement = ((word >> 5) & 0x7ffff)
                    if displacement & 0x40000:
                        displacement -= 0x80000
                    literal = pc + (displacement << 2)
                    target = by_location.get(literal)
                    if target in target_set:
                        candidates.append((pc, off + 4, f'x{word & 31}',
                                           target, 'ldr-literal'))
                for site, follow_offset, register, target, kind in candidates:
                    key = hex(target)
                    counts[key]['materializationCount'] += 1
                    function, size = _fde_for_site(frames, starts, pc)
                    if function is not None and function not in seen_functions:
                        seen_functions.add(function)
                        function_addresses.append(function)
                    if len(materializations) < max_sites:
                        materializations.append({'site': hex(site), 'kind': kind,
                                                 'target': key, 'register': register,
                                                 'section': sec.name,
                                                 'function': hex(function) if function is not None else None,
                                                 'size': size})
                    else:
                        truncated = True
                    call = _follow_indirect_register(decoder, data, follow_offset,
                                                     site + 4, register, target,
                                                     follow_window)
                    if call:
                        counts[key]['indirectCallCount'] += 1
                        if len(calls) < max_sites:
                            call.update({'materialization': kind,
                                         'materializationSite': hex(site),
                                         'section': sec.name})
                            calls.append(call)
                        else:
                            truncated = True
    return {'targets': [hex(value) for value in sorted(target_set)],
            'counts': counts, 'materializationSamples': materializations,
            'indirectCallSamples': calls, 'samplesTruncated': truncated,
            'pointerLocations': {
                'locationCount': pointers['locationCount'],
                'locationsTruncated': pointers['locationsTruncated'],
                'counts': pointers['counts'], 'samples': pointers['samples'],
                'allocatedScanned': pointers['allocatedScanned'],
                'allocatedTruncated': pointers['allocatedTruncated']},
            'functionAddresses': [hex(value) for value in function_addresses],
            'executableBytes': total, 'executableScanned': scanned,
            'execTruncated': scanned < total}


def _branch_target_from_instruction(instruction):
    if instruction.get('mnemonic') not in ('bl', 'b'):
        return None
    text = instruction.get('operands', '').strip()
    if text.startswith('#'):
        text = text[1:]
    try:
        return int(text, 0)
    except (TypeError, ValueError):
        return None


def function_direct_calls(path, entries, watched,
                          max_reports=MAX_FDE_REPORTS):
    """Count direct BL/B calls to predefined PLT stubs inside bounded FDEs."""
    watched = {int(address, 0) if isinstance(address, str) else address: label
               for address, label in watched.items()}
    unique = sorted({int(entry, 0) if isinstance(entry, str) else entry
                     for entry in entries})
    rows = []
    for entry in unique[:max_reports]:
        try:
            fde = flow.disassemble_fde(path, entry, max_size=MAX_FDE_SIZE)
        except ValueError as exc:
            rows.append({'entry': hex(entry), 'status': 'unavailable',
                         'reason': str(exc), 'callCounts': {}})
            continue
        call_counts = {label: 0 for label in watched.values()}
        samples = []
        for instruction in fde.get('instructions', []):
            target = _branch_target_from_instruction(instruction)
            if target not in watched:
                continue
            label = watched[target]
            call_counts[label] += 1
            if len(samples) < MAX_SAMPLES:
                samples.append({'site': instruction['address'], 'label': label,
                                'target': hex(target),
                                'mnemonic': instruction['mnemonic']})
        rows.append({'entry': fde['entry'], 'status': 'decoded',
                     'size': fde['size'],
                     'decodedInstructions': fde['decodedInstructions'],
                     'fullyDecoded': fde['fullyDecoded'],
                     'callCounts': call_counts, 'samples': samples,
                     'samplesTruncated': sum(call_counts.values()) > len(samples)})
    return {'watched': {hex(address): label for address, label in watched.items()},
            'rows': rows, 'reportsTruncated': len(unique) > max_reports}

#!/usr/bin/env python3
"""Bounded ARM64 ELF initialization/import triage; emits JSON, never code bytes.

BL results are a linear sweep heuristic, not a recovered call graph. The input
is never executed. Virtual addresses are relative to this ELF's load base.
"""
import argparse
import collections
import json
import struct
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_OP_IMM, ARM64_OP_MEM, ARM64_OP_REG
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from elftools.elf.sections import SymbolTableSection

WATCHED = frozenset({
    'open', 'open64', '__open_2', 'openat', '__openat_2', 'fopen', 'fopen64',
    'read', 'pread', 'pread64', 'close', 'lseek', 'lseek64', 'fstat', 'fstat64', 'stat',
    'AAssetManager_open', 'AAsset_read', 'mmap', 'mmap64', 'munmap', 'mprotect',
    'dlopen', 'android_dlopen_ext', 'dlsym', 'memcpy', 'memmove',
    'AES_decrypt', 'AES_cbc_encrypt', 'EVP_DecryptInit', 'EVP_DecryptInit_ex',
})
EXPORTED = ('JNI_OnLoad', 'il2cpp_init', 'il2cpp_domain_get', 'il2cpp_class_from_name', 'il2cpp_thread_attach')
MAX_EXEC = 96 * 1024 * 1024
INIT_LIMIT = 64
WINDOW_BYTES = 512
TRACE_NODES = 256
TRACE_DEPTH = 2
SAMPLE_LIMIT = 4
NEARBY_APIS = WATCHED - {'memcpy', 'memmove'}


def direct_branch(word, pc):
    """Decode an AArch64 BL immediate, including sign extension, or None."""
    if word & 0xfc000000 != 0x94000000:
        return None
    imm = word & 0x03ffffff
    if imm & 0x02000000:
        imm -= 0x04000000
    return pc + (imm << 2)


def instructions(data, base):
    usable = len(data) & ~3
    for index, (word,) in enumerate(struct.iter_unpack('<I', data[:usable])):
        yield base + 4 * index, word


def nearby_calls(data, base, plt):
    """Direct calls within a window, without claiming function or CFG boundaries."""
    result = []
    for pc, word in instructions(data, base):
        name = plt.get(direct_branch(word, pc))
        if name in NEARBY_APIS:
            result.append((pc, name))
    return result


def string_category(data):
    """Return only a safe, predefined category, never literal strings."""
    s = data.split(b'\0', 1)[0].lower()
    if s.startswith(b'/proc/'):
        return 'proc-path'
    if s.startswith(b'global-metadata.dat') or s.startswith(b'metadata.dat'):
        return 'metadata-name'
    if s.startswith(b'assets/bin/data/'):
        return 'unity-assets-path'
    return None


def nearby_string_categories(elf, f, data, base):
    # ADRP+ADD references are common but not exhaustive; limit the lifetime of
    # an ADRP value to reduce stale-register false positives. Only categorize
    # constants in allocated, non-writable, non-executable ELF sections.
    decoder = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    decoder.detail = True
    bases, found = {}, set()
    sections = [s for s in elf.iter_sections() if s['sh_type'] != 'SHT_NOBITS'
                and s['sh_flags'] & 2 and not s['sh_flags'] & (1 | 4)]
    for ins in decoder.disasm(data, base):
        ops = ins.operands
        if ins.mnemonic == 'adrp' and len(ops) >= 2 and ops[0].type == ARM64_OP_REG and ops[1].type == ARM64_OP_IMM:
            bases[ops[0].reg] = (ins.address, ops[1].imm)
        elif ins.mnemonic == 'add' and len(ops) >= 3 and ops[1].type == ARM64_OP_REG and ops[2].type == ARM64_OP_IMM:
            ref = bases.get(ops[1].reg)
            if not ref or ins.address - ref[0] > 32:
                continue
            target = ref[1] + (ops[2].imm << ops[2].shift.value)
            sec = next((x for x in sections if x['sh_addr'] <= target < x['sh_addr'] + x['sh_size']), None)
            if not sec:
                continue
            offset = target - sec['sh_addr']
            f.seek(sec['sh_offset'] + offset)
            category = string_category(f.read(min(128, sec['sh_size'] - offset)))
            if category:
                found.add(category)
    return sorted(found)


def plt_targets(elf, relocs):
    """Match AArch64 adrp/ldr/.../br PLT stubs to their relocated GOT slot.

    Unrecognized stub formats remain unresolved rather than being guessed.
    """
    decoder = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    decoder.detail = True
    targets = {}
    stub_count = 0
    for sec in elf.iter_sections():
        if not sec.name.startswith('.plt') or not (sec['sh_flags'] & 4):
            continue
        active = None
        previous = None
        for ins in decoder.disasm(sec.data(), sec['sh_addr']):
            ops = ins.operands
            if ins.mnemonic == 'adrp' and len(ops) >= 2 and ops[0].type == ARM64_OP_REG and ops[1].type == ARM64_OP_IMM:
                start = ins.address
                if previous and previous.mnemonic == 'bti' and previous.address + 4 == ins.address:
                    start = previous.address
                active = {'start': start, 'adrp': ins.address, 'base': ops[0].reg, 'page': ops[1].imm, 'target': None, 'dest': None}
            elif active and ins.address - active['adrp'] <= 20 and ins.mnemonic == 'ldr' and len(ops) >= 2 and ops[0].type == ARM64_OP_REG and ops[1].type == ARM64_OP_MEM and ops[1].mem.base == active['base']:
                got = active['page'] + ops[1].mem.disp
                if got in relocs:
                    active['target'], active['dest'] = relocs[got], ops[0].reg
            elif active and ins.address - active['adrp'] <= 20 and ins.mnemonic == 'br' and ops and ops[0].type == ARM64_OP_REG:
                if active['target'] and ops[0].reg == active['dest']:
                    targets[active['start']] = active['target']
                    # Some callers may branch directly to the ADRP after a BTI.
                    targets[active['adrp']] = active['target']
                    stub_count += 1
                active = None
            elif active and ins.address - active['adrp'] > 20:
                active = None
            previous = ins
    return targets, stub_count


def initializers(elf):
    found = set()
    array = elf.get_section_by_name('.init_array')
    if array:
        start, end = array['sh_addr'], array['sh_addr'] + array['sh_size']
        entries = {start + i: value for i, (value,) in zip(range(0, array['sh_size'] - 7, 8), struct.iter_unpack('<Q', array.data()[:array['sh_size'] & ~7]))}
        for sec in elf.iter_sections():
            if not isinstance(sec, RelocationSection) or not sec.is_RELA():
                continue
            symtab = elf.get_section(sec['sh_link'])
            for rel in sec.iter_relocations():
                slot = rel['r_offset']
                if not (start <= slot < end and slot in entries):
                    continue
                typ, addend = rel['r_info_type'], rel['r_addend']
                if typ == 1027:  # R_AARCH64_RELATIVE
                    entries[slot] = addend
                elif typ == 257 and isinstance(symtab, SymbolTableSection):  # R_AARCH64_ABS64
                    entries[slot] = symtab.get_symbol(rel['r_info_sym'])['st_value'] + addend
        found.update(x for x in entries.values() if x not in (0, 0xffffffffffffffff))
    dynamic = elf.get_section_by_name('.dynamic')
    if dynamic and hasattr(dynamic, 'iter_tags'):
        for tag in dynamic.iter_tags():
            if tag.entry.d_tag == 'DT_INIT' and tag.entry.d_ptr:
                found.add(tag.entry.d_ptr)
    return sorted(found)


def inspect(path):
    with Path(path).open('rb') as f:
        elf = ELFFile(f)
        if elf.elfclass != 64 or not elf.little_endian or elf['e_machine'] != 'EM_AARCH64':
            raise ValueError('Expected a little-endian ELF64 AArch64 library')
        dynsym = elf.get_section_by_name('.dynsym')
        if not isinstance(dynsym, SymbolTableSection):
            raise ValueError('ELF has no dynamic symbol table')
        imports, exports = set(), set()
        for sym in dynsym.iter_symbols():
            if sym['st_shndx'] == 'SHN_UNDEF':
                if sym.name in WATCHED:
                    imports.add(sym.name)
            elif sym.name in EXPORTED:
                exports.add(sym.name)
        relocs = {}
        for sec in elf.iter_sections():
            if not isinstance(sec, RelocationSection) or '.plt' not in sec.name:
                continue
            syms = elf.get_section(sec['sh_link'])
            if not isinstance(syms, SymbolTableSection):
                continue
            for rel in sec.iter_relocations():
                idx = rel['r_info_sym']
                if idx < syms.num_symbols():
                    name = syms.get_symbol(idx).name
                    if name in WATCHED:
                        relocs[rel['r_offset']] = name
        plt, matched_stubs = plt_targets(elf, relocs)
        executable = [sec for sec in elf.iter_sections() if sec['sh_flags'] & 4 and sec['sh_type'] != 'SHT_NOBITS']
        calls = {name: {'count': 0, 'sampleSites': []} for name in sorted(imports)}
        nearby_sites = []
        scanned, total = 0, sum(sec['sh_size'] for sec in executable)
        for sec in executable:
            remaining = MAX_EXEC - scanned
            if remaining < 4:
                break
            data = sec.data()[:remaining & ~3]
            for pc, word in instructions(data, sec['sh_addr']):
                name = plt.get(direct_branch(word, pc))
                if name in calls:
                    calls[name]['count'] += 1
                    if name in NEARBY_APIS and len(nearby_sites) < 512:
                        nearby_sites.append((pc, name))
                    if len(calls[name]['sampleSites']) < SAMPLE_LIMIT:
                        calls[name]['sampleSites'].append(hex(pc))
            scanned += len(data)
        funcs = initializers(elf)
        samples = []
        analyzable = 0
        for addr in funcs[:INIT_LIMIT]:
            sec = next((s for s in executable if s['sh_addr'] <= addr < s['sh_addr'] + s['sh_size']), None)
            if not sec or addr % 4:
                continue
            analyzable += 1
            offset = addr - sec['sh_addr']
            # This is only a short linear window; it is not a function boundary.
            f.seek(sec['sh_offset'] + offset)
            data = f.read(min(WINDOW_BYTES, sec['sh_size'] - offset))
            direct = 0
            watched = []
            for pc, word in instructions(data, addr):
                if word & 0xfffffc1f == 0xd65f0000:  # ret
                    break
                target = direct_branch(word, pc)
                if target is None:
                    continue
                direct += 1
                name = plt.get(target)
                if name and len(watched) < SAMPLE_LIMIT:
                    watched.append({'api': name, 'site': hex(pc)})
            if watched and len(samples) < SAMPLE_LIMIT:
                samples.append({'initializer': hex(addr), 'directCallsInWindow': direct, 'watchedCalls': watched})
        # A bounded, heuristic traversal of direct call targets near initialization.
        # Ret stops are approximate; overlapping windows and unreachable instructions
        # can produce false edges, and indirect branches are not followed.
        queue = collections.deque((addr, 0, addr) for addr in funcs[:INIT_LIMIT])
        visited = set()
        trace_sites = {}
        while queue and len(visited) < TRACE_NODES:
            addr, depth, origin = queue.popleft()
            if addr in visited or addr % 4:
                continue
            sec = next((part for part in executable if part['sh_addr'] <= addr < part['sh_addr'] + part['sh_size']), None)
            if not sec or sec.name.startswith('.plt'):
                continue
            visited.add(addr)
            offset = addr - sec['sh_addr']
            f.seek(sec['sh_offset'] + offset)
            data = f.read(min(WINDOW_BYTES, sec['sh_size'] - offset))
            for pc, word in instructions(data, addr):
                if word & 0xfffffc1f == 0xd65f0000:
                    break
                target = direct_branch(word, pc)
                if target is None:
                    continue
                name = plt.get(target)
                if name:
                    api = trace_sites.setdefault(name, {})
                    api.setdefault(pc, {'site': hex(pc), 'depth': depth, 'initializer': hex(origin)})
                elif depth < TRACE_DEPTH and target not in visited:
                    queue.append((target, depth + 1, origin))
        trace = {name: {'distinctSites': len(sites), 'examples': list(sites.values())[:SAMPLE_LIMIT]}
                 for name, sites in sorted(trace_sites.items())}
        # Nearby calls are only spatial clues; the window may span functions or
        # unreachable code. Prioritize a traced call and an open+read pair.
        nearby = {}
        trace_pcs = {pc for sites in trace_sites.values() for pc in sites}
        site_limit_reached = len(nearby_sites) == 512
        stored = {pc for pc, _ in nearby_sites}
        for name, sites in trace_sites.items():
            if name in NEARBY_APIS:
                nearby_sites.extend((pc, name) for pc in sites if pc not in stored)
        for site, _ in nearby_sites:
            sec = next((part for part in executable if part['sh_addr'] <= site < part['sh_addr'] + part['sh_size']), None)
            if not sec:
                continue
            start = max(sec['sh_addr'], site - 512)
            end = min(sec['sh_addr'] + sec['sh_size'], site + 516)
            f.seek(sec['sh_offset'] + start - sec['sh_addr'])
            data = f.read(end - start)
            near = nearby_calls(data, start, plt)
            api_names = {name for _, name in near}
            if len(api_names) < 2:
                continue
            key = tuple(near)
            if key in nearby:
                continue
            categories = nearby_string_categories(elf, f, data, start)
            score = (bool(trace_pcs.intersection(pc for pc, _ in near)), 'open' in api_names and 'read' in api_names, len(api_names))
            nearby[key] = (score, {'calls': [{'api': name, 'site': hex(pc)} for pc, name in near[:12]],
                                   'callCount': len(near), 'stringCategories': categories})
        ranked = sorted(nearby.values(), key=lambda value: value[0], reverse=True)
        return {
            'kind': 'arm64-static-triage',
            'watchedImports': sorted(imports), 'selectedExports': sorted(exports),
            'watchedPltRelocations': len(relocs), 'matchedWatchedPltStubs': matched_stubs,
            'executableBytes': total, 'scannedBytes': scanned, 'scanTruncated': scanned < total,
            'directPltCalls': calls,
            'initializers': {'total': len(funcs), 'sampled': min(len(funcs), INIT_LIMIT),
                             'inExecutableSections': analyzable, 'sampledWithWatchedCalls': samples},
            'initializerTrace': {'windowBytes': WINDOW_BYTES, 'maxDepth': TRACE_DEPTH,
                                 'visitedWindows': len(visited), 'nodeLimitReached': bool(queue),
                                 'watchedDirectCalls': trace},
            'nearbyImportWindows': {'windowBytes': 1028, 'eligibleWindows': len(ranked),
                                    'siteLimitReached': site_limit_reached,
                                    'examples': [item for _, item in ranked[:8]]},
            'limitations': 'Linear BL sweep and bounded heuristic initializer windows are not a proven call graph; indirect calls, other PLT formats, packed code and control flow may be missed; nearby sites and categorized constants do not establish function boundaries or purpose.',
        }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('elf')
    args = parser.parse_args()
    print(json.dumps(inspect(args.elf), separators=(',', ':')))

if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""Bounded static lead search. Emits categories/ELF offsets only, no strings or code."""
import json
import struct
import sys
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from elftools.elf.elffile import ELFFile
import worldbox_native_xrefs as refs

NEEDLES = {
    'metadata-name': (b'global-metadata.dat',),
    'premium-keyword': (b'premium',),
    'unity-purchasing-class': (b'UnityPurchasing',),
    'unity-callback-interface': (b'IUnityCallback',),
    'purchase-success-callback': (b'OnPurchaseSucceeded',),
    'products-retrieved-callback': (b'OnProductsRetrieved',),
    'purchase-failed-callback': (b'OnPurchaseFailed',),
    'setup-failed-callback': (b'OnSetupFailed',),
}
MAX_DATA = 96 * 1024 * 1024
MAX_EXEC = 96 * 1024 * 1024
MAX_TARGETS = 32  # per category; counts continue even when references are capped
MAX_SITES = 12
MAX_STRING = 512


def matches(data, base):
    """Find case-insensitive ASCII keywords inside bounded NUL-terminated runs.

    String-start and keyword-start pointers are candidates, not proof that they
    are used as strings. Runs split across sections or the scan bound are missed.
    """
    lower = data.lower()
    result = {k: [] for k in NEEDLES}
    for category, needles in NEEDLES.items():
        for needle in needles:
            needle = needle.lower()
            pos = 0
            while True:
                i = lower.find(needle, pos)
                if i < 0:
                    break
                pos = i + 1
                left = i
                while left > 0 and 32 <= data[left - 1] <= 126 and i - left < MAX_STRING:
                    left -= 1
                right = i + len(needle)
                while right < len(data) and 32 <= data[right] <= 126 and right - left <= MAX_STRING:
                    right += 1
                if right >= len(data) or data[right] != 0 or right - left > MAX_STRING:
                    continue
                if left > 0 and 32 <= data[left - 1] <= 126:
                    continue
                result[category].append((base + left, base + i))
    return result


def reference_pairs(data, base, targets):
    """ADRP + ADD within 32 bytes, no intervening branch or base-register clobber."""
    decoder = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    decoder.detail = True
    pages = {addr & ~0xfff for addr in targets}
    counts = {addr: 0 for addr in targets}
    samples = {addr: [] for addr in targets}
    data = data[:len(data) & ~3]
    for index, (word,) in enumerate(struct.iter_unpack('<I', data)):
        offset = index * 4
        pc = base + offset
        page = refs.adrp_value(word, pc)
        if not page or page[1] == 31 or page[0] not in pages:
            continue
        for off in range(offset + 4, min(offset + 36, len(data)), 4):
            add = refs.add_value(struct.unpack_from('<I', data, off)[0])
            if add and add[0] == page[1] and page[0] + add[1] in targets:
                target = page[0] + add[1]
                if refs.verify_adrp_add(decoder, data[offset:off + 4], pc, page[1], base + off):
                    counts[target] += 1
                    if len(samples[target]) < MAX_SITES:
                        samples[target].append({'adrp': hex(pc), 'add': hex(base + off)})
                # More than one ADD can refer to the same page; keep looking.
    return counts, samples


def inspect(path):
    with Path(path).open('rb') as f:
        elf = ELFFile(f)
        if elf.elfclass != 64 or not elf.little_endian or elf['e_machine'] != 'EM_AARCH64':
            raise ValueError('Expected little-endian ELF64 AArch64')
        found = {key: [] for key in NEEDLES}
        totals = {key: 0 for key in NEEDLES}
        data_total = data_scanned = 0
        for sec in elf.iter_sections():
            if sec['sh_type'] == 'SHT_NOBITS' or not sec['sh_flags'] & 2 or sec['sh_flags'] & (1 | 4):
                continue
            size = sec['sh_size']
            data_total += size
            budget = min(size, MAX_DATA - data_scanned)
            if budget <= 0:
                continue
            f.seek(sec['sh_offset'])
            data = f.read(budget)
            if len(data) != budget:
                raise ValueError('Short ELF section read')
            data_scanned += len(data)
            for category, rows in matches(data, sec['sh_addr']).items():
                totals[category] += len(rows)
                found[category].extend(rows[:max(0, MAX_TARGETS - len(found[category]))])
        targets = {addr for rows in found.values() for pair in rows for addr in pair}
        counts = {addr: 0 for addr in targets}
        sites = {addr: [] for addr in targets}
        exec_total = exec_scanned = 0
        for sec in elf.iter_sections():
            if sec['sh_type'] == 'SHT_NOBITS' or not sec['sh_flags'] & 4:
                continue
            size = sec['sh_size']
            exec_total += size
            budget = min(size, MAX_EXEC - exec_scanned) & ~3
            if budget <= 0:
                continue
            f.seek(sec['sh_offset'])
            data = f.read(budget)
            if len(data) != budget:
                raise ValueError('Short ELF section read')
            exec_scanned += len(data)
            if targets:
                n, s = reference_pairs(data, sec['sh_addr'], targets)
                for addr in targets:
                    counts[addr] += n[addr]
                    sites[addr].extend(s[addr][:max(0, MAX_SITES - len(sites[addr]))])
        categories = {}
        for category, rows in found.items():
            entries = []
            for start, keyword in rows:
                entries.append({'stringStart': hex(start), 'keywordStart': hex(keyword),
                                'startRefs': counts[start], 'keywordRefs': counts[keyword],
                                'startSamples': sites[start], 'keywordSamples': sites[keyword] if keyword != start else []})
            categories[category] = {'matches': totals[category], 'targetLimitReached': totals[category] > len(rows), 'entries': entries}
        return {'kind': 'arm64-string-leads', 'dataBytesScanned': data_scanned, 'dataBytesTotal': data_total,
                'execBytesRead': exec_scanned, 'execBytesScanned': exec_scanned if targets else 0,
                'execBytesTotal': exec_total, 'referenceSweepPerformed': bool(targets), 'categories': categories}


if __name__ == '__main__':
    print(json.dumps(inspect(sys.argv[1]), separators=(',', ':')))

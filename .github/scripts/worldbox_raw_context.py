#!/usr/bin/env python3
"""Bounded context and direct ARM64 reference clues for one verified ASCII hit.

No library bytes or surrounding strings are emitted. Context is byte-level only.
"""
import json
from pathlib import Path
import sys
from elftools.elf.elffile import ELFFile
import worldbox_string_leads as leads
import worldbox_raw_leads as raw

OFFSET = 0xede91d
KEYWORD = b'premium'
MAX_CONTEXT = 4096


def context(data, offset, keyword=KEYWORD):
    if offset < 0 or data[offset:offset + len(keyword)].lower() != keyword:
        raise ValueError('Expected keyword not present at requested offset')
    lo, hi = offset, offset + len(keyword)
    while lo and 32 <= data[lo - 1] <= 126 and offset - lo < MAX_CONTEXT:
        lo -= 1
    while hi < len(data) and 32 <= data[hi] <= 126 and hi - (offset + len(keyword)) < MAX_CONTEXT:
        hi += 1
    left_limited = lo > 0 and 32 <= data[lo - 1] <= 126
    right_limited = hi < len(data) and 32 <= data[hi] <= 126
    def boundary(i):
        if i < 0 or i >= len(data): return 'file-edge'
        return 'nul' if data[i] == 0 else 'nonprintable'
    return {'start': lo, 'end': hi, 'length': hi - lo,
            'leftLimited': left_limited, 'rightLimited': right_limited,
            'leftBoundary': 'limit' if left_limited else boundary(lo - 1),
            'rightBoundary': 'limit' if right_limited else boundary(hi)}


def inspect(path):
    path = Path(path)
    if path.stat().st_size > raw.MAX_FILE:
        raise ValueError('File exceeds bounded context limit')
    with path.open('rb') as f:
        elf = ELFFile(f)
        if elf.elfclass != 64 or not elf.little_endian or elf['e_machine'] != 'EM_AARCH64':
            raise ValueError('Expected little-endian ELF64 AArch64')
        sections = list(elf.iter_sections())
        f.seek(0)
        data = f.read()
        ctx = context(data, OFFSET)
        eligible = [s for s in sections if s['sh_type'] != 'SHT_NOBITS' and s['sh_flags'] & 2
                    and s['sh_offset'] <= ctx['start'] and ctx['end'] <= s['sh_offset'] + s['sh_size']]
        if len(eligible) != 1:
            raise ValueError('Printable run does not map uniquely to an allocated section')
        sec = eligible[0]
        keyword_addr = sec['sh_addr'] + OFFSET - sec['sh_offset']
        start_addr = sec['sh_addr'] + ctx['start'] - sec['sh_offset']
        # If the prefix was truncated there is no defensible start target.
        targets = {keyword_addr}
        if not ctx['leftLimited']:
            targets.add(start_addr)
        counts = {addr: 0 for addr in targets}
        samples = {addr: [] for addr in targets}
        total = scanned = 0
        for s in sections:
            if s['sh_type'] == 'SHT_NOBITS' or not s['sh_flags'] & 4:
                continue
            total += s['sh_size']
            budget = min(s['sh_size'], leads.MAX_EXEC - scanned) & ~3
            if budget <= 0: continue
            code = data[s['sh_offset']:s['sh_offset'] + budget]
            if len(code) != budget: raise ValueError('Short executable section')
            n, found = leads.reference_pairs(code, s['sh_addr'], targets)
            scanned += len(code)
            for addr in targets:
                counts[addr] += n[addr]
                samples[addr].extend(found[addr][:max(0, leads.MAX_SITES - len(samples[addr]))])
        def refs(addr):
            return {'address': hex(addr), 'count': counts[addr], 'samples': samples[addr],
                    'samplesTruncated': counts[addr] > len(samples[addr])}
        return {'kind': 'arm64-raw-name-context',
                'context': {k: v for k, v in ctx.items() if k not in ('start', 'end')},
                'keyword': refs(keyword_addr),
                'printableRunStart': refs(start_addr) if not ctx['leftLimited'] else None,
                'execBytesScanned': scanned, 'execBytesTotal': total}


if __name__ == '__main__':
    print(json.dumps(inspect(Path(sys.argv[1])), separators=(',', ':')))

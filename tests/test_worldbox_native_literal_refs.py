"""Synthetic ARM64 ELF tests for bounded literal-reference modeling."""
import hashlib
import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.github/scripts'))
sys.path.insert(0, str(ROOT / 'tests'))
import worldbox_native_literal_refs as refs
import worldbox_thunk_callers as thunks
from elftools.elf.elffile import ELFFile
from test_worldbox_native import branch
from test_worldbox_native_import_probe import adrp, br, ldr

TARGET = 0x189941c
STATE_CREATE = 0x189932c
STATE_DESTROY = 0x18993dc
UNKNOWN = b'fixture_unknown_secret\0'


def add(rd, rn, immediate):
    return 0x91000000 | ((immediate & 0xfff) << 10) | (rn << 5) | rd


def ldr_literal(rt, literal, pc):
    displacement = (literal - pc) >> 2
    return 0x58000000 | ((displacement & 0x7ffff) << 5) | rt


def blr(register):
    return 0xd63f0000 | (register << 5)


def nop():
    return 0xd503201f


def ret():
    return 0xd65f03c0


def fixture():
    names = ['', '.shstrtab', '.dynstr', '.dynsym', '.rela.plt', '.plt',
             '.text', '.rodata', '.data', '.dynamic', '.eh_frame']
    shstr = b'\0'
    name_offsets = [0]
    for name in names[1:]:
        name_offsets.append(len(shstr))
        shstr += name.encode() + b'\0'
    dynstr = b'\0'
    offsets = {}
    for name in ('dlsym', 'BrotliDecoderDecompress'):
        offsets[name] = len(dynstr)
        dynstr += name.encode() + b'\0'
    dynsym = bytes(24)
    dynsym += struct.pack('<IBBHQQ', offsets['dlsym'], 0x12, 0, 0, 0, 0)
    dynsym += struct.pack('<IBBHQQ', offsets['BrotliDecoderDecompress'],
                          0x12, 0, 6, TARGET, 16)
    rela_plt = struct.pack('<QQq', 0x5010, (1 << 32) | 1026, 0)
    plt = struct.pack('<4I', adrp(16, 0x5000, 0x2000),
                      ldr(17, 16, 0x10), br(17), nop())
    rodata = bytearray(0xa0)
    rodata[0:len(b'BrotliDecoderDecompress\0')] = b'BrotliDecoderDecompress\0'
    rodata[0x20:0x20 + len(b'premium_unlocked\0')] = b'premium_unlocked\0'
    rodata[0x40:0x40 + len(b'Get It Now\0')] = b'Get It Now\0'
    rodata[0x60:0x60 + len('premium_unlocked'.encode('utf-16le') + b'\0\0')] = (
        'premium_unlocked'.encode('utf-16le') + b'\0\0')
    rodata[0x80:0x80 + len(UNKNOWN)] = UNKNOWN
    data = bytearray(0x30)
    struct.pack_into('<Q', data, 0x18, TARGET)
    words = []

    def pc():
        return 0x3000 + 4 * len(words)

    def emit(word):
        words.append(word)

    # Two bounded name-literal references followed by the synthetic dlsym stub.
    emit(adrp(0, 0x4000, pc())); emit(add(0, 0, 0))
    emit(branch(pc(), 0x2000)); emit(nop())
    emit(adrp(3, 0x4000, pc())); emit(add(3, 3, 0x20))
    emit(branch(pc(), 0x2000)); emit(nop())
    # Direct address materialization followed by an indirect call.
    emit(adrp(1, 0x1899000, pc())); emit(add(1, 1, 0x41c))
    emit(blr(1)); emit(nop())
    # Literal-pool pointer followed by an indirect call.
    literal_pc = pc()
    literal_address = literal_pc + 16
    emit(ldr_literal(2, literal_address, literal_pc))
    emit(blr(2)); emit(nop()); emit(nop())
    if pc() != literal_address:
        raise AssertionError('fixture literal address mismatch')
    words.extend(struct.unpack('<II', struct.pack('<Q', TARGET)))
    emit(branch(pc(), STATE_CREATE)); emit(branch(pc(), STATE_DESTROY)); emit(ret())
    text = struct.pack('<%dI' % len(words), *words)
    dynamic = struct.pack('<QQ', 0, 0)
    cie_body = bytes(4) + b'\x01zR\x00\x01\x78\x1e\x01\x00\x0c\x1f\x00'
    cie = struct.pack('<I', len(cie_body)) + cie_body
    fde_body = struct.pack('<IQQ', len(cie) + 4, 0x3000, len(text)) + bytes(4)
    eh_frame = cie + struct.pack('<I', len(fde_body)) + fde_body + bytes(4)
    blobs = [b'', shstr, dynstr, dynsym, rela_plt, plt, text, bytes(rodata),
             bytes(data), dynamic, eh_frame]
    types = [0, 3, 3, 11, 4, 1, 1, 1, 1, 6, 1]
    flags = [0, 0, 2, 2, 2, 6, 6, 2, 3, 3, 2]
    addrs = [0, 0, 0x1000, 0x1100, 0x1200, 0x2000, 0x3000, 0x4000,
             0x5000, 0x6000, 0x7000]
    links = [0, 0, 0, 2, 3, 0, 0, 0, 0, 2, 0]
    infos = [0, 0, 1, 1, 5, 0, 0, 0, 0, 0, 0]
    entsizes = [0, 0, 0, 24, 24, 0, 0, 0, 0, 16, 0]
    image = bytearray(64)
    sections = [bytes(64)]
    for index in range(1, len(names)):
        while len(image) % 8:
            image.append(0)
        offset = len(image)
        image.extend(blobs[index])
        sections.append(struct.pack(
            '<IIQQQQIIQQ', name_offsets[index], types[index], flags[index],
            addrs[index], offset, len(blobs[index]), links[index], infos[index],
            8, entsizes[index]))
    while len(image) % 8:
        image.append(0)
    shoff = len(image)
    image.extend(b''.join(sections))
    ident = b'\x7fELF' + bytes([2, 1, 1, 0]) + bytes(8)
    image[:64] = struct.pack('<16sHHIQQQIHHHHHH', ident, 3, 183, 1, 0, 0,
                             shoff, 0, 64, 0, 0, 64, len(names), 1)
    return bytes(image)


class NativeLiteralRefsTest(unittest.TestCase):
    def test_literal_references_loader_calls_and_indirect_calls(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'fixture.so'
            path.write_bytes(fixture())
            with path.open('rb') as handle:
                elf = ELFFile(handle)
                frames, status = thunks.unwind_frames(elf)
            self.assertEqual(status, 'parsed')
            starts = [lo for lo, _ in frames]
            needles = {'brotli_export': 'BrotliDecoderDecompress',
                       'premium_unlocked': 'premium_unlocked',
                       'get_it_now': 'Get It Now'}
            literals = refs.literal_occurrences(path, needles)
            self.assertGreaterEqual(literals['results']['brotli_export']['ascii']['count'], 2)
            self.assertEqual(literals['results']['premium_unlocked']['ascii']['count'], 1)
            self.assertEqual(literals['results']['premium_unlocked']['utf16le']['count'], 1)
            self.assertIn('0x4020', literals['referenceAddresses'])
            sites = refs.adrp_add_reference_sites(path, ['0x4020'], frames, starts)
            self.assertEqual(sites['count'], 1)
            self.assertIn('0x3000', sites['functionAddresses'])
            calls = refs.function_direct_calls(path, sites['functionAddresses'],
                                               {0x2000: 'dlsym'})
            self.assertEqual(calls['rows'][0]['callCounts']['dlsym'], 2)
            pointers = refs.pointer_locations(path, [TARGET])
            self.assertGreaterEqual(pointers['counts'][hex(TARGET)], 2)
            indirect = refs.indirect_call_sites(path, [TARGET], frames, starts)
            self.assertEqual(indirect['counts'][hex(TARGET)]['materializationCount'], 2)
            self.assertEqual(indirect['counts'][hex(TARGET)]['indirectCallCount'], 2)
            self.assertEqual({row['kind'] for row in indirect['materializationSamples']},
                             {'adrp-add', 'ldr-literal'})
            output = json.dumps({'literals': literals, 'sites': sites,
                                 'calls': calls, 'indirect': indirect},
                                separators=(',', ':'))
            self.assertNotIn('fixture_unknown_secret', output)

    def test_hash_text_is_stable_and_never_empty(self):
        self.assertEqual(refs.hash_text('premium_unlocked'),
                         hashlib.sha256(b'premium_unlocked').hexdigest())
        self.assertEqual(len(refs.hash_text('')), 64)


if __name__ == '__main__':
    unittest.main()

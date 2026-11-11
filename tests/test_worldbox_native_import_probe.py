"""Synthetic ELF tests for bounded native import classification."""
import contextlib
import hashlib
import io
from pathlib import Path
import struct
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.github/scripts'))
sys.path.insert(0, str(ROOT / 'tests'))
import worldbox_native_import_probe as probe
from test_worldbox_native import branch


def adrp(register, target_page, pc):
    imm = (target_page - (pc & ~0xfff)) >> 12
    return 0x90000000 | ((imm & 3) << 29) | (((imm >> 2) & 0x7ffff) << 5) | register


def ldr(rt, rn, displacement):
    return 0xf9400000 | ((displacement // 8) << 10) | (rn << 5) | rt


def br(register):
    return 0xd61f0000 | (register << 5)


def synthetic_elf(imports, needed=()):
    names = ['', '.shstrtab', '.dynstr', '.dynsym', '.rela.plt', '.plt',
             '.text', '.dynamic', '.eh_frame']
    shstr = b'\0'
    name_offsets = [0]
    for name in names[1:]:
        name_offsets.append(len(shstr))
        shstr += name.encode() + b'\0'
    dynstr = b'\0'
    symbol_offsets = {}
    for name in imports:
        symbol_offsets[name] = len(dynstr)
        dynstr += name.encode() + b'\0'
    needed_offsets = {}
    for name in needed:
        needed_offsets[name] = len(dynstr)
        dynstr += name.encode() + b'\0'
    dynsym = bytes(24)
    for name in imports:
        dynsym += struct.pack('<IBBHQQ', symbol_offsets[name], 0x12, 0, 0, 0, 0)
    rela_plt = b''.join(
        struct.pack('<QQq', 0x5010 + 8 * index, ((index + 1) << 32) | 1026, 0)
        for index in range(len(imports)))
    plt_words = []
    for index in range(len(imports)):
        pc = 0x2000 + 16 * index
        plt_words.extend((adrp(16, 0x5000, pc), ldr(17, 16, 0x10 + 8 * index),
                          br(17), 0xd503201f))
    plt = struct.pack('<%dI' % len(plt_words), *plt_words) if plt_words else bytes(16)
    text_words = [branch(0x3000 + 4 * index, 0x2000 + 16 * index)
                  for index in range(len(imports))]
    text_words.append(0xd65f03c0)
    while len(text_words) < 16:
        text_words.append(0xd503201f)
    text = struct.pack('<16I', *text_words)
    dynamic = b''.join(struct.pack('<QQ', 1, needed_offsets[name]) for name in needed)
    dynamic += struct.pack('<QQ', 0, 0)
    cie_body = bytes(4) + b'\x01zR\x00\x01\x78\x1e\x01\x00\x0c\x1f\x00'
    cie = struct.pack('<I', len(cie_body)) + cie_body
    fdes = b''
    fde_body = struct.pack('<IQQ', len(cie) + len(fdes) + 4, 0x3000, len(text)) + bytes(4)
    fdes += struct.pack('<I', len(fde_body)) + fde_body
    eh_frame = cie + fdes + bytes(4)
    blobs = [b'', shstr, dynstr, dynsym, rela_plt, plt, text, dynamic, eh_frame]
    types = [0, 3, 3, 11, 4, 1, 1, 6, 1]
    flags = [0, 0, 2, 2, 2, 6, 6, 3, 2]
    addrs = [0, 0, 0x1000, 0x1100, 0x1200, 0x2000, 0x3000, 0x4000, 0x7000]
    links = [0, 0, 0, 2, 3, 0, 0, 2, 0]
    infos = [0, 0, 1, 1, 5, 0, 0, 0, 0]
    entsizes = [0, 0, 0, 24, 24, 0, 0, 16, 0]
    data = bytearray(64)
    sections = [bytes(64)]
    for index in range(1, len(names)):
        while len(data) % 8:
            data.append(0)
        offset = len(data)
        data.extend(blobs[index])
        sections.append(struct.pack(
            '<IIQQQQIIQQ', name_offsets[index], types[index], flags[index],
            addrs[index], offset, len(blobs[index]), links[index], infos[index],
            8, entsizes[index]))
    while len(data) % 8:
        data.append(0)
    shoff = len(data)
    data.extend(b''.join(sections))
    ident = b'\x7fELF' + bytes([2, 1, 1, 0]) + bytes(8)
    data[:64] = struct.pack('<16sHHIQQQIHHHHHH', ident, 3, 183, 1, 0, 0,
                            shoff, 0, 64, 0, 0, 64, len(names), 1)
    return bytes(data)


def write_elf(directory, data):
    path = Path(directory) / 'fixture.so'
    path.write_bytes(data)
    return path, hashlib.sha256(data).hexdigest()


class NativeImportProbeTest(unittest.TestCase):
    def test_predefined_imports_dependencies_and_callers(self):
        data = synthetic_elf(
            ['open', 'AAssetManager_open', 'inflateInit_', 'AES_decrypt'],
            needed=['libz.so', 'libandroid.so', 'libcrypto.so'])
        with tempfile.TemporaryDirectory() as directory:
            path, sha = write_elf(directory, data)
            report = probe.import_report(path, path,
                                         expected_il2cpp=sha, expected_unity=sha)
        self.assertEqual(report['kind'], probe.KIND)
        self.assertEqual(report['ghidraLibrary'], 'libil2cpp.so')
        library = report['libraries'][0]
        self.assertEqual(library['categorySymbolCounts']['file-io'], 1)
        self.assertEqual(library['categorySymbolCounts']['asset-android'], 1)
        self.assertEqual(library['categorySymbolCounts']['compression-zlib'], 1)
        self.assertEqual(library['categorySymbolCounts']['crypto-openssl-aes'], 1)
        self.assertEqual(set(library['dynamicDependencyLabels']),
                         {'asset-android', 'compression-zlib', 'crypto-openssl'})
        self.assertIn('AAssetManager_open', library['matchedSymbolNames'])
        self.assertGreaterEqual(library['pltStubCount'], 1)
        self.assertEqual(library['pltSymbolMap']['0x2000'],
                         {'symbol': 'open', 'category': 'file-io'})
        self.assertEqual(library['pltSymbolMap']['0x2020']['symbol'], 'inflateInit_')
        self.assertEqual(len(report['rows']), 8)
        for row in report['rows'][:4]:
            self.assertEqual(row['directCallCount'], 1)
            self.assertGreaterEqual(len(row['fdeReports']), 1)
        self.assertIn('0x3000', report['ghidraAddresses'])
        self.assertIn('0x2000', report['traceTargets'])
        self.assertFalse(report['traceTargetsTruncated'])

    def test_unknown_symbols_are_not_emitted(self):
        data = synthetic_elf(['mystery_api'], needed=['mystery.so'])
        with tempfile.TemporaryDirectory() as directory:
            path, sha = write_elf(directory, data)
            report = probe.import_report(path, path,
                                         expected_il2cpp=sha, expected_unity=sha)
        self.assertEqual(report['rows'], [])
        self.assertEqual(report['ghidraAddresses'], [])
        self.assertEqual(set(report['traceTargets']), set(probe.KNOWN_ANCHORS))
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            probe.emit_import_annotations(report)
        output = buffer.getvalue()
        self.assertIn('::warning title=WorldBox native import summary::', output)
        self.assertNotIn('mystery_api', output)
        self.assertNotIn('mystery.so', output)

    def test_known_dependency_labels_filter_unknown_names(self):
        self.assertEqual(probe.known_dependency_labels(['libz.so', 'libcrypto.so', 'mystery.so']),
                         ['compression-zlib', 'crypto-openssl'])

    def test_hash_gate_rejects_mismatched_library(self):
        data = synthetic_elf(['open'])
        with tempfile.TemporaryDirectory() as directory:
            path, _sha = write_elf(directory, data)
            with self.assertRaises(ValueError):
                probe.library_report(path, 'libil2cpp.so', '0' * 64)


if __name__ == '__main__':
    unittest.main()

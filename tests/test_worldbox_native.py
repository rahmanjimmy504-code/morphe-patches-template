"""Synthetic ARM64 ELF tests; no game libraries are required."""
import importlib.util
from pathlib import Path
import struct
import tempfile
import unittest

SOURCE = Path(__file__).resolve().parents[1] / '.github/scripts/worldbox_native_scan.py'
spec = importlib.util.spec_from_file_location('worldbox_native_scan', SOURCE)
scan = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scan)


def branch(pc, target):
    return 0x94000000 | (((target - pc) // 4) & 0x03ffffff)


def fixture(broken_stub=False, via_helper=False):
    """Construct a minimal AArch64 ELF with an imported open() PLT and init array."""
    names = ['', '.shstrtab', '.dynstr', '.dynsym', '.rela.plt', '.rela.dyn', '.plt', '.text', '.init_array']
    shstr = b'\0'
    name_offsets = [0]
    for name in names[1:]:
        name_offsets.append(len(shstr))
        shstr += name.encode() + b'\0'
    dynstr = b'\0open\0'
    dynsym = bytes(24) + struct.pack('<IBBHQQ', 1, 0x12, 0, 0, 0, 0)
    rela_plt = struct.pack('<QQq', 0x5010, (1 << 32) | 1026, 0)
    rela_dyn = struct.pack('<QQq', 0x6000, 1027, 0x3000)
    # AArch64: adrp x16, 0x5000; ldr x17, [x16, #0x10]; add; br x17.
    adrp = 0x90000000 | (3 << 29) | 16
    ldr = 0xf9400000 | (2 << 10) | (16 << 5) | 17
    plt = struct.pack('<12I', *([0xd503201f] * 8), adrp, ldr, 0x91004210, 0xd61f0220 if not broken_stub else 0xd65f03c0)
    if via_helper:
        text = struct.pack('<2I', branch(0x3000, 0x3040), 0xd65f03c0) + bytes(56) + struct.pack('<2I', branch(0x3040, 0x2020), 0xd65f03c0)
    else:
        text = struct.pack('<3I', branch(0x3000, 0x2020), 0xd65f03c0, 0xd503201f)
    blobs = [b'', shstr, dynstr, dynsym, rela_plt, rela_dyn, plt, text, bytes(8)]
    types = [0, 3, 3, 11, 4, 4, 1, 1, 14]
    flags = [0, 0, 2, 2, 2, 2, 6, 6, 3]
    addrs = [0, 0, 0x1000, 0x1100, 0x1200, 0x1300, 0x2000, 0x3000, 0x6000]
    links = [0, 0, 0, 2, 3, 3, 0, 0, 0]
    infos = [0, 0, 0, 1, 6, 0, 0, 0, 0]
    entsizes = [0, 0, 0, 24, 24, 24, 0, 0, 8]
    data = bytearray(64)
    sections = [bytes(64)]
    for i in range(1, len(names)):
        while len(data) % 8:
            data.append(0)
        offset = len(data)
        data.extend(blobs[i])
        sections.append(struct.pack('<IIQQQQIIQQ', name_offsets[i], types[i], flags[i], addrs[i], offset, len(blobs[i]), links[i], infos[i], 8, entsizes[i]))
    while len(data) % 8:
        data.append(0)
    shoff = len(data)
    data.extend(b''.join(sections))
    ident = b'\x7fELF' + bytes([2, 1, 1, 0]) + bytes(8)
    data[:64] = struct.pack('<16sHHIQQQIHHHHHH', ident, 3, 183, 1, 0, 0, shoff, 0, 64, 0, 0, 64, len(names), 1)
    return data


class NativeTriageTest(unittest.TestCase):
    def test_branch_decoding(self):
        self.assertEqual(scan.direct_branch(branch(0x3000, 0x2020), 0x3000), 0x2020)
        self.assertEqual(scan.direct_branch(branch(0x1000, 0x2000), 0x1000), 0x2000)
        self.assertIsNone(scan.direct_branch(0xd65f03c0, 0x1000))

    def test_nearby_calls_and_safe_string_categories(self):
        data = struct.pack('<3I', branch(0x1000, 0x2000), branch(0x1004, 0x2010), 0xd65f03c0)
        self.assertEqual(scan.nearby_calls(data, 0x1000, {0x2000: 'open', 0x2010: 'read'}), [(0x1000, 'open'), (0x1004, 'read')])
        self.assertEqual(scan.string_category(b'/proc/self/maps\0'), 'proc-path')
        self.assertEqual(scan.string_category(b'global-metadata.dat\0'), 'metadata-name')
        self.assertIsNone(scan.string_category(b'private-string\0'))

    def test_real_elf_parse_plt_and_relocated_initializer(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'sample.so'
            path.write_bytes(fixture())
            report = scan.inspect(path)
        self.assertEqual(report['watchedImports'], ['open'])
        self.assertEqual(report['watchedPltRelocations'], 1)
        self.assertEqual(report['matchedWatchedPltStubs'], 1)
        self.assertEqual(report['directPltCalls']['open']['count'], 1)
        self.assertEqual(report['directPltCalls']['open']['sampleSites'], ['0x3000'])
        self.assertEqual(report['initializers']['total'], 1)
        self.assertEqual(report['initializers']['inExecutableSections'], 1)
        self.assertEqual(report['initializers']['sampledWithWatchedCalls'][0]['watchedCalls'][0]['api'], 'open')
        self.assertFalse(report['scanTruncated'])

    def test_bounded_direct_trace_reaches_helper(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'helper.so'
            path.write_bytes(fixture(via_helper=True))
            report = scan.inspect(path)
        trace = report['initializerTrace']
        self.assertEqual(trace['visitedWindows'], 2)
        self.assertFalse(trace['nodeLimitReached'])
        self.assertEqual(trace['watchedDirectCalls']['open']['examples'][0], {'site': '0x3040', 'depth': 1, 'initializer': '0x3000'})

    def test_unrecognized_stub_is_not_guessed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'broken.so'
            path.write_bytes(fixture(broken_stub=True))
            report = scan.inspect(path)
        self.assertEqual(report['matchedWatchedPltStubs'], 0)
        self.assertEqual(report['directPltCalls']['open']['count'], 0)
        self.assertEqual(report['initializers']['sampledWithWatchedCalls'], [])

    def test_rejects_non_arm64(self):
        data = fixture()
        data[18:20] = struct.pack('<H', 62)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'wrong.so'
            path.write_bytes(data)
            with self.assertRaisesRegex(ValueError, 'AArch64'):
                scan.inspect(path)

if __name__ == '__main__':
    unittest.main()

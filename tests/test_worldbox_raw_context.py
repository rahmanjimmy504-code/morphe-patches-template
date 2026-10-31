"""Synthetic bounds and reference tests for the raw byte-sequence follow-up."""
from pathlib import Path
import sys
import io
import struct
import tempfile
from unittest.mock import patch
from elftools.elf.elffile import ELFFile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / '.github/scripts'))
import worldbox_raw_context as probe
from test_worldbox_native import fixture


class RawContextTest(unittest.TestCase):
    def test_printable_run_and_boundaries(self):
        found = probe.context(b'\0aPremiumXYZ\0', 2)
        self.assertEqual((found['start'], found['end'], found['length']), (1, 12, 11))
        self.assertEqual(found['leftBoundary'], 'nul')
        self.assertEqual(found['rightBoundary'], 'nul')
        self.assertFalse(found['leftLimited'])

    def test_long_run_is_bounded(self):
        data = b'x' * 5000 + b'premium' + b'y' * 5000
        found = probe.context(data, 5000)
        self.assertTrue(found['leftLimited'])
        self.assertTrue(found['rightLimited'])
        self.assertEqual(found['length'], 2 * probe.MAX_CONTEXT + len(b'premium'))
        self.assertEqual(found['leftBoundary'], 'limit')

    def test_nonprintable_and_file_edge(self):
        found = probe.context(b'PREMIUM\xff', 0)
        self.assertEqual(found['leftBoundary'], 'file-edge')
        self.assertEqual(found['rightBoundary'], 'nonprintable')

    def test_full_fixture_reference(self):
        data = fixture()
        elf = ELFFile(io.BytesIO(data))
        strings = elf.get_section_by_name('.shstrtab')
        text = elf.get_section_by_name('.text')
        relative = strings.data().find(b'.init_array')
        self.assertGreater(relative, 0)
        offset = strings['sh_offset'] + relative
        data[offset:offset + 11] = b'premiumxxxx'
        shoff = elf['e_shoff'] + elf['e_shentsize']
        struct.pack_into('<Q', data, shoff + 8, 2)
        struct.pack_into('<Q', data, shoff + 16, 0x5000)
        adrp = 0x90000000 | (2 << 29) | 16
        add = 0x91000000 | (relative << 10) | (16 << 5)
        struct.pack_into('<II', data, text['sh_offset'], adrp, add)
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory) / 'fixture.so'
            p.write_bytes(data)
            with patch.object(probe, 'OFFSET', offset):
                report = probe.inspect(p)
        self.assertEqual(report['keyword']['count'], 1)
        self.assertEqual(report['printableRunStart']['count'], 1)
        self.assertEqual(report['context']['rightBoundary'], 'nul')
        self.assertEqual(report['execBytesScanned'], report['execBytesTotal'])

    def test_wrong_target_fails_closed(self):
        with self.assertRaises(ValueError): probe.context(b'not a target', 0)
        with self.assertRaises(ValueError): probe.context(b'premium', -1)

if __name__ == '__main__':
    unittest.main()

"""Synthetic raw name search tests; no game files required."""
from pathlib import Path
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / '.github/scripts'))
import worldbox_raw_leads as scan
from test_worldbox_native import fixture


class RawLeadTest(unittest.TestCase):
    def test_ascii_utf16_and_overlapping_categories(self):
        data = b'preMIUM' + 'GLOBAL-METADATA.DAT'.encode('utf-16le') + 'Premium'.encode('utf-16be')
        found = scan.scan_bytes(data)
        self.assertEqual(found[('premium-keyword', 'ascii')]['count'], 1)
        self.assertEqual(found[('premium-keyword', 'utf16be')]['count'], 1)
        self.assertEqual(found[('global-metadata-name', 'utf16le')]['count'], 1)
        self.assertEqual(found[('metadata-name', 'utf16le')]['count'], 1)
        self.assertEqual(found[('metadata-name', 'ascii')]['count'], 0)

    def test_bounded_examples_but_count_all(self):
        found = scan.scan_bytes(b'premium!' * 10)[('premium-keyword', 'ascii')]
        self.assertEqual(found['count'], 10)
        self.assertEqual(found['offsets'], [0, 8, 16, 24])

    def test_synthetic_elf_maps_offsets(self):
        data = fixture()
        # Header padding is unallocated and should still be found.
        data[9:16] = b'premium'
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory) / 'fixture.so'
            p.write_bytes(data)
            result = scan.inspect(p)
        row = next(r for r in result['results'] if r['category'] == 'premium-keyword' and r['encoding'] == 'ascii')
        self.assertEqual(row['count'], 1)
        self.assertEqual(row['samples'][0]['fileOffset'], '0x9')
        self.assertEqual(row['samples'][0]['sectionMappings'], [])
        self.assertEqual(result['scannedBytes'], len(data))
        self.assertFalse(result['truncated'])

    def test_section_mapping_requires_full_containment(self):
        section = {'sh_offset': 100, 'sh_size': 10, 'sh_type': 'SHT_PROGBITS',
                   'sh_flags': 2, 'sh_addr': 0x5000}
        matches, truncated = scan.section_location([section], 102, 7)
        self.assertEqual(matches[0]['vaddr'], '0x5002')
        self.assertFalse(truncated)
        self.assertEqual(scan.section_location([section], 108, 3)[0], [])

    def test_reject_non_arm64(self):
        data = fixture()
        struct.pack_into('<H', data, 18, 62)
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory) / 'fixture.so'
            p.write_bytes(data)
            with self.assertRaises(ValueError):
                scan.inspect(p)

if __name__ == '__main__':
    unittest.main()

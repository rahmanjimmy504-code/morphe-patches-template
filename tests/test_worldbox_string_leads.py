"""Synthetic tests for bounded keyword leads; no game input needed."""
from pathlib import Path
import struct
import io
import tempfile
from elftools.elf.elffile import ELFFile
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / '.github/scripts'))
import worldbox_string_leads as leads
from test_worldbox_native import fixture


def words(*items):
    return b''.join(struct.pack('<I', i) for i in items)


class LeadTests(unittest.TestCase):
    def test_ascii_and_case_and_keyword_pointer(self):
        data = b'\0x/PremiumFeature\0global-metadata.dat\0PREMIUM\0no end premium'
        rows = leads.matches(data, 0x5000)
        self.assertEqual(rows['premium-keyword'], [(0x5001, 0x5003), (0x5026, 0x5026)])
        self.assertEqual(rows['metadata-name'], [(0x5012, 0x5012)])

    def test_long_and_unterminated_are_not_reported(self):
        self.assertEqual(leads.matches(b'a' * 600 + b'premium\0', 0)['premium-keyword'], [])
        self.assertEqual(leads.matches(b'premium', 0)['premium-keyword'], [])

    def test_reference_and_clobber(self):
        # adrp x16,0x5000 at 0x2000; add x0,x16,#0x10
        adrp = 0x90000000 | (3 << 29) | 16
        add = 0x91000000 | (0x10 << 10) | (16 << 5)
        count, sites = leads.reference_pairs(words(adrp, add), 0x2000, {0x5010})
        self.assertEqual(count[0x5010], 1)
        self.assertEqual(sites[0x5010][0]['add'], '0x2004')
        clobber = 0x91000000 | (4 << 10) | (16 << 5) | 16
        count, _ = leads.reference_pairs(words(adrp, clobber, add), 0x2000, {0x5010})
        self.assertEqual(count[0x5010], 0)

    def test_real_elf_scan_and_xref(self):
        data = fixture()
        elf = ELFFile(io.BytesIO(data))
        strings = elf.get_section_by_name('.shstrtab')
        text = elf.get_section_by_name('.text')
        relative = strings.data().find(b'.init_array')
        self.assertGreater(relative, 0)
        offset = strings['sh_offset'] + relative
        data[offset:offset + 11] = b'premiumxxxx'
        # Make the synthetic string table allocated at 0x5000.
        shoff = elf['e_shoff'] + elf['e_shentsize']  # section 1
        struct.pack_into('<Q', data, shoff + 8, 2)
        struct.pack_into('<Q', data, shoff + 16, 0x5000)
        adrp = 0x90000000 | (2 << 29) | 16  # 0x3000 -> 0x5000
        add = 0x91000000 | (relative << 10) | (16 << 5)
        struct.pack_into('<II', data, text['sh_offset'], adrp, add)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'fixture.so'
            path.write_bytes(data)
            report = leads.inspect(path)
        row = report['categories']['premium-keyword']['entries'][0]
        self.assertEqual(row['stringStart'], hex(0x5000 + relative))
        self.assertEqual(row['startRefs'], 1)
        self.assertEqual(row['startSamples'][0]['add'], '0x3004')
        self.assertEqual(report['categories']['metadata-name']['matches'], 0)

    def test_limit_does_not_hide_count(self):
        rows = leads.matches(b'premium\0' * 40, 0)
        self.assertEqual(len(rows['premium-keyword']), 40)

if __name__ == '__main__':
    unittest.main()

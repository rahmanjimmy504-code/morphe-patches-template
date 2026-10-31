"""Synthetic tests for bounded direct-caller triage, not game binaries."""
from pathlib import Path
import io
import json
import struct
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.github/scripts'))
sys.path.insert(0, str(ROOT / 'tests'))
from elftools.elf.elffile import ELFFile
import worldbox_upstream as upstream
from test_worldbox_native import fixture


class UpstreamTest(unittest.TestCase):
    def inspect_fixture(self, data, target):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'fixture.so'
            path.write_bytes(data)
            return upstream.inspect(path, target)

    def test_direct_call_and_entry_argument(self):
        report = self.inspect_fixture(fixture(via_helper=True, eh_frame=True, split_frames=True), 0x3040)
        self.assertEqual(report['directCalls'], 1)
        self.assertEqual(report['directTailBranches'], 0)
        self.assertFalse(report['execTruncated'])
        self.assertEqual(report['unwindStatus'], 'parsed')
        self.assertEqual(report['examples'][0]['site'], '0x3000')
        self.assertEqual(report['examples'][0]['x0'], ['entry-argument-0'])
        self.assertTrue(report['examples'][0]['reachedInModel'])
        payloads = upstream.annotation_payloads(report)
        self.assertEqual(len(payloads), 2)
        self.assertTrue(all(len(item) <= 3800 for item in payloads))
        self.assertEqual(json.loads(payloads[1])['site'], '0x3000')

    def test_prior_call_result_is_attributed_without_claiming_value(self):
        report = self.inspect_fixture(fixture(eh_frame=True, origin_helper=True), 0x3040)
        row = report['examples'][0]
        self.assertEqual(row['x0'], ['x0-after-call@0x3000'])
        self.assertEqual(row['x0CallOrigins'][0]['target'], '0x3080')
        self.assertIsNone(row['x0CallOrigins'][0]['recognizedApi'])

    def test_tail_branch_and_missing_unwind_are_explicit(self):
        data = fixture(via_helper=True)
        text = ELFFile(io.BytesIO(data)).get_section_by_name('.text')
        word = 0x14000000 | (((0x3040 - 0x3000) // 4) & 0x03ffffff)
        struct.pack_into('<I', data, text['sh_offset'], word)
        report = self.inspect_fixture(data, 0x3040)
        self.assertEqual(report['directCalls'], 0)
        self.assertEqual(report['directTailBranches'], 1)
        self.assertEqual(report['examples'][0]['status'], 'no-unwind-range')

    def test_rejects_other_architecture(self):
        data = fixture()
        data[18:20] = struct.pack('<H', 62)
        with self.assertRaisesRegex(ValueError, 'AArch64'):
            self.inspect_fixture(data, 0x3040)

if __name__ == '__main__':
    unittest.main()

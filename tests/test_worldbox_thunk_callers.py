"""Synthetic-only tests for bounded ARM64 thunk references and data summaries."""
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.github/scripts'))
sys.path.insert(0, str(ROOT / 'tests'))
from elftools.elf.elffile import ELFFile

import worldbox_thunk_callers as thunks
from test_worldbox_native import fixture


class ThunkReferenceTest(unittest.TestCase):
    def test_direct_call_and_tail_branch_are_counted_separately(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'fixture.so'
            path.write_bytes(fixture(eh_frame=True, origin_helper=True, helper_calls_import=True))
            report = thunks.reference_report(path, thunks=(0x2020, 0x2000),
                                            static_addresses=(0x1000,))
        self.assertEqual(report['unwindStatus'], 'parsed')
        self.assertEqual(report['thunks']['0x2020']['directCalls'], 1)
        self.assertEqual(report['thunks']['0x2020']['sampleSites'][0]['site'], '0x3080')
        self.assertEqual(report['thunks']['0x2000']['tailBranches'], 1)
        self.assertEqual(report['thunks']['0x2000']['sampleSites'][0]['site'], '0x3040')
        self.assertEqual(report['thunks']['0x2000']['sampleSites'][0]['function'], '0x3040')

    def test_static_data_summary_is_bounded_and_uses_safe_categories(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'fixture.so'
            path.write_bytes(fixture(eh_frame=True))
            report = thunks.reference_report(path, thunks=(0x2020,),
                                            static_addresses=(0x1000,))
        row = report['staticData'][0]
        self.assertEqual(row['address'], '0x1000')
        self.assertEqual(row['section'], '.dynstr')
        self.assertEqual(row['status'], 'read')
        self.assertEqual(row['bytesRead'], 6)
        self.assertEqual(row['printablePrefixLength'], 0)
        self.assertIsNone(row['stringCategory'])
        self.assertFalse(row['executable'])

    def test_pointer_description_names_the_containing_section(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'fixture.so'
            path.write_bytes(fixture(eh_frame=True))
            with path.open('rb') as f:
                sections = thunks.allocated_sections(ELFFile(f))
                described = thunks.describe_pointer(0x3000, sections)
        self.assertEqual(described['section'], '.text')
        self.assertEqual(described['offset'], '0x0')
        self.assertTrue(described['executable'])


if __name__ == '__main__':
    unittest.main()

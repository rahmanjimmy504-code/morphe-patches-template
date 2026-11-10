"""Synthetic-only tests for bounded adjacent-thunk reference reports."""
import io
from pathlib import Path
import struct
import sys
import tempfile
import unittest

from elftools.elf.elffile import ELFFile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.github/scripts'))
sys.path.insert(0, str(ROOT / 'tests'))
import worldbox_adjacent_thunks as probe
from test_worldbox_native import fixture


def patched_fixture():
    data = bytearray(fixture(eh_frame=True, via_helper=True))
    with ELFFile(io.BytesIO(data)) as elf:
        text = elf.get_section_by_name('.text')
        offset = text['sh_offset']
    data[offset:offset + 4] = struct.pack('<I', 0x17FFFC08)  # b #0x2020
    return bytes(data)


class AdjacentThunkProbeTest(unittest.TestCase):
    def test_tail_branch_is_attributed_to_caller_fde(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'fixture.so'
            path.write_bytes(patched_fixture())
            report = probe.reference_report(path, thunks=(0x2020,))
        row = report['rows'][0]
        self.assertEqual(row['target'], '0x2020')
        self.assertIsNone(row['fdeStart'])
        self.assertGreaterEqual(row['xrefs']['directTailBranches'], 1)
        self.assertEqual(row['tailSamples'][0]['site'], '0x3000')
        self.assertEqual(row['tailSamples'][0]['function'], '0x3000')
        self.assertEqual(row['fdeReports'][0]['entry'], '0x3000')
        self.assertFalse(row['fdeReportsTruncated'])

    def test_target_inside_fde_reports_its_exact_start(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'fixture.so'
            path.write_bytes(fixture(eh_frame=True, via_helper=True))
            report = probe.reference_report(path, thunks=(0x3000,))
        row = report['rows'][0]
        self.assertEqual(row['fdeStart'], '0x3000')
        self.assertEqual(row['fdeSize'], 72)
        self.assertEqual(row['fdeReports'][0]['entry'], '0x3000')

    def test_default_targets_are_the_two_adjacent_thunks(self):
        self.assertEqual(probe.THUNKS, (0x3ae2828, 0x3ae2594))

    def test_branch_destinations_are_accepted_as_custom_targets(self):
        self.assertEqual(probe.BRANCH_DESTINATIONS, (0x1890260, 0x3adec0c))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'fixture.so'
            path.write_bytes(fixture(eh_frame=True, via_helper=True))
            report = probe.reference_report(path, thunks=probe.BRANCH_DESTINATIONS,
                                            kind='worldbox-branch-destination-probe')
        self.assertEqual(report['kind'], 'worldbox-branch-destination-probe')
        self.assertEqual(report['targets'], ['0x1890260', '0x3adec0c'])
        self.assertEqual(len(report['rows']), 2)

    def test_file_adapter_callee_targets_and_trace_targets_are_bounded(self):
        self.assertEqual(probe.FILE_ADAPTER_TARGETS,
                         (0x1890260, 0x18eb7a4, 0x18edbb8))
        self.assertEqual(len(probe.FILE_ADAPTER_TRACE_TARGETS), 13)
        self.assertIn('0x18eb7a4', probe.FILE_ADAPTER_TRACE_TARGETS)
        self.assertIn('0x18edbb8', probe.FILE_ADAPTER_TRACE_TARGETS)
        self.assertIn('0x3bf90c0', probe.FILE_ADAPTER_TRACE_TARGETS)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'fixture.so'
            path.write_bytes(fixture(eh_frame=True, via_helper=True))
            report = probe.reference_report(path, thunks=probe.FILE_ADAPTER_TARGETS,
                                            kind=probe.FILE_ADAPTER_KIND)
        self.assertEqual(report['kind'], probe.FILE_ADAPTER_KIND)
        self.assertEqual(report['targets'],
                         ['0x1890260', '0x18eb7a4', '0x18edbb8'])
        self.assertEqual(len(report['rows']), 3)


if __name__ == '__main__':
    unittest.main()

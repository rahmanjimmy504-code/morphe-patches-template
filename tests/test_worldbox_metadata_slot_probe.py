"""Synthetic-only tests for bounded metadata pointer-slot consumer probes."""
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
import worldbox_metadata_slot_probe as probe
from test_worldbox_native import fixture


def patched_fixture():
    """Put ADRP+ADD and ADRP+LDR slot consumers into the synthetic .text FDE."""
    data = bytearray(fixture(eh_frame=True, via_helper=True))
    with ELFFile(io.BytesIO(data)) as elf:
        text = elf.get_section_by_name('.text')
        offset, size = text['sh_offset'], text['sh_size']
    assert size >= 28
    words = [
        0xF0000000,  # adrp x0, 0x6000
        0x91000000,  # add x0, x0, #0
        0xF9400001,  # ldr x1, [x0]
        0xD65F03C0,  # ret
        0xF0000002,  # adrp x2, 0x6000
        0xF9400043,  # ldr x3, [x2]
        0xD65F03C0,  # ret
    ]
    data[offset:offset + 4 * len(words)] = struct.pack('<%dI' % len(words), *words)
    return bytes(data)


class MetadataSlotProbeTest(unittest.TestCase):
    def test_adrp_add_and_adrp_ldr_consumers_are_attributed_to_one_fde(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'fixture.so'
            path.write_bytes(patched_fixture())
            report = probe.slot_reference_report(path, slots=(0x6000,))
        row = report['rows'][0]
        self.assertEqual(row['slot'], '0x6000')
        self.assertGreaterEqual(row['xrefs']['pcRelativeAddressPairs'], 1)
        self.assertGreaterEqual(len(row['adrpAddSamples']), 1)
        self.assertGreaterEqual(len(row['adrpLdrSamples']), 1)
        self.assertEqual(row['adrpAddSamples'][0]['function'], '0x3000')
        self.assertEqual(row['adrpLdrSamples'][0]['function'], '0x3000')
        self.assertEqual(row['fdeReports'][0]['entry'], '0x3000')
        self.assertGreaterEqual(row['fdeReports'][0]['decodedInstructions'], 7)

    def test_slot_load_scan_reports_bounded_executable_coverage(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'fixture.so'
            path.write_bytes(patched_fixture())
            report = probe.slot_reference_report(path, slots=(0x6000,))
        scan = report['slotLoadScan']
        self.assertEqual(scan['execTruncated'], False)
        self.assertEqual(scan['executableBytes'], scan['executableScanned'])

    def test_report_includes_three_real_slot_addresses_by_default(self):
        self.assertEqual(probe.SLOTS, (0x40f1f70, 0x40f1f78, 0x3e45c38))


if __name__ == '__main__':
    unittest.main()

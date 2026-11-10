"""Synthetic tests for bounded indirect/GOT-mediated slot load modeling."""
import contextlib
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
import worldbox_indirect_slot_probe as probe
from test_worldbox_native import fixture


def adrp(register, target_page, pc):
    imm = (target_page - (pc & ~0xfff)) >> 12
    return 0x90000000 | ((imm & 3) << 29) | (((imm >> 2) & 0x7ffff) << 5) | register


def ldr(rt, rn, displacement):
    return 0xf9400000 | ((displacement // 8) << 10) | (rn << 5) | rt


def synthetic_indirect_fixture():
    data = bytearray(fixture(eh_frame=True, via_helper=True))
    with ELFFile(io.BytesIO(data)) as elf:
        text = elf.get_section_by_name('.text')
        text_offset = text['sh_offset']
        init_array = elf.get_section_by_name('.init_array')
        init_offset = init_array['sh_offset']
    words = [
        adrp(0, 0x6000, 0x3000),
        ldr(1, 0, 0),
        ldr(2, 1, 8),
        0xd63f0040,  # blr x2
        0xd65f03c0,  # ret
    ]
    words += [0xd503201f] * (18 - len(words))  # NOP to fill the 72-byte FDE
    data[text_offset:text_offset + 72] = struct.pack('<18I', *words)
    data[init_offset:init_offset + 8] = struct.pack('<Q', 0x6000)
    return bytes(data)


class IndirectSlotProbeTest(unittest.TestCase):
    def test_got_load_slot_load_and_indirect_call_are_attributed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'fixture.so'
            path.write_bytes(synthetic_indirect_fixture())
            report = probe.indirect_slot_report(path, slots=(0x6008,), window=0x1000)
        self.assertEqual(report['kind'], probe.KIND)
        row = report['rows'][0]
        self.assertEqual(row['slot'], '0x6008')
        self.assertGreaterEqual(row['dataPointerCount'], 1)
        self.assertEqual(row['consumerCounts']['gotLoadCount'], 1)
        self.assertEqual(row['consumerCounts']['slotLoadCount'], 1)
        self.assertEqual(row['consumerCounts']['indirectCallCount'], 1)
        self.assertEqual(row['gotLoadSamples'][0]['gotLocation'], '0x6000')
        self.assertEqual(row['gotLoadSamples'][0]['function'], '0x3000')
        self.assertEqual(row['slotLoadSamples'][0]['site'], '0x3008')
        self.assertEqual(row['indirectCallSamples'][0]['site'], '0x300c')
        self.assertEqual(row['fdeReports'][0]['entry'], '0x3000')

    def test_annotations_emit_bounded_counts_and_no_literal_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'fixture.so'
            path.write_bytes(synthetic_indirect_fixture())
            report = probe.indirect_slot_report(path, slots=(0x6008,), window=0x1000)
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            probe.emit_indirect_slot_annotations(report)
        output = buffer.getvalue()
        self.assertIn('WorldBox full indirect slot report:', output)
        self.assertIn('::warning title=WorldBox indirect slot summary::', output)
        self.assertIn('::warning title=WorldBox indirect slot consumers 0x6008::', output)
        self.assertIn('"indirectCallCount":1', output)
        self.assertNotIn('open', output)

    def test_no_candidate_window_reports_zero_consumers(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'fixture.so'
            path.write_bytes(synthetic_indirect_fixture())
            report = probe.indirect_slot_report(path, slots=(0x9000,), window=0x1000)
        row = report['rows'][0]
        self.assertEqual(row['dataPointerCount'], 0)
        self.assertEqual(row['consumerCounts'],
                         {'gotLoadCount': 0, 'slotLoadCount': 0, 'indirectCallCount': 0})
        self.assertFalse(report['dataScan']['candidateLocationsTruncated'])


if __name__ == '__main__':
    unittest.main()

"""Synthetic tests for safe bounded static-literal descriptors."""
import contextlib
import hashlib
import io
from pathlib import Path
import sys
import tempfile
import unittest

from elftools.elf.elffile import ELFFile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.github/scripts'))
sys.path.insert(0, str(ROOT / 'tests'))
import worldbox_static_literal_probe as probe
from test_worldbox_native import fixture


def patched_fixture(replacement=None):
    data = bytearray(fixture())
    with ELFFile(io.BytesIO(data)) as elf:
        section = elf.get_section_by_name('.dynstr')
        offset = section['sh_offset']
    if replacement is not None:
        data[offset + 1:offset + 1 + len(replacement)] = replacement
    return bytes(data)


class StaticLiteralProbeTest(unittest.TestCase):
    def test_ascii_literal_descriptor_omits_content(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'fixture.so'
            path.write_bytes(fixture())
            report = probe.literal_report(path, address=0x1001)
        self.assertEqual(report['kind'], probe.STATIC_LITERAL_KIND)
        self.assertEqual(report['status'], 'ok')
        self.assertEqual(report['sectionName'], '.dynstr')
        self.assertEqual(report['byteLength'], 4)
        self.assertTrue(report['zeroTerminated'])
        self.assertTrue(report['printableAscii'])
        self.assertEqual(report['literalSha256'], hashlib.sha256(b'open').hexdigest())
        self.assertFalse(report['matchesMetadataPathNeedle'])
        self.assertEqual(set(report['needleLabels']),
                         {'metadata_filename', 'unity_metadata_path', 'metadata_relative_path'})
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            probe.emit_literal_annotations(report)
        output = buffer.getvalue()
        self.assertIn('::warning title=WorldBox static literal descriptor::', output)
        self.assertNotIn('open', output)

    def test_custom_needle_match_is_detected_without_printing_needle(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'fixture.so'
            path.write_bytes(fixture())
            report = probe.literal_report(path, address=0x1001,
                                          needles={'short_label': 'open'})
        self.assertTrue(report['needleRelations']['short_label']['literalEqualsNeedle'])
        self.assertTrue(report['matchesMetadataPathNeedle'])
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            probe.emit_literal_annotations(report)
        self.assertNotIn('open', buffer.getvalue())

    def test_nonprintable_bytes_are_categorized_without_content(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'fixture.so'
            path.write_bytes(patched_fixture(b'\xffpen'))
            report = probe.literal_report(path, address=0x1001)
        self.assertEqual(report['byteLength'], 4)
        self.assertFalse(report['printableAscii'])
        self.assertEqual(report['nonPrintableByteCount'], 1)
        self.assertEqual(report['literalCategory'], 'mixed-bytes')
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            probe.emit_literal_annotations(report)
        self.assertNotIn('pen', buffer.getvalue())

    def test_missing_address_returns_bounded_status(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'fixture.so'
            path.write_bytes(fixture())
            report = probe.literal_report(path, address=0xf00000)
        self.assertEqual(report['status'], 'not-found')
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            probe.emit_literal_annotations(report)
        self.assertIn('::notice title=WorldBox static literal unavailable::', buffer.getvalue())


if __name__ == '__main__':
    unittest.main()

"""Synthetic coverage for the bounded metadata string-neighborhood probe."""
import contextlib
import hashlib
import io
import struct
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.github/scripts'))
import worldbox_metadata_string_neighborhood as probe

UNKNOWN = b'unknownSecretToken'


def fixture():
    anchor = 64
    data = bytearray(b'\0' * anchor)
    data += b'premium_unlocked\0'
    data += b'PremiumWindow\0' + UNKNOWN + b'\0'
    while len(data) % 4:
        data += b'\0'
    token = b'premium_unlocked'
    data += struct.pack('<I', len(token)) + token + b'\0'
    while len(data) % 4:
        data += b'\0'
    data += struct.pack('<I', anchor)
    return bytes(data), anchor


class MetadataStringNeighborhoodTest(unittest.TestCase):
    def test_bounded_report_and_annotations_hash_unknown_strings(self):
        data, anchor = fixture()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'global-metadata.dat'
            path.write_bytes(data)
            sha = hashlib.sha256(data).hexdigest()
            report = probe.neighborhood_report(
                path, expected_sha=sha, expected_anchor=anchor, radius=256)
            self.assertEqual(report['kind'], probe.KIND)
            self.assertEqual(report['anchor']['expectedAnchor'], hex(anchor))
            self.assertTrue(report['anchor']['anchorNulTerminated'])
            self.assertGreaterEqual(report['tokens']['count'], 4)
            self.assertGreaterEqual(report['tokens']['safeKnownCount'], 2)
            self.assertGreaterEqual(report['lengthPrefixes']['count'], 1)
            self.assertGreaterEqual(
                report['alignedU32']['counts']['anchorAbsoluteValue'], 1)
            buffer = io.StringIO()
            with contextlib.redirect_stdout(buffer):
                probe.emit_neighborhood_annotations(report)
            output = buffer.getvalue()
            self.assertIn('::warning title=WorldBox metadata string neighborhood summary::', output)
            self.assertIn('::notice title=WorldBox metadata string neighborhood tokens::', output)
            self.assertNotIn(UNKNOWN.decode(), output)
            for line in output.splitlines():
                if line.startswith('::'):
                    self.assertLessEqual(len(line), 4096)
            with self.assertRaises(ValueError):
                probe.neighborhood_report(path, expected_sha='0' * 64,
                                          expected_anchor=anchor, radius=256)

    def test_anchor_mismatch_refuses_analysis(self):
        data = b'no expected anchor\0' + b'other\0'
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'global-metadata.dat'
            path.write_bytes(data)
            with self.assertRaises(ValueError):
                probe.neighborhood_report(path, expected_sha=None,
                                          expected_anchor=64, radius=32)

    def test_token_descriptor_never_returns_unknown_literal(self):
        self.assertEqual(probe.token_descriptor('premium_unlocked'),
                         {'safe': 'premium_unlocked'})
        self.assertNotIn('unknownSecretToken',
                         str(probe.token_descriptor('unknownSecretToken')))
        self.assertEqual(len(probe.token_descriptor('unknownSecretToken')['sha256']), 64)


if __name__ == '__main__':
    unittest.main()

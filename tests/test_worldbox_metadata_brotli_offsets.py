"""Synthetic tests for safe bounded Brotli start-offset trials."""
import contextlib
import hashlib
import io
from pathlib import Path
import struct
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.github/scripts'))
import brotli
import worldbox_metadata_brotli_offsets as probe


STANDARD_MAGIC = 0xFAB11BAF
EXPECTED_VERSION = 31


def standard_data():
    words = [STANDARD_MAGIC, EXPECTED_VERSION, 16, 32, 0, 0]
    return struct.pack('<6I', *words) + bytes(4096)


def write_metadata(directory, data):
    path = Path(directory) / 'global-metadata.dat'
    path.write_bytes(data)
    return path, hashlib.sha256(data).hexdigest()


class MetadataBrotliOffsetsTest(unittest.TestCase):
    def test_candidate_after_custom_header_with_trailing_bytes(self):
        raw = standard_data()
        data = bytes(16) + brotli.compress(raw) + b'TRAILING' * 8
        with tempfile.TemporaryDirectory() as directory:
            path, sha = write_metadata(directory, data)
            report = probe.offset_report(path, expected_sha=sha,
                                         expected_size=len(data),
                                         offsets=range(0, 64))
        self.assertEqual(report['kind'], probe.KIND)
        self.assertEqual(report['offsetPolicy']['offsetCount'], 64)
        candidates = [item for item in report['candidates']
                      if item['offset'] == hex(16)]
        self.assertEqual(len(candidates), 1)
        full = candidates[0]['full']
        self.assertEqual(full['status'], 'decompressed')
        self.assertEqual(full['decompressedBytes'], len(raw))
        self.assertEqual(full['decompressedSha256'], hashlib.sha256(raw).hexdigest())
        self.assertTrue(full['magicMatchesStandard'])
        self.assertTrue(full['versionMatches31'])
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            probe.emit_offset_annotations(report)
        output = buffer.getvalue()
        self.assertIn('::warning title=WorldBox metadata Brotli offsets summary::', output)
        self.assertIn('::warning title=WorldBox metadata Brotli offsets candidate 0x10::', output)
        self.assertNotIn('DO-NOT-EMIT-LITERAL', output)

    def test_invalid_data_produces_no_candidates(self):
        data = b'not a brotli stream' + bytes(4096)
        with tempfile.TemporaryDirectory() as directory:
            path, sha = write_metadata(directory, data)
            report = probe.offset_report(path, expected_sha=sha,
                                         expected_size=len(data),
                                         offsets=range(0, 32))
        self.assertEqual(report['candidateCount'], 0)
        self.assertEqual(report['metadataHeaderCandidateCount'], 0)
        self.assertGreater(report['prefixStatuses'].get('invalid', 0), 0)
        self.assertEqual(report['fullStatuses'], {})

    def test_full_output_cap_is_enforced(self):
        raw = standard_data()
        data = brotli.compress(raw)
        with tempfile.TemporaryDirectory() as directory:
            path, sha = write_metadata(directory, data)
            report = probe.offset_report(path, expected_sha=sha,
                                         expected_size=len(data),
                                         offsets=(0,), max_full_output=64)
        self.assertEqual(report['candidateCount'], 1)
        self.assertEqual(report['candidates'][0]['full']['status'],
                         'output-cap-exceeded')

    def test_hash_gate_rejects_mismatched_metadata(self):
        data = bytes(16) + brotli.compress(standard_data())
        with tempfile.TemporaryDirectory() as directory:
            path, _sha = write_metadata(directory, data)
            with self.assertRaises(ValueError):
                probe.offset_report(path, expected_sha='0' * 64,
                                    expected_size=len(data), offsets=(0,))


if __name__ == '__main__':
    unittest.main()

"""Synthetic tests for safe metadata decompression trials."""
import contextlib
import gzip
import hashlib
import io
from pathlib import Path
import struct
import sys
import tempfile
import unittest
import zlib

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.github/scripts'))
import brotli
import worldbox_metadata_stream_probe as probe


def standard_data():
    words = [probe.STANDARD_MAGIC, probe.EXPECTED_VERSION, 16, 32, 0, 0]
    return struct.pack('<6I', *words) + bytes(4096)


def raw_deflate(data):
    compressor = zlib.compressobj(wbits=-zlib.MAX_WBITS)
    return compressor.compress(data) + compressor.flush()


def write_metadata(directory, data):
    path = Path(directory) / 'global-metadata.dat'
    path.write_bytes(data)
    return path, hashlib.sha256(data).hexdigest()


class MetadataStreamProbeTest(unittest.TestCase):
    def assert_standard_output(self, row, expected_size):
        self.assertEqual(row['status'], 'decompressed')
        self.assertEqual(row['decompressedBytes'], expected_size)
        self.assertTrue(row['magicMatchesStandard'])
        self.assertTrue(row['versionMatches31'])
        self.assertEqual(row['headerNumericFields']['word0'], probe.STANDARD_MAGIC)
        self.assertGreater(row['entropyFirst4096'], 0)

    def test_brotli_trial_detects_standard_header(self):
        raw = standard_data()
        with tempfile.TemporaryDirectory() as directory:
            path, sha = write_metadata(directory, brotli.compress(raw))
            report = probe.stream_report(path, expected_sha=sha,
                                         expected_size=path.stat().st_size)
        self.assert_standard_output(report['codecs']['brotli'], len(raw))
        self.assertEqual(report['codecs']['brotli']['decompressedSha256'],
                         hashlib.sha256(raw).hexdigest())
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            probe.emit_stream_annotations(report)
        output = buffer.getvalue()
        self.assertIn('::warning title=WorldBox metadata stream brotli::', output)
        self.assertNotIn('DO-NOT-EMIT', output)

    def test_zlib_gzip_and_raw_deflate_trials(self):
        raw = standard_data()
        codecs = {'zlib': zlib.compress(raw),
                  'gzip': gzip.compress(raw),
                  'raw-deflate': raw_deflate(raw)}
        with tempfile.TemporaryDirectory() as directory:
            for name, data in codecs.items():
                path, sha = write_metadata(directory, data)
                report = probe.stream_report(path, expected_sha=sha,
                                             expected_size=len(data))
                self.assert_standard_output(report['codecs'][name], len(raw))

    def test_invalid_stream_statuses_and_no_raw_bytes(self):
        data = b'not a compressed stream' + b'DO-NOT-EMIT-LITERAL'
        with tempfile.TemporaryDirectory() as directory:
            path, sha = write_metadata(directory, data)
            report = probe.stream_report(path, expected_sha=sha,
                                         expected_size=len(data))
        for row in report['codecs'].values():
            self.assertIn(row['status'], ('invalid', 'truncated', 'output-cap-exceeded'))
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            probe.emit_stream_annotations(report)
        output = buffer.getvalue()
        self.assertNotIn('DO-NOT-EMIT-LITERAL', output)

    def test_output_cap_is_enforced(self):
        raw = bytes(4096)
        with tempfile.TemporaryDirectory() as directory:
            path, sha = write_metadata(directory, brotli.compress(raw))
            report = probe.stream_report(path, expected_sha=sha,
                                         expected_size=path.stat().st_size,
                                         max_output=64)
        self.assertEqual(report['codecs']['brotli']['status'], 'output-cap-exceeded')

    def test_hash_gate_rejects_mismatched_metadata(self):
        data = standard_data()
        with tempfile.TemporaryDirectory() as directory:
            path, _sha = write_metadata(directory, data)
            with self.assertRaises(ValueError):
                probe.stream_report(path, expected_sha='0' * 64,
                                    expected_size=len(data))


if __name__ == '__main__':
    unittest.main()

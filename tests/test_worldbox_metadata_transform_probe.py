"""Synthetic tests for the safe metadata constant-transform probe."""
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
import worldbox_metadata_transform_probe as probe


PADDED_SIZE = 4096


def plain_header(total_size=PADDED_SIZE):
    words = [probe.STANDARD_MAGIC, probe.EXPECTED_VERSION]
    for index in range(31):
        words.extend((8 + index * 16, 8))
    header = struct.pack('<64I', *words)
    return header + bytes(max(0, total_size - len(header)))


def pad_header(header, total_size=PADDED_SIZE):
    return header + bytes(max(0, total_size - len(header)))


def write_metadata(directory, data):
    path = Path(directory) / 'global-metadata.dat'
    path.write_bytes(data)
    return path, hashlib.sha256(data).hexdigest()


class MetadataTransformProbeTest(unittest.TestCase):
    def test_standard_header_reports_matching_constant_keys(self):
        data = plain_header()
        with tempfile.TemporaryDirectory() as directory:
            path, sha = write_metadata(directory, data)
            report = probe.transform_report(path, expected_sha=sha,
                                            expected_size=len(data))
        self.assertEqual(report['kind'], probe.KIND)
        self.assertEqual(report['status'], 'ok')
        self.assertTrue(report['constant32BitXor']['keysMatch'])
        self.assertTrue(report['constant32BitAdditive']['deltasMatch'])
        self.assertTrue(report['constant32BitSubtractive']['deltasMatch'])
        self.assertTrue(report['repeating4ByteXor']['keysMatch'])
        self.assertTrue(report['repeating4ByteXor']['versionMatchesExpected'])
        self.assertGreaterEqual(
            report['repeating4ByteXor']['transformedPairStats']['boundedPairCount'], 30)

    def test_constant_xor_header_is_detected_without_raw_bytes(self):
        key = 0x12345678
        words = list(struct.unpack_from('<64I', plain_header()))
        words = [value ^ key for value in words]
        data = pad_header(struct.pack('<64I', *words)) + b'DO-NOT-EMIT-LITERAL'
        with tempfile.TemporaryDirectory() as directory:
            path, sha = write_metadata(directory, data)
            report = probe.transform_report(path, expected_sha=sha,
                                            expected_size=len(data))
        self.assertTrue(report['constant32BitXor']['keysMatch'])
        self.assertGreaterEqual(
            report['constant32BitXor']['transformedPairStats']['boundedPairCount'], 30)
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            probe.emit_transform_annotations(report)
        output = buffer.getvalue()
        self.assertIn('::warning title=WorldBox metadata transform summary::', output)
        self.assertNotIn('DO-NOT-EMIT-LITERAL', output)
        self.assertNotIn('af1bb1fa', output.lower())

    def test_constant_additive_header_is_detected(self):
        delta = 0x11111111
        words = list(struct.unpack_from('<64I', plain_header()))
        words = [(value + delta) & probe.MASK32 for value in words]
        data = pad_header(struct.pack('<64I', *words))
        with tempfile.TemporaryDirectory() as directory:
            path, sha = write_metadata(directory, data)
            report = probe.transform_report(path, expected_sha=sha,
                                            expected_size=len(data))
        self.assertTrue(report['constant32BitAdditive']['deltasMatch'])
        self.assertGreaterEqual(
            report['constant32BitAdditive']['transformedPairStats']['boundedPairCount'], 30)

    def test_nonmatching_header_has_no_constant_transform(self):
        data = bytes(range(256))
        with tempfile.TemporaryDirectory() as directory:
            path, sha = write_metadata(directory, data)
            report = probe.transform_report(path, expected_sha=sha,
                                            expected_size=len(data))
        self.assertFalse(report['constant32BitXor']['keysMatch'])
        self.assertFalse(report['constant32BitAdditive']['deltasMatch'])
        self.assertFalse(report['repeating4ByteXor']['keysMatch'])
        self.assertIsNone(report['repeating4ByteXor']['transformedPairStats'])

    def test_hash_gate_rejects_mismatched_metadata(self):
        data = plain_header()
        with tempfile.TemporaryDirectory() as directory:
            path, _sha = write_metadata(directory, data)
            with self.assertRaises(ValueError):
                probe.transform_report(path, expected_sha='0' * 64,
                                       expected_size=len(data))


if __name__ == '__main__':
    unittest.main()

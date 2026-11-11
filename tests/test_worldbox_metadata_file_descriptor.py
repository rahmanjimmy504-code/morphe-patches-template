"""Synthetic tests for the safe global-metadata.dat APK-entry descriptor."""
import contextlib
import hashlib
import io
from pathlib import Path
import struct
import sys
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.github/scripts'))
import worldbox_metadata_file_descriptor as probe


def make_apk(path: Path, payload: bytes, entry=probe.EXPECTED_ENTRY):
    with zipfile.ZipFile(path, 'w', zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(entry, payload)
    return hashlib.sha256(path.read_bytes()).hexdigest()


def standard_payload():
    body = bytearray(bytes(range(256)) * 32)
    body[:8] = probe.STANDARD_LE + struct.pack('<I', probe.EXPECTED_METADATA_VERSION)
    body[1000:1020] = b'DO-NOT-EMIT-LITERAL'
    body[2000:2004] = probe.STANDARD_LE
    return bytes(body)


class MetadataFileDescriptorTest(unittest.TestCase):
    def test_standard_header_and_safe_descriptor(self):
        payload = standard_payload()
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            apk = directory / 'base.apk'
            expected_hash = make_apk(apk, payload)
            extracted = directory / 'global-metadata.dat'
            extracted.write_bytes(payload)
            report = probe.metadata_file_report(apk, extracted,
                                                expected_base_hash=expected_hash,
                                                expected_size=len(payload))
        self.assertEqual(report['kind'], probe.KIND)
        self.assertEqual(report['status'], 'ok')
        self.assertEqual(report['baseApkSha256'], expected_hash)
        self.assertEqual(report['sha256'], hashlib.sha256(payload).hexdigest())
        self.assertEqual(report['bytes'], len(payload))
        self.assertTrue(report['sizeMatchesExpected'])
        self.assertTrue(report['metadataMatchesExtractedFile'])
        self.assertTrue(report['header']['standardMagicLEAtHeader'])
        self.assertEqual(report['header']['versionLE'], probe.EXPECTED_METADATA_VERSION)
        self.assertTrue(report['header']['versionEqualsExpectedLE'])
        self.assertGreaterEqual(report['magicCandidates']['candidates']['standard-le']['count'], 2)
        self.assertTrue(report['magicCandidates']['candidates']['standard-le']['atHeader'])
        self.assertGreater(report['entropy']['fullShannonBitsPerByte'], 0)
        self.assertEqual(report['containerSignatures']['signatureAtStartCount'], 0)

    def test_hash_gate_rejects_mismatched_base_apk(self):
        payload = standard_payload()
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / 'base.apk'
            make_apk(apk, payload)
            with self.assertRaises(ValueError):
                probe.metadata_file_report(apk, expected_base_hash='0' * 64,
                                           expected_size=len(payload))

    def test_gzip_container_signature_and_nonstandard_header(self):
        payload = b'\x1f\x8b' + bytes(range(256)) * 16
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / 'base.apk'
            expected_hash = make_apk(apk, payload)
            report = probe.metadata_file_report(apk,
                                                expected_base_hash=expected_hash,
                                                expected_size=len(payload))
        self.assertEqual(report['status'], 'ok')
        self.assertIn('gzip', report['containerSignatures']['atStart'])
        self.assertFalse(report['header']['standardMagicLEAtHeader'])
        self.assertFalse(report['magicCandidates']['candidates']['standard-le']['atHeader'])

    def test_single_byte_xor_magic_candidate(self):
        transformed = bytes(byte ^ 0x5a for byte in probe.STANDARD_LE)
        payload = transformed + struct.pack('<I', 31) + bytes(range(256)) * 16
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / 'base.apk'
            expected_hash = make_apk(apk, payload)
            report = probe.metadata_file_report(apk,
                                                expected_base_hash=expected_hash,
                                                expected_size=len(payload))
        self.assertEqual(report['header']['headerSingleByteXorKeyFromStandardLE'], 0x5a)
        self.assertFalse(report['header']['standardMagicLEAtHeader'])
        dynamic = report['magicCandidates']['dynamicLabel']
        self.assertEqual(dynamic, 'header-single-byte-xor')
        self.assertTrue(report['magicCandidates']['candidates'][dynamic]['atHeader'])

    def test_missing_entry_and_annotation_safety(self):
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / 'base.apk'
            expected_hash = make_apk(apk, standard_payload(), entry='other.bin')
            report = probe.metadata_file_report(apk,
                                                expected_base_hash=expected_hash,
                                                expected_size=10)
        self.assertEqual(report['status'], 'entry-not-found')
        self.assertEqual(report['matchingEntryCount'], 0)
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            probe.emit_metadata_file_annotations(report)
        output = buffer.getvalue()
        self.assertIn('::notice title=WorldBox metadata file descriptor unavailable::', output)
        self.assertNotIn('DO-NOT-EMIT-LITERAL', output)

    def test_annotations_omit_raw_payload_bytes_and_unknown_literals(self):
        payload = standard_payload()
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / 'base.apk'
            expected_hash = make_apk(apk, payload)
            report = probe.metadata_file_report(apk,
                                                expected_base_hash=expected_hash,
                                                expected_size=len(payload))
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            probe.emit_metadata_file_annotations(report)
        output = buffer.getvalue()
        self.assertIn('::warning title=WorldBox metadata file descriptor summary::', output)
        self.assertIn('::warning title=WorldBox metadata file descriptor magic candidates::', output)
        self.assertNotIn('DO-NOT-EMIT-LITERAL', output)
        self.assertNotIn('af1bb1fa', output.lower())
        self.assertNotIn(probe.STANDARD_LE.decode('latin1'), output)


if __name__ == '__main__':
    unittest.main()

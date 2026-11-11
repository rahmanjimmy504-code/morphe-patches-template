"""Synthetic ELF tests for bounded Brotli export-consumer modeling."""
import contextlib
import hashlib
import io
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.github/scripts'))
sys.path.insert(0, str(ROOT / 'tests'))
import worldbox_brotli_export_consumers as probe
from test_worldbox_native_literal_refs import fixture


class BrotliExportConsumersTest(unittest.TestCase):
    def test_report_and_annotations_are_bounded_and_hash_gated(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'fixture.so'
            image = fixture()
            path.write_bytes(image)
            sha = hashlib.sha256(image).hexdigest()
            report = probe.export_consumers_report(
                path, expected_sha=sha, watched_stubs={0x2000: 'dlsym'})
            self.assertEqual(report['kind'], probe.KIND)
            self.assertEqual(report['sha256'], sha)
            self.assertEqual(report['observedStubLabels']['0x2000'], 'dlsym')
            self.assertEqual(report['directCallers']['counts']['state_create_caller'], 1)
            self.assertEqual(report['directCallers']['counts']['state_destroy_caller'], 1)
            self.assertEqual(
                report['indirectModel']['counts']['0x189941c']['indirectCallCount'], 2)
            self.assertGreaterEqual(
                report['literalModel']['results']['brotli_decompress_name']['ascii']['count'], 2)
            self.assertGreaterEqual(report['nameReferences']['count'], 1)
            self.assertGreaterEqual(
                report['loaderCalls']['rows'][0]['callCounts']['dlsym'], 1)
            self.assertIn('0x3000', report['ghidraAddresses'])
            buffer = io.StringIO()
            with contextlib.redirect_stdout(buffer):
                probe.emit_export_consumer_annotations(report)
            output = buffer.getvalue()
            self.assertIn('::warning title=WorldBox Brotli export consumer summary::', output)
            self.assertNotIn('fixture_unknown_secret', output)
            for line in output.splitlines():
                if line.startswith('::'):
                    self.assertLessEqual(len(line), 4096)
            with self.assertRaises(ValueError):
                probe.export_consumers_report(path, expected_sha='0' * 64)

    def test_default_watched_stubs_are_predefined_only(self):
        self.assertEqual(probe.DEFAULT_WATCHED_STUBS[0x3bf9d70], 'dlsym')
        self.assertEqual(probe.DEFAULT_WATCHED_STUBS[0x3bf9220],
                         'brotli-decompress-stream-import')
        self.assertIn('BrotliDecoderDecompress', probe.NAME_NEEDLES.values())


if __name__ == '__main__':
    unittest.main()

"""Synthetic ELF tests for bounded Brotli-wrapper caller classification."""
import contextlib
import hashlib
import io
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.github/scripts'))
sys.path.insert(0, str(ROOT / 'tests'))
import worldbox_brotli_callers as probe
from test_worldbox_native_import_probe import synthetic_elf


class BrotliCallersTest(unittest.TestCase):
    def test_direct_bl_caller_is_bounded_and_annotated(self):
        data = synthetic_elf(['open'])
        sha = hashlib.sha256(data).hexdigest()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'fixture.so'
            path.write_bytes(data)
            report = probe.callers_report(path, expected_sha=sha,
                                          targets=(0x2000,))
        self.assertEqual(report['kind'], probe.KIND)
        self.assertEqual(report['library'], 'libil2cpp.so')
        self.assertEqual(report['targets'], ['0x2000'])
        self.assertEqual(report['rows'][0]['directCallCount'], 1)
        self.assertEqual(report['rows'][0]['callSamples'][0]['site'], '0x3000')
        self.assertIn('0x3000', report['rows'][0]['fdeReportEntries'])
        self.assertIn('0x3000', report['ghidraAddresses'])
        static = report['rows'][0]['indirectStaticReferences']
        self.assertIsInstance(static['alignedPointerCount'], int)
        self.assertIsInstance(static['matchingRelocationCount'], int)
        self.assertIsInstance(static['directTailBranchCount'], int)
        self.assertFalse(report['ghidraAddressesTruncated'])
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            probe.emit_callers_annotations(report)
        output = buffer.getvalue()
        self.assertIn('::warning title=WorldBox brotli callers summary::', output)
        self.assertIn('::warning title=WorldBox brotli callers 0x2000::', output)
        self.assertNotIn('DO-NOT-EMIT-LITERAL', output)

    def test_hash_gate_rejects_mismatched_library(self):
        data = synthetic_elf(['open'])
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'fixture.so'
            path.write_bytes(data)
            with self.assertRaises(ValueError):
                probe.callers_report(path, expected_sha='0' * 64,
                                     targets=(0x2000,))


if __name__ == '__main__':
    unittest.main()

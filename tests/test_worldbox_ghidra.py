"""Host-side validation for the bounded Ghidra wrapper and report parser."""
import io
import os
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.github/scripts'))
import worldbox_ghidra_probe as probe

class GhidraProbeTest(unittest.TestCase):
    @unittest.skipUnless(os.environ.get('WORLDBOX_TEST_FIXTURE'), 'compiled ARM64 fixture not provided')
    def test_selects_actual_compiled_arm64_fixture(self):
        result = probe.targets(os.environ['WORLDBOX_TEST_FIXTURE'], fixture=True)
        self.assertGreater(result['helperSize'], 0)
        self.assertEqual(len(result['targets']), 1)
        self.assertGreater(result['targets'][0]['size'], 0)

    def test_marked_json_ignores_ghidra_log_decoration(self):
        report = probe.marked_report(io.StringIO('INFO Probe> WB_GHIDRA_JSON:{"kind":"ghidra-bounded-probe","sites":[]} (GhidraScript)\n'))
        self.assertEqual(report['sites'], [])

    def test_missing_or_multiple_reports_fail(self):
        with self.assertRaisesRegex(RuntimeError, 'exactly one'):
            probe.marked_report(io.StringIO('unrelated log\n'))
        with self.assertRaisesRegex(RuntimeError, 'exactly one'):
            probe.marked_report(io.StringIO('WB_GHIDRA_JSON:{"kind":"ghidra-bounded-probe"}\n' * 2))

    def test_invalid_or_other_json_does_not_count(self):
        with self.assertRaisesRegex(RuntimeError, 'exactly one'):
            probe.marked_report(io.StringIO('WB_GHIDRA_JSON:{broken}\nWB_GHIDRA_JSON:{"kind":"other"}\n'))

if __name__ == '__main__':
    unittest.main()

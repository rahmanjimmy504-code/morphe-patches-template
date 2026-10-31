"""Host-side validation for the bounded Ghidra wrapper and report parser."""
import io
import json
import os
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.github/scripts'))
import worldbox_ghidra_probe as probe
import worldbox_ghidra_callees as callees

class GhidraProbeTest(unittest.TestCase):
    @unittest.skipUnless(os.environ.get('WORLDBOX_TEST_FIXTURE'), 'compiled ARM64 fixture not provided')
    def test_selects_actual_compiled_arm64_fixture(self):
        result = probe.targets(os.environ['WORLDBOX_TEST_FIXTURE'], fixture=True)
        self.assertGreater(result['helperSize'], 0)
        self.assertEqual(len(result['targets']), 1)
        self.assertGreater(result['targets'][0]['size'], 0)

    def test_fixture_requires_both_constant_stack_fields(self):
        def write(offset, kind):
            return {'relativeOffset': offset, 'sourceGraph': {'rootKinds': [kind]}}
        evidence = {'stackAddressResolved': True, 'writes': [write(8, 'constant'), write(16, 'constant')]}
        self.assertTrue(probe.valid_fixture_evidence(evidence))
        self.assertFalse(probe.valid_fixture_evidence(dict(evidence, stackAddressResolved=False)))
        self.assertFalse(probe.valid_fixture_evidence(dict(evidence, writes=[write(8, 'constant')])))
        self.assertFalse(probe.valid_fixture_evidence(dict(evidence, writes=[write(8, 'constant'), write(16, 'register')])))

    def test_site_annotation_compacts_and_retains_evidence(self):
        write = {'relativeOffset': 8, 'width': 8,
                 'sourceGraph': {'rootKinds': ['constant', 'stack'], 'stringCategories': [], 'nodes': 2}}
        call = {'site': '0x1234', 'target': '0x5678', 'argumentIndex': 1, 'relativeOffset': 0}
        row = {'site': '0xabc', 'stackEvidence': {'stackAddressResolved': True,
               'writes': [write] * 8, 'calls': [call] * 8, 'truncated': True}}
        text = probe.compact_site(row)
        self.assertLessEqual(len(text), 3800)
        decoded = json.loads(text)
        self.assertEqual(decoded['stackEvidence']['writes'][0]['roots'], ['constant', 'stack'])
        self.assertEqual(len(decoded['stackEvidence']['calls']), 8)
        self.assertTrue(decoded['stackEvidence']['truncated'])

    def test_callee_parser_and_redacted_annotation(self):
        text = 'WB_GHIDRA_CALLEES:{"kind":"ghidra-callees-probe","functions":[]} (GhidraScript)\n'
        self.assertEqual(callees.parse_report(io.StringIO(text))['functions'], [])
        with self.assertRaises(RuntimeError):
            callees.parse_report(io.StringIO(text * 2))
        row = {'entry': '0x100', 'calls': [{'target': '0x200', 'site': '0x120'}] * 16,
               'returnGraphs': [{'rootKinds': ['constant'], 'stringCategories': [],
                                 'operationCounts': {'CALL': 1}, 'nodes': 3}]}
        compact = callees.compact_callee(row)
        self.assertLessEqual(len(compact), 3800)
        self.assertEqual(json.loads(compact)['returnGraphs'][0]['operations'], ['CALL'])

    @unittest.skipUnless(os.environ.get('WORLDBOX_TEST_FIXTURE'), 'compiled ARM64 fixture not provided')
    def test_selects_callee_fixture(self):
        plan = callees.target_plan(os.environ['WORLDBOX_TEST_FIXTURE'], fixture=True)
        self.assertEqual(len(plan['functions']), 1)
        self.assertNotEqual(plan['functions'][0]['entry'], plan['expected'])

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

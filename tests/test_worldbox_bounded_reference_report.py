"""Synthetic tests for compact bounded reference/Ghidra annotation emitters."""
import contextlib
import io
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.github/scripts'))
import worldbox_bounded_reference_report as emitter


def synthetic_reference_report():
    return {
        'kind': 'worldbox-branch-destination-probe',
        'targets': ['0x1890260', '0x3adec0c'],
        'unwindStatus': 'parsed',
        'unwindRanges': 1,
        'limitations': 'Static candidates only.',
        'rows': [{
            'target': '0x1890260', 'fdeStart': '0x1890260', 'fdeSize': 4,
            'xrefs': {'symbolMatches': 0, 'directTailBranches': 0,
                      'pcRelativeAddressPairs': 0, 'matchingRelocations': 0,
                      'alignedPointerValues': 0, 'executableBytes': 4,
                      'executableScanned': 4, 'execTruncated': False,
                      'allocatedDataBytes': 0, 'allocatedDataScanned': 0,
                      'dataTruncated': False, 'unsupportedRelocationSections': [],
                      'limitations': 'Static candidates only.'},
            'tailSamples': [], 'pcRelativeSamples': [],
            'relocationSamples': [], 'pointerSamples': [],
            'fdeReports': [{'entry': '0x1890260', 'size': 4,
                            'decodedInstructions': 1, 'fullyDecoded': True,
                            'instructions': [{'address': '0x1890260',
                                              'mnemonic': 'ret', 'operands': ''}]}],
            'fdeReportsTruncated': False}]}


class BoundedReferenceReportTest(unittest.TestCase):
    def test_annotation_escapes_workflow_command_characters(self):
        self.assertEqual(emitter.annotation('100%\r\n'), '100%25%0D%0A')

    def test_reference_annotations_emit_compact_json_and_fde_chunks(self):
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            emitter.emit_reference_annotations(synthetic_reference_report(),
                'branch destination', 'branch destination',
                'worldbox-branch-destination-probe')
        output = buffer.getvalue()
        self.assertIn('WorldBox full branch destination report:', output)
        self.assertIn('::warning title=WorldBox branch destination summary::', output)
        self.assertIn('::warning title=WorldBox branch destination xrefs 0x1890260::', output)
        self.assertIn('::warning title=WorldBox branch destination consumers 0x1890260::', output)
        self.assertIn('::notice title=WorldBox branch destination FDE instructions 0x1890260 1/1::', output)
        self.assertIn('0x1890260 ret', output)
        summary_line = next(line for line in output.splitlines()
                            if '::warning title=WorldBox branch destination summary::' in line)
        summary = json.loads(summary_line.split('::', 2)[2])
        self.assertEqual(summary['targets'], ['0x1890260', '0x3adec0c'])
        self.assertEqual(summary['rows'][0]['consumerCounts']['directTailBranches'], 0)

    def test_ghidra_annotations_require_requested_anchors(self):
        report = {'kind': 'ghidra-callees-probe',
                  'functions': [{'entry': '0x1890260', 'anchorSites': ['0x1890260'],
                                 'directCallCount': 0, 'calls': [],
                                 'tracedTargetArguments': [], 'returnGraphs': [],
                                 'stringCategories': [], 'operationCounts': {}}],
                  'limitations': 'Bounded decompilation.'}
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            emitter.emit_ghidra_annotations(report, 'branch destination',
                ('0x1890260',), ('0x1890260',),
                native_report=synthetic_reference_report())
        output = buffer.getvalue()
        self.assertIn('::warning title=WorldBox branch destination Ghidra summary::', output)
        self.assertIn('::warning title=WorldBox branch destination Ghidra::', output)
        self.assertIn('::notice title=WorldBox branch destination FDE instructions 0x1890260 1/1::', output)
        with self.assertRaises(RuntimeError):
            emitter.emit_ghidra_annotations(report, 'branch destination',
                ('0x1890260', '0x3adec0c'), ('0x1890260',))


if __name__ == '__main__':
    unittest.main()

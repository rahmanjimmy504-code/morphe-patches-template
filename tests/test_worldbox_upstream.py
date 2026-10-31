"""Synthetic tests for bounded direct-caller triage, not game binaries."""
from pathlib import Path
import io
import json
import struct
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.github/scripts'))
sys.path.insert(0, str(ROOT / 'tests'))
from elftools.elf.elffile import ELFFile
import worldbox_upstream as upstream
from test_worldbox_native import fixture


class UpstreamTest(unittest.TestCase):
    def inspect_fixture(self, data, target):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'fixture.so'
            path.write_bytes(data)
            return upstream.inspect(path, target)

    def test_direct_call_and_entry_argument(self):
        report = self.inspect_fixture(fixture(via_helper=True, eh_frame=True, split_frames=True), 0x3040)
        self.assertEqual(report['directCalls'], 1)
        self.assertEqual(report['directTailBranches'], 0)
        self.assertFalse(report['execTruncated'])
        self.assertEqual(report['unwindStatus'], 'parsed')
        self.assertEqual(report['examples'][0]['site'], '0x3000')
        self.assertEqual(report['examples'][0]['x0'], ['entry-argument-0'])
        self.assertTrue(report['examples'][0]['reachedInModel'])
        payloads = upstream.annotation_payloads(report)
        self.assertEqual(len(payloads), 2)
        self.assertTrue(all(len(item) <= 3800 for item in payloads))
        self.assertEqual(json.loads(payloads[1])['site'], '0x3000')

    def test_prior_call_result_is_attributed_without_claiming_value(self):
        report = self.inspect_fixture(fixture(eh_frame=True, origin_helper=True), 0x3040)
        row = report['examples'][0]
        self.assertEqual(row['x0'], ['x0-after-call@0x3000'])
        self.assertEqual(row['x0CallOrigins'][0]['target'], '0x3080')
        self.assertIsNone(row['x0CallOrigins'][0]['recognizedApi'])

    def test_two_target_analysis_and_bounded_annotations(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'fixture.so'
            path.write_bytes(fixture(eh_frame=True, origin_helper=True))
            report = upstream.inspect_many(path, [0x3040, 0x3080])
        self.assertEqual([row['target'] for row in report['reports']], ['0x3040', '0x3080'])
        self.assertEqual(report['reports'][0]['examples'][0]['x0'], ['x0-after-call@0x3000'])
        self.assertEqual(report['reports'][1]['examples'][0]['x0'], ['entry-argument-0'])
        payloads = upstream.multi_annotation_payloads(report)
        self.assertEqual(len(payloads), 4)
        self.assertTrue(all(len(text) <= 3800 for _, text in payloads))
        self.assertEqual(json.loads(payloads[1][1])['target'], '0x3040')
        with self.assertRaises(ValueError):
            upstream.inspect_many('unused', [0x3040, 0x3040])
        with self.assertRaises(ValueError):
            upstream.inspect_many('unused', [0x3041])
        with self.assertRaises(ValueError):
            upstream.inspect_many('unused', [0x3000, 0x3040, 0x3080])

    def test_trace_origin_verifies_branch_and_captures_return(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'fixture.so'
            path.write_bytes(fixture(eh_frame=True, origin_helper=True))
            result = upstream.trace_origin(path, 0x3080, 0x3000)
            self.assertEqual(result['status'], 'modeled')
            self.assertEqual(result['returns'][0]['x0'], ['entry-argument-1'])
            self.assertEqual(result['callerInputs']['arguments']['x0'], ['entry-argument-0'])
            self.assertEqual(result['callerInputs']['arguments']['x2'], ['entry-argument-2'])
            self.assertTrue(result['callerInputs']['reachedInModel'])
            with self.assertRaisesRegex(ValueError, 'direct branch'):
                upstream.trace_origin(path, 0x3080, 0x3004)

    def test_tail_caller_is_verified_separately_from_call(self):
        data = fixture(eh_frame=True, origin_helper=True)
        text = ELFFile(io.BytesIO(data)).get_section_by_name('.text')
        tail = 0x14000000 | (((0x3080 - 0x3040) // 4) & 0x03ffffff)
        struct.pack_into('<I', data, text['sh_offset'] + 0x40, tail)
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'fixture.so'
            path.write_bytes(data)
            result = upstream.trace_origin(path, 0x3080, 0x3040, caller_kind='tail')
            self.assertEqual(result['callerKind'], 'tail')
            self.assertEqual(result['returns'][0]['x0'], ['entry-argument-1'])
            self.assertTrue(result['callerInputs']['reachedInModel'])
            self.assertEqual(result['callerInputs']['arguments']['x0'], ['entry-argument-0'])
            with self.assertRaisesRegex(ValueError, 'direct branch'):
                upstream.trace_origin(path, 0x3080, 0x3040)
            with self.assertRaisesRegex(ValueError, 'tail branch'):
                upstream.trace_origin(path, 0x3080, 0x3000, caller_kind='tail')

    def test_trace_origin_exposes_tail_transfer_without_inventing_return(self):
        data = fixture(eh_frame=True, origin_helper=True)
        text = ELFFile(io.BytesIO(data)).get_section_by_name('.text')
        tail = 0x14000000 | (((0x2000 - 0x3080) // 4) & 0x03ffffff)
        struct.pack_into('<I', data, text['sh_offset'] + 0x80, tail)
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'fixture.so'
            path.write_bytes(data)
            result = upstream.trace_origin(path, 0x3080, 0x3000)
        self.assertEqual(result['returns'], [])
        self.assertEqual(result['tailTransfers'][0]['target'], '0x2000')
        self.assertEqual(result['tailTransfers'][0]['x0'], ['entry-argument-0'])

    def test_batch_origin_validates_pairs_and_recovers_each(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'fixture.so'
            path.write_bytes(fixture(eh_frame=True, origin_helper=True))
            result = upstream.trace_origin_batch(path, [(0x3080, 0x3000), (0x3040, 0x3004)])
            self.assertEqual(result['kind'], 'arm64-upstream-origin-batch')
            self.assertEqual(len(result['origins']), 2)
            self.assertEqual(result['origins'][0]['returns'][0]['x0'], ['entry-argument-1'])
            self.assertEqual(result['origins'][1]['tailTransfers'][0]['target'], '0x2000')
            with self.assertRaises(ValueError):
                upstream.trace_origin_batch(path, [(0x3080, 0x3000)] * 2)
            with self.assertRaises(ValueError):
                upstream.trace_origin_batch(path, [(0x3081, 0x3000)])

    def test_origin_annotation_reserves_budget(self):
        item = {'target': '0x3000', 'examples': [{'site': hex(i * 4)} for i in range(8)]}
        report = {'kind': 'arm64-upstream-multi', 'reports': [item, dict(item, target='0x4000')],
                  'origin': {'target': '0x5000', 'status': 'modeled'}}
        payloads = upstream.multi_annotation_payloads(report)
        self.assertLessEqual(len(payloads), 10)
        self.assertEqual(json.loads(payloads[0][1])['annotationExamplesEmitted'], 3)
        self.assertEqual(payloads[-1][0], 'origin')

    def test_reference_summary_reports_relocation_without_section_names(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'fixture.so'
            path.write_bytes(fixture(eh_frame=True))
            report = upstream.inspect_many(path, [0x3000], references=True)
        summary = report['reports'][0]['referenceSummary']
        self.assertEqual(summary['relocations']['count'], 1)
        self.assertEqual(summary['relocations']['sampleSlots'], ['0x6000'])
        self.assertEqual(summary['relocations']['sampleTypes'], [1027])
        self.assertEqual(summary['alignedPointers']['samples'][0]['sectionKind'], 'relocation-section')
        self.assertNotIn('.rela.dyn', json.dumps(summary))
        payloads = upstream.multi_annotation_payloads(report)
        self.assertLess(len(payloads[0][1]), 3800)

    def test_multi_annotation_marks_hidden_samples(self):
        item = {'target': '0x3000', 'examples': [{'site': hex(i * 4)} for i in range(8)]}
        payloads = upstream.multi_annotation_payloads({'kind': 'arm64-upstream-multi', 'reports': [item]})
        summary = json.loads(payloads[0][1])
        self.assertEqual(summary['annotationExamplesAvailable'], 8)
        self.assertEqual(summary['annotationExamplesEmitted'], 4)
        self.assertTrue(summary['annotationExamplesTruncated'])
        self.assertEqual(len(payloads), 5)
        self.assertNotIn('annotationExamplesEmitted', item)

    def test_tail_branch_and_missing_unwind_are_explicit(self):
        data = fixture(via_helper=True)
        text = ELFFile(io.BytesIO(data)).get_section_by_name('.text')
        word = 0x14000000 | (((0x3040 - 0x3000) // 4) & 0x03ffffff)
        struct.pack_into('<I', data, text['sh_offset'], word)
        report = self.inspect_fixture(data, 0x3040)
        self.assertEqual(report['directCalls'], 0)
        self.assertEqual(report['directTailBranches'], 1)
        self.assertEqual(report['examples'][0]['status'], 'no-unwind-range')

    def test_rejects_other_architecture(self):
        data = fixture()
        data[18:20] = struct.pack('<H', 62)
        with self.assertRaisesRegex(ValueError, 'AArch64'):
            self.inspect_fixture(data, 0x3040)

if __name__ == '__main__':
    unittest.main()

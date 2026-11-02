"""Synthetic-only tests for the bounded ARM64 file argument analysis."""
import importlib.util
from pathlib import Path
import struct
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.github/scripts'))
sys.path.insert(0, str(ROOT / 'tests'))
import worldbox_native_flow as flow
from test_worldbox_native import branch, fixture


def words(*values):
    return b''.join(struct.pack('<I', value) for value in values)


def classify(_):
    return 'small-constant'


class FlowTest(unittest.TestCase):
    def test_open_result_can_reach_read_through_callee_saved_register(self):
        # bl open; mov w19,w0; mov w0,w19; bl read; ret
        data = words(branch(0x3000, 0x2000), 0x2a0003f3, 0x2a1303e0,
                     branch(0x300c, 0x2010), 0xd65f03c0)
        result = flow.analyze_window(data, 0x3000, {0x2000: 'open', 0x2010: 'read'},
                                     {0x3000: 'open', 0x300c: 'read'}, classify)
        self.assertFalse(result['workLimitReached'])
        self.assertEqual(result['calls'][0]['arguments']['x0'], ['entry-argument-0'])
        self.assertEqual(result['calls'][1]['arguments']['x0'], ['return-from-open@0x3000'])

    def test_conditional_paths_merge_and_do_not_claim_definite_flow(self):
        # cbz x1,read; bl open; nop; read; ret
        data = words(0xb4000061, branch(0x3004, 0x2000), 0xd503201f,
                     branch(0x300c, 0x2010), 0xd65f03c0)
        result = flow.analyze_window(data, 0x3000, {0x2000: 'open', 0x2010: 'read'},
                                     {0x3004: 'open', 0x300c: 'read'}, classify)
        self.assertEqual(result['calls'][1]['arguments']['x0'], ['entry-argument-0', 'return-from-open@0x3004'])
        self.assertGreater(result['branchVisits'], 0)

    def test_call_clobbers_caller_saved_registers(self):
        data = words(branch(0x3000, 0x2000), branch(0x3004, 0x2020),
                     branch(0x3008, 0x2010), 0xd65f03c0)
        result = flow.analyze_window(data, 0x3000, {0x2000: 'open', 0x2010: 'read'},
                                     {0x3008: 'read'}, classify)
        self.assertEqual(result['calls'][0]['arguments']['x0'], ['x0-after-call@0x3004'])
        self.assertEqual(result['calls'][0]['callOrigins'][0]['target'], '0x2020')

    def test_callee_and_memory_provenance(self):
        # bl helper; ldr x0,[x0]; bl read; ret
        data = words(branch(0x3000, 0x2020), 0xf9400000,
                     branch(0x3008, 0x2010), 0xd65f03c0)
        result = flow.analyze_window(data, 0x3000, {0x2010: 'read'},
                                     {0x3008: 'read'}, classify)
        call = result['calls'][0]
        self.assertEqual(call['arguments']['x0'], ['loaded-through-x0-after-call@0x3000'])
        self.assertEqual(call['callOrigins'], [{'site': '0x3000', 'kind': 'direct', 'target': '0x2020', 'recognizedApi': None}])

    def test_load_through_entry_argument(self):
        # ldr x0,[x0]; bl read; ret
        data = words(0xf9400000, branch(0x3004, 0x2010), 0xd65f03c0)
        result = flow.analyze_window(data, 0x3000, {0x2010: 'read'},
                                     {0x3004: 'read'}, classify)
        self.assertEqual(result['calls'][0]['arguments']['x0'], ['loaded-through-entry-argument-0'])

    def test_stack_spill_and_reload(self):
        # stp fp,lr,[sp,#-32]!; bl open; str w0,[sp,#16];
        # ldr w0,[sp,#16]; bl read; ldp fp,lr,[sp],#32; ret
        data = words(0xa9be7bfd, branch(0x3004, 0x2000), 0xb90013e0,
                     0xb94013e0, branch(0x3010, 0x2010), 0xa8c27bfd, 0xd65f03c0)
        result = flow.analyze_window(data, 0x3000, {0x2000: 'open', 0x2010: 'read'},
                                     {0x3004: 'open', 0x3010: 'read'}, classify)
        self.assertEqual(result['calls'][1]['arguments']['x0'], ['return-from-open@0x3004'])

    def test_return_provenance_is_opt_in_and_bounded(self):
        # bl helper; ret
        data = words(branch(0x3000, 0x2020), 0xd65f03c0)
        result = flow.analyze_window(data, 0x3000, {}, {}, classify, capture_returns=True)
        self.assertEqual(result['returns'][0]['x0'], ['x0-after-call@0x3000'])
        self.assertEqual(result['returns'][0]['callOrigins'][0]['target'], '0x2020')
        self.assertFalse(result['returnsTruncated'])
        no_capture = flow.analyze_window(data, 0x3000, {}, {}, classify)
        self.assertEqual(no_capture['returns'], [])

    def test_return_analysis_reports_external_tail_transfer(self):
        word = 0x14000000 | (((0x2000 - 0x3000) // 4) & 0x03ffffff)
        result = flow.analyze_window(words(word), 0x3000, {}, {}, classify, capture_returns=True)
        self.assertEqual(result['returns'], [])
        self.assertEqual(result['tailTransfers'][0], {'site': '0x3000', 'target': '0x2000', 'x0': ['entry-argument-0']})

    def test_stack_pointee_categories(self):
        # sub sp,sp,#32; str x1,[sp,#16]; add x0,sp,#16; bl helper; ret
        data = words(0xd10083ff, 0xf9000be1, 0x910043e0,
                     branch(0x300c, 0x2020), 0xd65f03c0)
        result = flow.analyze_window(data, 0x3000, {0x2020: 'source-helper'},
                                     {0x300c: 'source-helper'}, classify)
        call = result['calls'][0]
        self.assertEqual(call['arguments']['x0'], ['stack-address'])
        self.assertEqual(call['x0StackSlots']['0'], ['entry-argument-1'])
        self.assertEqual(call['x0StackSlots']['8'], ['unknown'])

    def test_file_helper_call_reports_stack_object_fields(self):
        # sub sp,sp,#32; str x1,[sp,#16]; add x0,sp,#16; bl file_helper; ret
        data = words(0xd10083ff, 0xf9000be1, 0x910043e0,
                     branch(0x300c, 0x2020), 0xd65f03c0)
        result = flow.analyze_window(data, 0x3000, {0x2020: 'file-helper'},
                                     {0x300c: 'file-helper'}, classify)
        call = result['calls'][0]
        self.assertEqual(call['arguments']['x0'], ['stack-address'])
        self.assertEqual(call['x0StackSlots']['0'], ['entry-argument-1'])

    def test_stack_pointee_preserves_other_pointer_paths(self):
        # sub sp,sp,#32; cbz x1,call; str x2,[sp]; mov x0,sp; call; ret
        data = words(0xd10083ff, 0xb4000061, 0xf90003e2, 0x910003e0,
                     branch(0x3010, 0x2020), 0xd65f03c0)
        result = flow.analyze_window(data, 0x3000, {0x2020: 'source-helper'},
                                     {0x3010: 'source-helper'}, classify)
        self.assertEqual(result['calls'][0]['x0StackSlots']['0'], ['entry-argument-2', 'unknown'])

    def test_call_may_clobber_pointed_stack(self):
        # sub sp,sp,#32; str x1,[sp,#16]; add x0,sp,#16; bl other;
        # add x0,sp,#16; bl helper; ret
        data = words(0xd10083ff, 0xf9000be1, 0x910043e0, branch(0x300c, 0x2020),
                     0x910043e0, branch(0x3014, 0x2030), 0xd65f03c0)
        result = flow.analyze_window(data, 0x3000, {0x2030: 'source-helper'},
                                     {0x3014: 'source-helper'}, classify)
        self.assertEqual(result['calls'][0]['x0StackSlots']['0'], ['unknown'])

    def test_tail_branch_arguments(self):
        # b 0x2000; no return to this window.
        word = 0x14000000 | (((0x2000 - 0x3000) // 4) & 0x03ffffff)
        result = flow.analyze_window(words(word), 0x3000, {0x2000: 'tail-mapparent'},
                                     {0x3000: 'tail-mapparent'}, classify)
        self.assertTrue(result['calls'][0]['reachedInModel'])
        self.assertEqual(result['calls'][0]['arguments']['x0'], ['entry-argument-0'])

    def test_direct_call_to_internal_tail_target_captures_argument_registers(self):
        # bl internal_tail_thunk; ret
        data = words(branch(0x3000, 0x2000), 0xd65f03c0)
        result = flow.analyze_window(data, 0x3000, {0x2000: 'tail-mapparent'},
                                     {0x3000: 'tail-mapparent'}, classify)
        call = result['calls'][0]
        self.assertTrue(call['reachedInModel'])
        self.assertEqual(call['arguments']['x0'], ['entry-argument-0'])
        self.assertEqual(call['arguments']['x1'], ['entry-argument-1'])

    def test_unwind_overlap_selection(self):
        frames = [(100, 500), (150, 180), (160, 220), (800, 900)]
        starts = [lo for lo, _ in frames]
        self.assertEqual(flow.frame_for_site(frames, starts, 170), (150, 180))
        self.assertIsNone(flow.frame_for_site(frames, starts, 700))

    def test_internal_wrapper_arguments_are_sampled(self):
        data = words(branch(0x3000, 0x2100), 0xd65f03c0)
        result = flow.analyze_window(data, 0x3000, {0x2100: 'wrapper-open'},
                                     {0x3000: 'wrapper-open'}, classify)
        self.assertEqual(result['calls'][0]['arguments']['x1'], ['entry-argument-1'])

    def test_actual_elf_unwind_boundary_and_call_confirmation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'fixture.so'
            path.write_bytes(fixture(eh_frame=True))
            report = flow.inspect(path, {0x3000: 'open'})
        self.assertEqual(report['unwindStatus'], 'parsed')
        self.assertEqual(report['unwindRanges'], 1)
        self.assertEqual(report['functions'][0]['boundarySource'], 'eh-frame-fde')
        self.assertTrue(report['functions'][0]['calls'][0]['reachedInModel'])
        self.assertEqual(report['functions'][0]['calls'][0]['arguments']['x0'], ['entry-argument-0'])

    def test_missing_unwind_is_inconclusive(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'fixture.so'
            path.write_bytes(fixture())
            report = flow.inspect(path, {0x3000: 'open'})
        self.assertEqual(report['unwindStatus'], 'missing')
        self.assertEqual(report['functions'], [])
        self.assertEqual(report['unresolvedSites'][0]['status'], 'no-executable-unwind-range')

if __name__ == '__main__':
    unittest.main()

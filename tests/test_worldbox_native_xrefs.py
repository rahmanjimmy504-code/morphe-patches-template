"""Synthetic-only tests of ARM64 tail branches and indirect-reference clues."""
from pathlib import Path
import io
from elftools.elf.elffile import ELFFile
import struct
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.github/scripts'))
sys.path.insert(0, str(ROOT / 'tests'))
import worldbox_native_xrefs as refs
from test_worldbox_native import fixture


def words(*items):
    return b''.join(struct.pack('<I', item) for item in items)


def tail(pc, target):
    return 0x14000000 | (((target - pc) // 4) & 0x03ffffff)


class NativeXrefsTest(unittest.TestCase):
    def test_tail_branch_forward_backward_and_not_bl(self):
        self.assertEqual(refs.direct_tail(tail(0x1000, 0x2000), 0x1000), 0x2000)
        self.assertEqual(refs.direct_tail(tail(0x3000, 0x2000), 0x3000), 0x2000)
        self.assertIsNone(refs.direct_tail(0x94000000, 0x1000))

    def test_adrp_add_and_register_clobber(self):
        # at 0x2000: adrp x16,0x5000; add x0,x16,#0x10
        adrp = 0x90000000 | (3 << 29) | 16
        add = 0x91000000 | (0x10 << 10) | (16 << 5)
        self.assertEqual(refs.adrp_value(adrp, 0x2000), (0x5000, 16))
        self.assertEqual(refs.add_value(add), (16, 0x10))
        count, tails, pairs, samples = refs.executable_refs(words(tail(0x2000, 0x5010), adrp, add), 0x2000, 0x5010)
        self.assertEqual(count, 1)
        self.assertEqual(tails, ['0x2000'])
        self.assertEqual(pairs, 1)
        self.assertEqual(samples[0]['add'], '0x2008')
        clobber_x16 = 0x91000000 | (4 << 10) | (16 << 5) | 16
        _, _, pairs, _ = refs.executable_refs(words(adrp, clobber_x16, add), 0x2000, 0x5010)
        self.assertEqual(pairs, 0)

    def test_packed_relocations_are_flagged(self):
        self.assertTrue(refs.is_packed_relocation_type(0x60000002))
        self.assertTrue(refs.is_packed_relocation_type('SHT_ANDROID_REL'))
        self.assertTrue(refs.is_packed_relocation_type('SHT_RELR'))
        self.assertFalse(refs.is_packed_relocation_type('SHT_PROGBITS'))

    def test_real_elf_relative_relocation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'fixture.so'
            path.write_bytes(fixture(eh_frame=True))
            report = refs.inspect(path, target=0x3000)
        self.assertEqual(report['matchingRelocations']['count'], 1)
        self.assertEqual(report['matchingRelocations']['samples'][0]['slot'], '0x6000')
        self.assertEqual(report['matchingRelocations']['samples'][0]['type'], 1027)
        self.assertFalse(report['execTruncated'])
        self.assertFalse(report['dataTruncated'])

    def test_tail_branch_uses_unwind_function_and_tracks_arguments(self):
        data = fixture(eh_frame=True)
        elf = ELFFile(io.BytesIO(data))
        text = elf.get_section_by_name('.text')
        struct.pack_into('<I', data, text['sh_offset'], tail(0x3000, 0x2000))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'fixture.so'
            path.write_bytes(data)
            report = refs.inspect(path, target=0x2000)
        found = report['directTailBranches']
        self.assertEqual(found['count'], 1)
        self.assertEqual(found['unwindStatus'], 'parsed')
        trace = found['traces'][0]
        self.assertEqual(trace['function'], '0x3000')
        self.assertTrue(trace['call']['reachedInModel'])
        self.assertEqual(trace['call']['arguments']['x0'], ['entry-argument-0'])

    def test_tail_caller_arguments_in_separate_unwind_range(self):
        data = fixture(via_helper=True, eh_frame=True, split_frames=True)
        elf = ELFFile(io.BytesIO(data))
        text = elf.get_section_by_name('.text')
        struct.pack_into('<I', data, text['sh_offset'] + 0x40, tail(0x3040, 0x2000))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'fixture.so'
            path.write_bytes(data)
            report = refs.inspect(path, target=0x2000)
        found = report['directTailBranches']
        self.assertEqual(found['traces'][0]['function'], '0x3040')
        caller = found['enclosingFunctionCallers']['0x3040']
        self.assertEqual(caller['directCalls'], 1)
        self.assertEqual(caller['argumentExamples'][0]['function'], '0x3000')
        self.assertTrue(caller['argumentExamples'][0]['call']['reachedInModel'])
        self.assertEqual(caller['argumentExamples'][0]['call']['arguments']['x0'], ['entry-argument-0'])

    def test_mapping_argument_source_callee_return(self):
        data = fixture(eh_frame=True, origin_helper=True)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'fixture.so'
            path.write_bytes(data)
            report = refs.inspect(path, target=0x2000)
        source = report['directTailBranches']['argumentSourceCallees']
        self.assertEqual(source['uniqueTargets'], 1)
        self.assertEqual(source['examples'][0]['target'], '0x3080')
        self.assertEqual(source['examples'][0]['returns'][0]['x0'], ['entry-argument-1'])

    def test_rejects_other_architecture(self):
        data = fixture()
        data[18:20] = struct.pack('<H', 62)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'wrong.so'
            path.write_bytes(data)
            with self.assertRaisesRegex(ValueError, 'AArch64'):
                refs.inspect(path)

if __name__ == '__main__':
    unittest.main()

"""Synthetic tests for ZIP header selection, raw filter and pointer validation."""
from pathlib import Path
import struct
import sys
import tempfile
from unittest.mock import patch
import unittest
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / '.github/scripts'))
import worldbox_guid_script_refs as scan
from test_worldbox_unity_script_refs import fixture


def verified_fixture():
    return {'matchedIdentifiers': [{'pathId': k, 'className': v} for k, v in scan.refs.TARGETS.items()],
            'parseErrors': [], 'candidateLimitReached': False, 'oversizedCandidates': 0}


class GuidRefsTest(unittest.TestCase):
    def make_apk(self, directory, candidate):
        p = Path(directory) / 'base.apk'
        with zipfile.ZipFile(p, 'w', zipfile.ZIP_DEFLATED) as z:
            z.writestr(scan.scripts.ENTRY, b'target')
            z.writestr('assets/bin/Data/abcdef', candidate)
            z.writestr('assets/bin/Data/not-unity', b'ordinary')
        return p

    def test_raw_prefilter_and_real_monobehaviour(self):
        with tempfile.TemporaryDirectory() as d, patch.object(scan.scripts, 'inspect_bytes', return_value=verified_fixture()):
            report = scan.inspect(self.make_apk(d, fixture()))
        self.assertEqual(report['totals']['filesParsed'], 1)
        self.assertEqual(report['totals']['references-external-basename-match'], 1)
        self.assertEqual(report['resultFiles'][0]['samples'][0]['script'], scan.TARGET_NAME)
        self.assertFalse(report['errors'])

    def test_nonmatching_path_does_not_trigger_parser(self):
        with tempfile.TemporaryDirectory() as d, patch.object(scan.scripts, 'inspect_bytes', return_value=verified_fixture()):
            report = scan.inspect(self.make_apk(d, fixture(script_id=500)))
        self.assertEqual(report['totals']['filesScanned'], 1)
        self.assertNotIn('filesParsed', report['totals'])

    def test_byte_budget_is_visible(self):
        with tempfile.TemporaryDirectory() as d, patch.object(scan.scripts, 'inspect_bytes', return_value=verified_fixture()), patch.object(scan, 'MAX_TOTAL', 1):
            report = scan.inspect(self.make_apk(d, fixture()))
        self.assertEqual(report['totals']['sizeBudgetSkipped'], 1)
        self.assertGreater(report['totals']['sizeBudgetSkippedBytes'], 0)

    def test_legacy_and_big_endian_bypass_filter(self):
        no_needle = bytearray(fixture(script_id=500))
        self.assertFalse(scan.needs_parser(no_needle))
        no_needle[16] = 1
        self.assertTrue(scan.needs_parser(no_needle))
        no_needle[16] = 0
        struct.pack_into('>I', no_needle, 8, 13)
        self.assertTrue(scan.needs_parser(no_needle))

    def test_six_target_mode_detects_other_script(self):
        with tempfile.TemporaryDirectory() as d, patch.object(scan.scripts, 'inspect_bytes', return_value=verified_fixture()):
            report = scan.inspect(self.make_apk(d, fixture(script_id=640)), scan.refs.TARGETS)
        self.assertEqual(report['totals']['filesParsed'], 1)
        self.assertEqual(report['referenceScriptCounts'], [
            {'script': 'TopPremiumButtonMover', 'resolution': 'external-basename-match', 'count': 1}])

    def test_unknown_target_fails_closed(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ValueError):
                scan.inspect(self.make_apk(d, fixture()), {640: 'wrong-name'})

    def test_identity_mismatch_fails_closed(self):
        with tempfile.TemporaryDirectory() as d, patch.object(scan.scripts, 'inspect_bytes', return_value={'matchedIdentifiers': [], 'parseErrors': [], 'candidateLimitReached': False, 'oversizedCandidates': 0}):
            with self.assertRaises(ValueError): scan.inspect(self.make_apk(d, fixture()))

if __name__ == '__main__': unittest.main()

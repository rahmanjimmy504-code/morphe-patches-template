"""Synthetic ZIP/ELF/resource/DEX tests for the Premium entitlement lead probe."""
import contextlib
import hashlib
import io
import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.github/scripts'))
sys.path.insert(0, str(ROOT / 'tests'))
import worldbox_premium_entitlement_probe as probe
from test_worldbox_native_literal_refs import fixture as native_fixture

UNKNOWN = 'fixture_unknown_secret'


class FakeResourceParser:
    def __init__(self, _data):
        self.resource_keys = {
            'com.example.worldbox': {
                'string': {'premium_unlocked_label': 0x7f0e0003,
                           'ordinary_label': 0x7f0e0004}}}

    def get_resolved_strings(self):
        return {'com.example.worldbox': {
            'DEFAULT': {0x7f0e0001: 'Get It Now',
                        0x7f0e0002: 'unrelated resource'}}}


class FakeInstruction:
    def __init__(self, name, output='', literals=()):
        self.name = name
        self.output = output
        self.literals = literals

    def get_name(self):
        return self.name

    def get_output(self):
        return self.output

    def get_literals(self):
        return list(self.literals)


class FakeBytecode:
    def get_instructions(self):
        return [FakeInstruction('const-string', 'premium_unlocked', ()),
                FakeInstruction('const', '', (0x7f0e0001,))]


class FakeCode:
    def get_bc(self):
        return FakeBytecode()


class FakeMethod:
    def get_code(self):
        return FakeCode()

    def get_name(self):
        return 'premiumCheck'

    def get_descriptor(self):
        return '()Z'


class FakeClass:
    def get_name(self):
        return 'Lcom/example/WorldBox;'

    def get_methods(self):
        return [FakeMethod()]


class FakeDEX:
    def get_strings(self):
        return ['premium_unlocked', 'unrelated', 'Get It Now']

    def get_classes(self):
        return [FakeClass()]


class PremiumEntitlementProbeTest(unittest.TestCase):
    def test_stream_scan_handles_chunk_boundaries_and_no_unknown_strings(self):
        data = b'xxpremium_unlockedxxpremium_unlockedxx' + UNKNOWN.encode()
        result = probe.scan_stream(io.BytesIO(data),
                                   {'unlock': 'premium_unlocked'},
                                   encodings=('ascii',), chunk_size=7)
        self.assertEqual(result['counts']['unlock']['ascii'], 2)
        self.assertEqual(len(result['examples']), 2)
        self.assertFalse(result['examplesTruncated'])
        self.assertNotIn(UNKNOWN, json.dumps(result))

    def test_resource_maps_are_hashed_and_parser_failures_are_safe(self):
        parsed = probe.resource_matches(b'not-a-real-arsc',
                                        parser_factory=FakeResourceParser)
        self.assertEqual(parsed['status'], 'parsed')
        self.assertIn('0x7f0e0001', parsed['resourceIds'])
        self.assertIn('0x7f0e0003', parsed['resourceIds'])
        self.assertNotIn('Get It Now', json.dumps(parsed))
        self.assertNotIn('premium_unlocked_label', json.dumps(parsed))
        failed = probe.resource_matches(
            b'not-a-real-arsc',
            parser_factory=lambda _data: (_ for _ in ()).throw(ValueError('secret')))
        self.assertEqual(failed['status'], 'parse-failed')
        self.assertEqual(failed['reason'], 'ValueError')
        self.assertNotIn('secret', json.dumps(failed))

    def test_fake_dex_semantics_emit_only_hashes_and_resource_ids(self):
        result = probe.dex_report(b'not-a-real-dex',
                                  resource_ids=['0x7f0e0001', '0x7f0e0003'],
                                  dex_factory=lambda _data: FakeDEX())
        self.assertEqual(result['status'], 'parsed')
        self.assertEqual(result['methodMatchCount'], 1)
        self.assertEqual(result['methods'][0]['resourceIds'], ['0x7f0e0001'])
        self.assertNotIn('premiumCheck', json.dumps(result))
        self.assertNotIn('Lcom/example/WorldBox;', json.dumps(result))
        self.assertNotIn('Get It Now', json.dumps(result['methods']))

    def test_full_hash_gated_report_and_annotations(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            native = root / 'libil2cpp.so'
            native_bytes = native_fixture()
            native.write_bytes(native_bytes)
            unity = root / 'libunity.so'
            unity.write_bytes(native_bytes)
            metadata = root / 'global-metadata.dat'
            metadata.write_bytes(b'premium_unlocked\0Get It Now\0' +
                                 UNKNOWN.encode() + b'\0')
            apk = root / 'base.apk'
            with zipfile.ZipFile(apk, 'w') as archive:
                archive.writestr('classes.dex', b'premium_unlocked Get It Now')
                archive.writestr('resources.arsc', b'premium_unlocked Get It Now')
                archive.writestr('assets/ordinary.bin', b'no predefined needle')
            expected = {
                'libil2cpp.so': hashlib.sha256(native_bytes).hexdigest(),
                'libunity.so': hashlib.sha256(native_bytes).hexdigest(),
                'metadata': hashlib.sha256(metadata.read_bytes()).hexdigest(),
                'base.apk': hashlib.sha256(apk.read_bytes()).hexdigest(),
            }
            report = probe.premium_report(
                native, unity, metadata, [apk], expected_hashes=expected,
                watched_stubs={0x2000: 'dlsym'},
                resource_parser_factory=FakeResourceParser,
                dex_factory=lambda _data: FakeDEX())
            self.assertEqual(report['kind'], probe.KIND)
            self.assertEqual(report['mode'], 'android')
            self.assertEqual(report['ghidraLibrary'], 'libil2cpp.so')
            self.assertIn('0x3000', report['ghidraAddresses'])
            self.assertIn('0x3000', report['unityGhidraAddresses'])
            self.assertEqual(report['metadataScan']['counts']['premium_unlocked']['ascii'], 1)
            self.assertGreaterEqual(report['apkEntryScan']['hitEntryCount'], 2)
            self.assertEqual(report['androidReports']['resources'][0]['status'], 'parsed')
            self.assertEqual(report['androidReports']['dexFiles'][0]['report']['status'], 'parsed')
            self.assertFalse(report['androidReports']['dexFilesTruncated'])
            self.assertEqual(report['androidReports']['dexFilesSeen'], 1)
            self.assertEqual(
                report['nativeReports']['libil2cpp.so']['watchedCalls']['rows'][0]['callCounts']['dlsym'],
                2)
            buffer = io.StringIO()
            with contextlib.redirect_stdout(buffer):
                probe.emit_premium_annotations(report)
            output = buffer.getvalue()
            self.assertIn('::warning title=WorldBox Premium entitlement summary::', output)
            self.assertNotIn(UNKNOWN, output)
            for line in output.splitlines():
                if line.startswith('::'):
                    self.assertLessEqual(len(line), 4096)
            bad = dict(expected)
            bad['base.apk'] = '0' * 64
            with self.assertRaises(ValueError):
                probe.premium_report(native, unity, metadata, [apk],
                                     expected_hashes=bad,
                                     watched_stubs={0x2000: 'dlsym'},
                                     resource_parser_factory=FakeResourceParser,
                                     dex_factory=lambda _data: FakeDEX())

    def test_native_only_report_skips_android_analysis(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            native = root / 'libil2cpp.so'
            native.write_bytes(native_fixture())
            unity = root / 'libunity.so'
            unity.write_bytes(native.read_bytes())
            metadata = root / 'global-metadata.dat'
            metadata.write_bytes(b'premium_unlocked\0')
            expected = {
                'libil2cpp.so': hashlib.sha256(native.read_bytes()).hexdigest(),
                'libunity.so': hashlib.sha256(unity.read_bytes()).hexdigest(),
                'metadata': hashlib.sha256(metadata.read_bytes()).hexdigest(),
            }
            report = probe.premium_report(native, unity, metadata,
                                          expected_hashes=expected,
                                          watched_stubs={0x2000: 'dlsym'})
            self.assertEqual(report['mode'], 'native')
            self.assertEqual(report['apkEntryScan']['status'], 'not-requested')
            self.assertEqual(report['androidReports']['dexFiles'], [])


if __name__ == '__main__':
    unittest.main()

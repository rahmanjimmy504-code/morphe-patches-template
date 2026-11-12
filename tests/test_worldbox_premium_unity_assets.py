"""Synthetic Unity object/Premium needle coverage with hash-only strings."""
import contextlib
import io
import struct
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.github/scripts'))
sys.path.insert(0, str(ROOT / 'tests'))
from UnityPy.helpers.UnityVersion import UnityVersion
import worldbox_premium_unity_assets as probe
import worldbox_unity_script_refs as refs

UNKNOWN = 'unknownSecretToken'


def serialized(value):
    return struct.pack('<I', len(value)) + value + bytes((-(4 + len(value))) % 4)


def fixture():
    payload = bytearray(16)
    struct.pack_into('<iq', payload, 0, 0, 42)
    payload += serialized(b'clickPremium')
    payload += serialized(b'premium_unlocked')
    payload += serialized(b'Get It Now')
    payload += serialized(UNKNOWN.encode('ascii'))
    version = UnityVersion.from_str('2021.3.0f1')

    class FakeObject:
        def __init__(self, path_id, type_name, values, raw=b''):
            self.path_id = path_id
            self.type = SimpleNamespace(name=type_name)
            self.values = values
            self.byte_start = 0
            self.byte_size = len(payload)
            self.version = version
            self.serialized_type = SimpleNamespace(node=None)
            self.raw = raw

        def read_typetree(self, **kwargs):
            return self.values

        def read(self):
            return self.values

        def get_raw_data(self):
            return self.raw

    ptr = lambda path_id: {'m_FileID': 0, 'm_PathID': path_id}
    script = SimpleNamespace(m_Name='ButtonPremium', m_ClassName='ButtonPremium',
                             m_Namespace='', m_AssemblyName='Assembly-CSharp')
    data = bytes(payload)
    objects = {
        42: FakeObject(42, 'MonoBehaviour', {
            'm_GameObject': ptr(5), 'm_Enabled': 1,
            'm_Script': ptr(1116), 'm_Name': 'premium_unlocked'}, bytes(payload)),
        5: FakeObject(5, 'GameObject', {
            'm_Name': 'premium_unlocked', 'm_IsActive': 1,
            'm_Component': [{'component': ptr(42)}]}),
        6: FakeObject(6, 'GameObject', {
            'm_Name': 'Get It Now', 'm_IsActive': 1,
            'm_Component': [{'component': ptr(42)}]}),
        1116: FakeObject(1116, 'MonoScript', script),
    }
    # Map the two exact needles to distinct serialized GameObject extents; the
    # base component has a separate extent to prevent ambiguous attribution.
    objects[42].byte_start = 0
    objects[42].byte_size = 16
    objects[5].byte_start = data.index(b'premium_unlocked')
    objects[5].byte_size = len(b'premium_unlocked')
    objects[6].byte_start = data.index(b'Get It Now')
    objects[6].byte_size = len(b'Get It Now')
    objects[1116].byte_size = 0
    asset = SimpleNamespace(objects=objects, externals=[],
                            unity_version='2021.3.0f1',
                            header=SimpleNamespace(data_offset=0, version=17,
                                                   file_size=len(payload)))
    return bytes(payload), asset


class PremiumUnityAssetsTest(unittest.TestCase):
    def test_asset_model_and_annotations_hash_unknown_strings(self):
        data, asset = fixture()
        row = probe.inspect_asset_bytes(
            data, refs.TARGET_FILE, asset=asset, script_asset=asset,
            basename_unique=True, script_cache={})
        self.assertEqual(row['needles']['premium_unlocked']['count'], 1)
        self.assertEqual(row['needles']['get_it_now']['count'], 1)
        self.assertEqual(row['objectCount'], 4)
        detail = row['objectDetails'][0]
        self.assertEqual(detail['objectType'], {'safe': 'GameObject'})
        self.assertEqual(detail['needles'], ['get_it_now'])
        mono = probe.monobehaviour_details(asset.objects[42], asset,
                                           refs.TARGET_FILE, asset, True, {})
        self.assertEqual(mono['scriptPathId'], 1116)
        self.assertEqual(mono['storedSchema']['available'], False)
        self.assertTrue(any(token['token'] ==
                            {'safe': 'premium_unlocked'}
                            for token in mono['payloadTokens']))
        self.assertTrue(any(candidate.get('methodToken') ==
                            {'safe': 'clickPremium'}
                            for candidate in mono['localPPtrCandidates']['samples']))
        context_names = [row['context'].get('name')
                         for row in row['gameObjectContexts']]
        self.assertIn({'safe': 'Get It Now'}, context_names)
        self.assertIn({'safe': 'premium_unlocked'}, context_names)
        self.assertTrue(any(
            {'safe': 'ButtonPremium'} in context.get('scriptClasses', [])
            for context in (item['context']
                            for item in row['gameObjectContexts'])))
        report = {
            'kind': probe.KIND, 'baseApkSha256': '0' * 64,
            'unityPyVersion': {'safe': '1.25.4'},
            'scriptIdentityValidated': True, 'scriptCandidateCount': 6,
            'scriptParseErrorCount': 0, 'basenameUnique': True,
            'selectedEntries': [refs.TARGET_FILE], 'files': [row],
            'limitations': 'bounded'}
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            probe.emit_annotations(report)
        output = buffer.getvalue()
        self.assertIn('::warning title=WorldBox Premium Unity asset summary 1/1::', output)
        self.assertIn('::notice title=WorldBox Premium Unity asset file 1/1::', output)
        self.assertIn('::notice title=WorldBox Premium Unity object 1.1::', output)
        self.assertIn('Get It Now', output)
        self.assertNotIn('contextsOmitted', output)
        self.assertNotIn(UNKNOWN, output)
        for line in output.splitlines():
            if line.startswith('::'):
                self.assertLessEqual(len(line), 4096)

    def test_compact_context_keeps_button_pointer_method_associations(self):
        context = {
            'available': True, 'name': 'Get It Now', 'activeSelf': True,
            'activeInHierarchy': True, 'hierarchy': ['Get It Now', 'premium_menu'],
            'componentTypes': ['Button', 'MonoBehaviour'],
            'componentScripts': [{'script': {'className': 'ButtonPremium'}}],
            'buttonPPtrCandidates': [{'buttonIndex': 1, 'buttonPathId': 100,
                'localPPtrMatches': [{'index': 4, 'pathId': 200,
                    'type': 'MonoBehaviour', 'scriptClassName': 'ButtonPremium',
                    'offsets': [316], 'methodTokens': [
                        {'pptrOffset': 316, 'tokenOffset': 332,
                         'candidateMethod': 'clickPremium'}]}]}]}
        compact = probe.compact_context(context)
        self.assertEqual(compact['pointerCalls'][0]['targetPathId'], 200)
        self.assertEqual(compact['pointerCalls'][0]['targetScriptClass'],
                         {'safe': 'ButtonPremium'})
        self.assertEqual(compact['pointerCalls'][0]['methodTokens'],
                         [{'safe': 'clickPremium'}])
        self.assertNotIn('candidateMethod', str(compact))

    def test_sanitize_value_preserves_descriptors_and_hashes_unknowns(self):
        value = {'safe': 'premium_unlocked'}
        self.assertEqual(probe.sanitize_value(value), value)
        sanitized = probe.sanitize_value({'name': UNKNOWN})
        self.assertNotIn(UNKNOWN, str(sanitized))
        self.assertEqual(len(sanitized['name']['sha256']), 64)

    def test_hash_gate_rejects_mismatched_apk(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'base.apk'
            with zipfile.ZipFile(path, 'w') as archive:
                archive.writestr('placeholder.txt', b'x')
            with self.assertRaises(ValueError):
                probe.inspect(path, expected_sha='0' * 64)

    def test_selected_entries_include_both_get_it_now_assets(self):
        entries = [row['entry'] for row in probe.SELECTED_ENTRIES]
        self.assertIn('assets/bin/Data/13cfff6f881b80049833c82202d4227a', entries)
        self.assertIn('assets/bin/Data/6f7d4abbd6fb14eabaad2266d6de4adf', entries)


if __name__ == '__main__':
    unittest.main()

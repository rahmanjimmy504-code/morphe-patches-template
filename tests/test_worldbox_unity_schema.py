"""Synthetic type-tree, component pointer and fail-closed coverage."""
from pathlib import Path
import struct
import sys
from types import SimpleNamespace
import unittest
from UnityPy.helpers.UnityVersion import UnityVersion
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / '.github/scripts'))
import worldbox_unity_schema as probe
from test_worldbox_unity_script_refs import fixture


def node(name, kind, children=()):
    return SimpleNamespace(m_Name=name, m_Type=kind, m_Children=list(children))


class FakeUnityObject:
    def __init__(self, path_id, type_name, values):
        self.path_id = path_id
        self.type = SimpleNamespace(name=type_name)
        self.values = values
        self.version = UnityVersion.from_str('2021.3.0f1')

    def read_typetree(self, **kwargs):
        return self.values

    def read(self):
        return self.values


class FakeAsset:
    def __init__(self, objects, externals=()):
        self.objects = objects
        self.externals = externals


class SchemaTest(unittest.TestCase):
    def test_bounded_game_object_hierarchy_context(self):
        ptr = lambda path_id: {'m_FileID': 0, 'm_PathID': path_id}
        objects = {
            1: FakeUnityObject(1, 'GameObject', {'m_Name': 'Canvas', 'm_IsActive': 1,
                'm_Component': [{'component': ptr(11)}]}),
            2: FakeUnityObject(2, 'GameObject', {'m_Name': 'PremiumWindow', 'm_IsActive': 1,
                'm_Component': [{'component': ptr(12)}, {'component': ptr(13)}]}),
            11: FakeUnityObject(11, 'RectTransform', {'m_Father': ptr(0), 'm_GameObject': ptr(1)}),
            12: FakeUnityObject(12, 'RectTransform', {'m_Father': ptr(11), 'm_GameObject': ptr(2)}),
            13: FakeUnityObject(13, 'MonoBehaviour', {'m_Script': ptr(99)}),
            99: FakeUnityObject(99, 'MonoScript', SimpleNamespace(
                m_Name='Button', m_ClassName='Button', m_Namespace='UnityEngine.UI',
                m_AssemblyName='UnityEngine.UI')),
        }
        asset = FakeAsset(objects)
        context = probe.game_object_context(asset, 2, probe.refs.TARGET_FILE, asset)
        self.assertTrue(context['available'])
        self.assertEqual(context['name'], 'PremiumWindow')
        self.assertTrue(context['activeSelf'])
        self.assertTrue(context['activeInHierarchy'])
        self.assertEqual(context['hierarchy'], ['PremiumWindow', 'Canvas'])
        self.assertEqual(context['componentTypes'], ['RectTransform', 'MonoBehaviour'])
        self.assertEqual(context['componentScripts'], [{'index': 1, 'script': {
            'name': 'Button', 'className': 'Button', 'namespace': 'UnityEngine.UI',
            'assembly': 'UnityEngine.UI'}, 'storedSchema': {'available': False},
            'serializedStringCandidates': []}])
        self.assertFalse(context['hierarchyTruncated'])
        objects[2].values['m_IsActive'] = 0
        inactive = probe.game_object_context(asset, 2, probe.refs.TARGET_FILE, asset)
        self.assertFalse(inactive['activeSelf'])
        self.assertFalse(inactive['activeInHierarchy'])

    def test_local_pointer_reference_detection(self):
        payload = b'head' + struct.pack('<iq', 0, 1700) + b'tail'
        self.assertEqual(probe.pptr_reference_offsets(payload, 1700), [4])
        self.assertEqual(probe.pptr_reference_offsets(payload, 1701), [])

    def test_aligned_serialized_identifier_strings(self):
        value = b'UnlockPremium'
        payload = len(value).to_bytes(4, 'little') + value
        payload += bytes((-len(payload)) % 4)
        self.assertEqual(probe.aligned_serialized_strings(payload), ['UnlockPremium'])
        self.assertEqual(probe.aligned_serialized_strings(b'X' + payload), [])

    def test_canvas_group_state(self):
        component = FakeUnityObject(20, 'CanvasGroup', {
            'm_Alpha': 0.0, 'm_Interactable': 1, 'm_BlocksRaycasts': 0})
        self.assertEqual(probe._canvas_group_state(component), {
            'alpha': 0.0, 'interactable': True, 'blocksRaycasts': False})
        invalid = FakeUnityObject(21, 'CanvasGroup', {
            'm_Alpha': float('nan'), 'm_Interactable': 2, 'm_BlocksRaycasts': 'yes'})
        self.assertEqual(probe._canvas_group_state(invalid), {
            'alpha': None, 'interactable': None, 'blocksRaycasts': None})

    def test_stored_schema_and_safe_filter(self):
        root = node('root', 'MonoBehaviour', [node('isPremium', 'bool'),
                    node('bad\nname', 'secret\nvalue'), node('items', 'PPtr<GameObject>')])
        report = probe.schema(root)
        self.assertEqual(report['topLevelCount'], 3)
        self.assertEqual(report['nodesVisited'], 4)
        self.assertEqual(report['fields'][0], {'name': 'isPremium', 'type': 'bool'})
        self.assertEqual(report['fields'][1], {'name': None, 'type': None})
        self.assertEqual(report['fields'][2]['type'], 'PPtr<GameObject>')
        self.assertFalse(report['nodeLimitReached'])

    def test_limits_and_absent_schema(self):
        self.assertFalse(probe.schema(None)['available'])
        root = node('root', 'Node', [node('field', 'int') for _ in range(probe.MAX_NODES + 5)])
        result = probe.schema(root)
        self.assertTrue(result['fieldsTruncated'])
        self.assertTrue(result['nodeLimitReached'])
        self.assertEqual(result['nodesVisited'], probe.MAX_NODES)

    def test_real_mono_component_base_and_missing_schema(self):
        result = probe.inspect_bytes(fixture(), 'assets/bin/Data/test', {42: 1559})
        row = result['objects'][0]
        self.assertEqual(row['script'], 'PremiumElementsChecker')
        self.assertEqual(row['scriptResolution'], 'external-basename-match')
        self.assertEqual((row['gameObjectFileId'], row['gameObjectPathId']), (0, 5))
        self.assertFalse(row['ownerContext']['available'])
        self.assertFalse(row['schema']['available'])

    def test_wrong_object_script_and_unresolved_reference_fail(self):
        with self.assertRaises(ValueError): probe.inspect_bytes(fixture(), 'assets/bin/Data/test', {42: 2449})
        with self.assertRaises(ValueError): probe.inspect_bytes(fixture(), 'assets/bin/Data/test', {99: 1559})
        with self.assertRaises(ValueError): probe.inspect_bytes(fixture(external='archive:/CAB-X/CAB-X'), 'assets/bin/Data/test', {42: 1559})

if __name__ == '__main__': unittest.main()

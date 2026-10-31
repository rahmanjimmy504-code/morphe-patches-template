"""Synthetic type-tree, component pointer and fail-closed coverage."""
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / '.github/scripts'))
import worldbox_unity_schema as probe
from test_worldbox_unity_script_refs import fixture


def node(name, kind, children=()):
    return SimpleNamespace(m_Name=name, m_Type=kind, m_Children=list(children))


class SchemaTest(unittest.TestCase):
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
        self.assertFalse(row['schema']['available'])

    def test_wrong_object_script_and_unresolved_reference_fail(self):
        with self.assertRaises(ValueError): probe.inspect_bytes(fixture(), 'assets/bin/Data/test', {42: 2449})
        with self.assertRaises(ValueError): probe.inspect_bytes(fixture(), 'assets/bin/Data/test', {99: 1559})
        with self.assertRaises(ValueError): probe.inspect_bytes(fixture(external='archive:/CAB-X/CAB-X'), 'assets/bin/Data/test', {42: 1559})

if __name__ == '__main__': unittest.main()

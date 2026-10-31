"""Real synthetic serialized MonoScript and identifier-output tests."""
from pathlib import Path
import importlib
import struct
import sys
from types import SimpleNamespace
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / '.github/scripts'))
from UnityPy.helpers import TypeTreeHelper
from UnityPy.helpers.UnityVersion import UnityVersion
from UnityPy.streams.EndianBinaryWriter import EndianBinaryWriter
import worldbox_unity_scripts as scan


def script_fixture():
    node = importlib.import_module('UnityPy.files.ObjectReader').get_typetree_node(
        115, UnityVersion.from_str('2021.3.0f1'))
    writer = EndianBinaryWriter(endian='<')
    TypeTreeHelper.write_typetree({'m_Name': 'PremiumScreen', 'm_ExecutionOrder': 0,
        'm_PropertiesHash': {f'bytes[{i}]': 0 for i in range(16)},
        'm_ClassName': 'PremiumScreen', 'm_Namespace': 'Example',
        'm_AssemblyName': 'Assembly-CSharp.dll'}, node, writer)
    obj = writer.bytes
    b = bytearray(bytes(20))
    b += b'2021.3.0f1\0' + struct.pack('<iB', 13, 0) + struct.pack('<i', 1)
    b += struct.pack('<iBh', 115, 0, -1) + bytes(16) + struct.pack('<i', 1)
    while len(b) % 4: b += b'\0'
    b += struct.pack('<qIIi', 1, 0, len(obj), 0) + struct.pack('<ii', 0, 0) + b'\0'
    metadata_size = len(b) - 20
    b += bytes(256 - len(b)) + obj
    b[:20] = struct.pack('>IIII', metadata_size, len(b), 17, 256) + bytes(4)
    return bytes(b)


class ScriptTest(unittest.TestCase):
    def test_actual_fixture_parses_identifier(self):
        result = scan.inspect_bytes(script_fixture())
        self.assertEqual(result['candidateCount'], 1)
        self.assertFalse(result['parseErrors'])
        self.assertEqual(result['matchedIdentifiers'][0]['className'], 'PremiumScreen')
        self.assertEqual(result['matchedIdentifiers'][0]['pathId'], 1)
        self.assertEqual(result['matchedIdentifiers'][0]['assembly'], 'Assembly-CSharp.dll')

    def test_unrelated_and_unsafe_identifiers(self):
        self.assertIsNone(scan.identifiers(SimpleNamespace(m_Name='Store', m_ClassName='Store')))
        info = scan.identifiers(SimpleNamespace(m_Name='premium\nunsafe', m_ClassName='PremiumUI',
                                               m_Namespace='Example', m_AssemblyName='secret\nvalue'))
        self.assertIsNone(info['scriptName'])
        self.assertEqual(info['className'], 'PremiumUI')
        self.assertIsNone(info['assembly'])

    def test_reject_invalid_extent(self):
        b = bytearray(script_fixture())
        pattern = struct.pack('<qI', 1, 0)
        index = b.index(pattern)
        struct.pack_into('<I', b, index + 12, 10000)
        with self.assertRaises(ValueError): scan.inspect_bytes(bytes(b))

    def test_invalid_file(self):
        with self.assertRaises(Exception): scan.inspect_bytes(b'bad')

if __name__ == '__main__': unittest.main()

"""Synthetic serialized MonoBehaviour fixtures and reference resolution."""
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
import worldbox_unity_script_refs as scan


def fixture(file_id=1, script_id=1559, external='archive:/x/globalgamemanagers.assets'):
    version = UnityVersion.from_str('2021.3.0f1')
    node = importlib.import_module('UnityPy.files.ObjectReader').get_typetree_node(114, version)
    writer = EndianBinaryWriter(endian='<')
    TypeTreeHelper.write_typetree({'m_GameObject': {'m_FileID': 0, 'm_PathID': 5}, 'm_Enabled': 1,
                                   'm_Script': {'m_FileID': file_id, 'm_PathID': script_id},
                                   'm_Name': 'synthetic'}, node, writer)
    payload = writer.bytes
    b = bytearray(bytes(20))
    b += b'2021.3.0f1\0' + struct.pack('<iB', 13, 0) + struct.pack('<i', 1)
    # MonoBehaviour requires 16-byte script ID plus old type hash.
    b += struct.pack('<iBh', 114, 0, -1) + bytes(32) + struct.pack('<i', 1)
    while len(b) % 4: b += b'\0'
    b += struct.pack('<qIIi', 42, 0, len(payload), 0)
    b += struct.pack('<i', 0)  # local script types
    b += struct.pack('<i', 1) + b'\0' + bytes(16) + struct.pack('<i', 0) + external.encode() + b'\0'
    b += b'\0'  # user information
    metadata = len(b) - 20
    if len(b) > 512: raise ValueError('fixture too large')
    b += bytes(512 - len(b)) + payload
    b[:20] = struct.pack('>IIII', metadata, len(b), 17, 512) + bytes(4)
    return bytes(b)


class ScriptRefsTest(unittest.TestCase):
    def test_real_serialized_external_reference(self):
        report = scan.inspect_bytes(fixture(), 'assets/bin/Data/level0')
        self.assertEqual(report['monoBehaviourCount'], 1)
        self.assertFalse(report['parseErrors'])
        self.assertEqual(report['candidateCounts'], {'external-basename-match': 1})
        self.assertEqual(report['samples'][0]['script'], 'PremiumElementsChecker')
        self.assertEqual(report['samples'][0]['objectPathId'], 42)

    def test_local_and_unresolved_external(self):
        local = scan.inspect_bytes(fixture(file_id=0), scan.TARGET_FILE)
        self.assertEqual(local['candidateCounts'], {'same-file': 1})
        cab = scan.inspect_bytes(fixture(external='archive:/CAB-f00/CAB-f00'), 'assets/bin/Data/level0')
        self.assertEqual(cab['candidateCounts'], {'unresolved-external': 1})
        other = scan.inspect_bytes(fixture(file_id=0), 'assets/bin/Data/level0')
        self.assertEqual(other['candidateCounts'], {'other-file': 1})

    def test_pointer_resolution_is_conservative(self):
        ext = [SimpleNamespace(path='archive:/x/globalgamemanagers.assets')]
        self.assertEqual(scan.resolve(1, 'level0', ext, scan.TARGET_FILE, True), 'external-basename-match')
        self.assertEqual(scan.resolve(1, 'level0', ext, scan.TARGET_FILE, False), 'unresolved-ambiguous-basename')
        self.assertEqual(scan.resolve(2, 'level0', ext, scan.TARGET_FILE, True), 'unresolved-file-id')

    def test_filter_and_safe_path(self):
        self.assertTrue(scan.selected('assets/bin/Data/level10'))
        self.assertTrue(scan.selected('assets/bin/Data/resources.assets'))
        self.assertFalse(scan.selected('assets/bin/Data/global-metadata.dat'))
        self.assertEqual(scan.safe_path('bad\nname'), '<redacted>')

if __name__ == '__main__': unittest.main()

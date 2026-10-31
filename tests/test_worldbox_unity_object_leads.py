"""Generate a minimal serialized Unity file to validate offset classification."""
from pathlib import Path
import struct
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / '.github/scripts'))
import worldbox_unity_object_leads as scan


def fixture():
    b = bytearray(bytes(20))
    b += b'2021.3.0f1\0' + struct.pack('<iB', 13, 0) + struct.pack('<i', 1)
    b += struct.pack('<iBh', 49, 0, -1) + bytes(16) + struct.pack('<i', 1)
    while len(b) % 4: b += b'\0'
    data = b'prefixpremium-suffix\0'
    b += struct.pack('<qIIi', 1, 0, len(data), 0) + struct.pack('<ii', 0, 0) + b'purchase\0'
    metadata = len(b) - 20
    b += bytes(256 - len(b)) + data
    b[:20] = struct.pack('>IIII', metadata, len(b), 17, 256) + bytes(4)
    return bytes(b)


class UnityObjectTest(unittest.TestCase):
    def test_real_serialized_fixture(self):
        report = scan.inspect_bytes(fixture())
        self.assertEqual(report['objectCount'], 1)
        self.assertEqual(report['categories']['premium']['groups'], {'object:TextAsset': 1})
        self.assertEqual(report['categories']['premium']['samples'][0]['pathId'], 1)
        self.assertEqual(report['categories']['purchase']['groups'], {'pre-data': 1})
        self.assertFalse(report['categories']['premium']['matchLimitReached'])
        self.assertEqual(report['categories']['product']['count'], 0)

    def test_out_of_range_extent_rejected(self):
        b = bytearray(fixture())
        # v17 metadata object table contains path id 1, byte start 0, byte size 21.
        pattern = struct.pack('<qIIi', 1, 0, 21, 0)
        index = b.index(pattern)
        struct.pack_into('<I', b, index + 12, 1000)
        with self.assertRaises(ValueError): scan.inspect_bytes(bytes(b))

    def test_classification_overlap_and_boundary(self):
        obj = object()
        self.assertEqual(scan.classify(3, 4, 10, []), ('pre-data', None))
        self.assertEqual(scan.classify(10, 4, 10, [(10, 14, obj)])[0], 'object')
        self.assertEqual(scan.classify(10, 4, 10, [(10, 14, obj), (9, 15, obj)])[0], 'ambiguous-object')
        self.assertEqual(scan.classify(11, 4, 10, [(10, 14, obj)])[0], 'unmapped-data')

    def test_invalid_data_fails_closed(self):
        with self.assertRaises(Exception): scan.inspect_bytes(b'not a unity file')

if __name__ == '__main__':
    unittest.main()

"""Synthetic archive and serialized-header tests; no game files needed."""
from pathlib import Path
import struct
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / '.github/scripts'))
import worldbox_bundle_inventory as scan

class InventoryTest(unittest.TestCase):
    def test_unity_signatures_and_header(self):
        self.assertEqual(scan.classify(b'UnityFS\0anything', 100, 'assets/a'), 'unity-fs')
        self.assertIsNone(scan.classify(b'UnityFS-no-null', 100, 'assets/a'))
        header = struct.pack('>IIII', 30, 256, 17, 128) + bytes(48)
        self.assertEqual(scan.classify(header, 256, 'assets/example'), 'serialized-file-candidate')
        self.assertIsNone(scan.classify(header, 255, 'assets/example'))
        extended = struct.pack('>IIII', 0, 0, 22, 0) + bytes(4) + struct.pack('>IQQQ', 50, 300, 128, 0)
        self.assertEqual(scan.classify(extended, 300, 'assets/example'), 'serialized-file-candidate')

    def test_nested_and_generic_compression_not_claimed_as_unity(self):
        self.assertEqual(scan.classify(b'\x1f\x8b' + bytes(10), 12, 'assets/data'), 'gzip-container')
        self.assertIsNone(scan.classify(b'\x1f\x8b' + bytes(10), 12, 'lib/data'))
        self.assertEqual(scan.classify(b'PK\x03\x04' + bytes(10), 12, 'assets/data'), 'nested-zip')

    def test_inventory_fixture(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'base.apk'
            with zipfile.ZipFile(p, 'w', zipfile.ZIP_DEFLATED) as z:
                z.writestr('assets/bundle-without-extension', b'UnityFS\0' + bytes(100))
                z.writestr('assets/serialized', struct.pack('>IIII', 10, 128, 17, 64) + bytes(112))
                z.writestr('assets/ordinary', b'nothing')
            report = scan.inspect(p)
        self.assertEqual(report['entriesScanned'], 3)
        self.assertEqual(report['counts'], {'unity-fs': 1, 'serialized-file-candidate': 1})
        self.assertEqual(report['samples'][0]['entry'], 'assets/bundle-without-extension')
        self.assertFalse(report['readErrors'])

    def test_limits_and_unsafe_names(self):
        self.assertEqual(scan.safe('assets/a\nb'), '<redacted>')
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'base.apk'
            with zipfile.ZipFile(p, 'w') as z:
                z.writestr('a', b'x')
                z.writestr('b', b'y')
            old = scan.MAX_ENTRIES
            try:
                scan.MAX_ENTRIES = 1
                report = scan.inspect(p)
            finally:
                scan.MAX_ENTRIES = old
        self.assertTrue(report['entryLimitReached'])
        self.assertEqual(report['entriesScanned'], 1)

if __name__ == '__main__': unittest.main()

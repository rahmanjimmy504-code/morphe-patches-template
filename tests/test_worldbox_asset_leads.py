"""Synthetic Unity data entry scans; no WorldBox files required."""
from pathlib import Path
import io
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / '.github/scripts'))
import worldbox_asset_leads as scan

class AssetLeadsTest(unittest.TestCase):
    def test_cross_chunk_case_utf16_and_no_duplicates(self):
        content = b'xxPREMIUMx' + 'Purchase'.encode('utf-16le') + b'product'
        result, read = scan.scan_stream(io.BytesIO(content), len(content), chunk=3)
        self.assertEqual(read, len(content))
        self.assertEqual(result[('premium','ascii')], {'count': 1, 'sampleOffsets': [2]})
        self.assertEqual(result[('purchase','utf16le')]['count'], 1)
        self.assertEqual(result[('product','ascii')]['count'], 1)

    def test_short_reads_fail(self):
        with self.assertRaises(ValueError):
            scan.scan_stream(io.BytesIO(b'short'), 10, 4)

    def test_filter_order_and_budget(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'base.apk'
            with zipfile.ZipFile(path, 'w', zipfile.ZIP_DEFLATED) as apk:
                apk.writestr('assets/bin/Data/sharedassets0.assets', 'premium')
                apk.writestr('assets/bin/Data/Managed/Metadata/global-metadata.dat', 'premium')
                apk.writestr('assets/bin/Data/globalgamemanagers', 'PRODUCT purchase')
                apk.writestr('lib/arm64-v8a/libil2cpp.so', 'premium')
            result = scan.inspect(path, max_total=18, max_entry=20, chunk=3)
        self.assertEqual(result['eligibleEntries'], 2)
        self.assertEqual(result['results'][0]['entry'], 'assets/bin/Data/globalgamemanagers')
        self.assertTrue(result['truncated'])
        self.assertEqual(result['scannedBytes'], 18)
        self.assertEqual(result['results'][0]['matches'][0]['category'], 'purchase')
        self.assertEqual(result['results'][1]['scannedBytes'], 2)

    def test_entry_limits_and_unsafe_name(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'base.apk'
            with zipfile.ZipFile(path, 'w') as apk:
                apk.writestr('assets/bin/Data/globalgamemanagers', 'abc')
                apk.writestr('assets/bin/Data/StreamingAssets/unsafe\nname', 'premium')
            result = scan.inspect(path, max_entries=1)
        self.assertTrue(result['entriesLimitReached'])
        self.assertEqual(result['entriesScanned'], 1)
        self.assertEqual(scan.safe_name('a\nb', 7), '<redacted-entry-7>')

if __name__ == '__main__':
    unittest.main()

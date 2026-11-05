"""Synthetic-only tests for bounded DEX metadata-path probes."""
import io
from pathlib import Path
import sys
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.github/scripts'))
import worldbox_metadata_java_probe as probe


class MetadataJavaProbeTest(unittest.TestCase):
    def test_chunk_boundary_and_utf16le_occurrences_are_counted(self):
        needle = b'global-metadata.dat'
        data = b'xx' + needle + b'yy'
        with io.BytesIO(data) as handle:
            count, examples = probe.needle_in_stream(handle, needle, chunk_size=8)
        self.assertEqual(count, 1)
        self.assertEqual(examples[0]['offset'], '0x2')
        utf16 = 'global-metadata.dat'.encode('utf-16le')
        with io.BytesIO(b'aa' + utf16) as handle:
            count, examples = probe.needle_in_stream(handle, utf16, chunk_size=7)
        self.assertEqual(count, 1)
        self.assertEqual(examples[0]['offset'], '0x2')

    def test_raw_dex_scan_counts_ascii_and_utf16le_needles(self):
        data = (b'not-a-dex global-metadata.dat ' +
                'global-metadata.dat'.encode('utf-16le'))
        report = probe.raw_dex_scan(data)
        filename = report['results']['metadata_filename']
        self.assertEqual(filename['ascii']['count'], 1)
        self.assertEqual(filename['utf16le']['count'], 1)
        self.assertEqual(filename['ascii']['examples'][0]['kind'], 'dex-content')

    def test_non_dex_entries_are_reported_without_importing_java_parser(self):
        self.assertEqual(probe.dex_parse_report(b'not-a-dex')['status'], 'not-a-dex')

    def test_analyze_apks_reports_one_row_per_dex_entry(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'base.apk'
            data = (b'not-a-dex global-metadata.dat ' +
                    'global-metadata.dat'.encode('utf-16le'))
            with zipfile.ZipFile(path, 'w', zipfile.ZIP_DEFLATED) as apk:
                apk.writestr('classes.dex', data)
                apk.writestr('classes2.dex', data)
            report = probe.analyze_apks([path])
        self.assertEqual(report['kind'], 'worldbox-metadata-java-probe')
        self.assertEqual(len(report['dexFiles']), 2)
        self.assertEqual(report['dexFiles'][0]['parsed']['status'], 'not-a-dex')
        self.assertEqual(report['dexFiles'][0]['raw']['results']['metadata_filename']['ascii']['count'], 1)


if __name__ == '__main__':
    unittest.main()

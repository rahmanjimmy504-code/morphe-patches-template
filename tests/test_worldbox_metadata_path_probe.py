"""Synthetic-only tests for bounded metadata-path probes."""
import io
from pathlib import Path
import sys
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.github/scripts'))
sys.path.insert(0, str(ROOT / 'tests'))
import worldbox_metadata_path_probe as probe
from test_worldbox_native import fixture


class MetadataPathProbeTest(unittest.TestCase):
    def test_chunk_boundary_and_utf16le_occurrences_are_counted(self):
        needle = b'global-metadata.dat'
        data = b'xx' + needle + b'yy'
        with io.BytesIO(data) as handle:
            count, examples = probe.needle_in_stream(handle, needle, chunk_size=8)
        self.assertEqual(count, 1)
        self.assertEqual(examples[0]['offset'], '0x2')
        utf16 = 'global-metadata.dat'.encode('utf-16le')
        with io.BytesIO(b'aa' + utf16 + b'bb') as handle:
            count, examples = probe.needle_in_stream(handle, utf16, chunk_size=7)
        self.assertEqual(count, 1)
        self.assertEqual(examples[0]['offset'], '0x2')

    def test_elf_scan_reports_section_name_without_literal_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'fixture.so'
            path.write_bytes(fixture())
            report = probe.elf_string_scan(path, {'probe': 'open'})
        ascii_result = report['results']['probe']['ascii']
        self.assertEqual(ascii_result['count'], 1)
        self.assertEqual(ascii_result['examples'][0]['section'], '.dynstr')
        self.assertEqual(report['results']['probe']['utf16le']['count'], 0)

    def test_apk_scan_checks_entry_names_and_utf16le_content(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'base.apk'
            entry = 'assets/bin/Data/Managed/Metadata/global-metadata.dat'
            content = (b'xxglobal-metadata.datyy' +
                       'global-metadata.dat'.encode('utf-16le'))
            with zipfile.ZipFile(path, 'w', zipfile.ZIP_DEFLATED) as apk:
                apk.writestr(entry, content)
            report = probe.apk_string_scan(path)
        filename = report['results']['metadata_filename']
        self.assertGreaterEqual(filename['ascii']['count'], 2)
        self.assertGreaterEqual(filename['utf16le']['count'], 1)
        self.assertTrue(any(example.get('kind') == 'entry-name'
                            for example in report['results']['unity_metadata_path']['ascii']['examples']))

    def test_section_context_reports_bounded_window(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'fixture.so'
            path.write_bytes(fixture())
            row = probe.section_context_summary(path, 0x1000)
        self.assertEqual(row['section'], '.dynstr')
        self.assertEqual(row['status'], 'read')
        self.assertEqual(row['contextWindow']['bytesRead'], 6)
        self.assertIsNone(row['contextWindow']['stringCategory'])

    def test_section_characterization_reports_inventory_and_bounded_references(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'fixture.so'
            path.write_bytes(fixture(eh_frame=True))
            report = probe.section_characterization(path, '.dynstr')
        self.assertEqual(report['sectionCount'], 1)
        self.assertEqual(report['sections'][0]['name'], '.dynstr')
        self.assertIn('sha256', report['sections'][0]['dataSummary'])
        self.assertEqual(report['adrpAddReferences']['count'], 0)
        self.assertEqual(report['dataPointers']['count'], 0)
        self.assertEqual(report['relocationAddends']['count'], 0)

    def test_build_report_combines_three_bundle_members(self):
        with tempfile.TemporaryDirectory() as directory:
            native = Path(directory) / 'libil2cpp.so'
            unity = Path(directory) / 'libunity.so'
            base = Path(directory) / 'base.apk'
            native.write_bytes(fixture())
            unity.write_bytes(fixture())
            with zipfile.ZipFile(base, 'w') as apk:
                apk.writestr('assets/bin/Data/Managed/Metadata/global-metadata.dat', b'data')
            report = probe.build_report(native, unity, base)
        self.assertEqual(report['kind'], 'worldbox-metadata-path-probe')
        self.assertEqual([item['role'] for item in report['files']],
                         ['libil2cpp', 'libunity', 'base.apk'])
        self.assertEqual(len(report['sectionContexts']), len(probe.CONTEXT_ADDRESSES))
        self.assertEqual(report['sectionCharacterization']['sectionName'], 'il2cpp')


if __name__ == '__main__':
    unittest.main()

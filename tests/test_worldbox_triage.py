"""Synthetic triage tests; do not require the WorldBox game files."""
import pathlib
import subprocess
import tempfile
import unittest
import zipfile

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / 'docs/worldbox/triage-static.sh'

class StaticTriageTest(unittest.TestCase):
    def test_nested_bundle_with_plaintext_header(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            with zipfile.ZipFile(root / 'base.apk', 'w') as apk:
                apk.writestr('assets/bin/Data/Managed/Metadata/global-metadata.dat',
                             bytes.fromhex('af1bb1fa1d000000') + bytes(512))
            with zipfile.ZipFile(root / 'config.arm64.apk', 'w') as apk:
                apk.writestr('lib/arm64-v8a/libil2cpp.so', b'not-an-elf')
            with zipfile.ZipFile(root / 'bundle.apkm', 'w') as bundle:
                for name in ('base.apk', 'config.arm64.apk'):
                    bundle.write(root / name, name)
            report = root / 'report.md'
            subprocess.run(['bash', str(SCRIPT), str(root / 'bundle.apkm'), str(report)],
                           check=True, stdout=subprocess.DEVNULL)
            text = report.read_text()
            self.assertIn('global-metadata.dat', text)
            self.assertIn('Standard IL2CPP magic (0xFAB11BAF) | **YES**', text)
            self.assertIn('libil2cpp.so', text)
            self.assertIn('not an ELF', text)

    def test_missing_metadata_is_reported(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / 'extracted').mkdir()
            report = root / 'report.md'
            subprocess.run(['bash', str(SCRIPT), str(root / 'extracted'), str(report)],
                           check=True, stdout=subprocess.DEVNULL)
            self.assertIn('No `global-metadata.dat` found', report.read_text())

if __name__ == '__main__':
    unittest.main()

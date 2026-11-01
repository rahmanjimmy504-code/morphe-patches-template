import hashlib
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch
import subprocess

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / '.github' / 'scripts'))
import worldbox_cpp2il_probe as probe


class Cpp2ILProbeTests(unittest.TestCase):
    def test_combines_only_hash_gated_base_and_arm64_native_files(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            base_path = root / 'base.apk'
            arm_path = root / 'arm64.apk'
            output = root / 'merged.apk'
            metadata = b'opaque-metadata-fixture'
            native = b'fixture-il2cpp'
            other = b'fixture-libunity'
            with zipfile.ZipFile(base_path, 'w') as z:
                z.writestr('assets/bin/Data/Managed/Metadata/global-metadata.dat', metadata)
                z.writestr('AndroidManifest.xml', b'fixture-manifest')
            with zipfile.ZipFile(arm_path, 'w') as z:
                z.writestr('lib/arm64-v8a/libil2cpp.so', native)
                z.writestr('lib/arm64-v8a/libunity.so', other)
                z.writestr('lib/armeabi-v7a/libil2cpp.so', b'not-copied')
            with patch.object(probe, 'EXPECTED_BASE', hashlib.sha256(base_path.read_bytes()).hexdigest()), \
                 patch.object(probe, 'EXPECTED_ARM64_IL2CPP', hashlib.sha256(native).hexdigest()):
                count, digest = probe.make_combined_apk(base_path, arm_path, output)
            self.assertEqual(count, 2)
            self.assertEqual(digest, hashlib.sha256(output.read_bytes()).hexdigest())
            with zipfile.ZipFile(output) as z:
                self.assertEqual(set(z.namelist()), {
                    'assets/bin/Data/Managed/Metadata/global-metadata.dat',
                    'AndroidManifest.xml',
                    'lib/arm64-v8a/libil2cpp.so',
                    'lib/arm64-v8a/libunity.so',
                })
                self.assertEqual(z.read('lib/arm64-v8a/libil2cpp.so'), native)
                self.assertEqual(z.read('assets/bin/Data/Managed/Metadata/global-metadata.dat'), metadata)

    def test_cpp2il_failure_is_reported_without_claiming_metadata_recovery(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            base_path = root / 'base.apk'
            arm_path = root / 'arm64.apk'
            binary = root / 'Cpp2IL'
            binary.write_text('synthetic executable placeholder')
            metadata = b'meta'
            native = b'il2cpp'
            with zipfile.ZipFile(base_path, 'w') as z:
                z.writestr('assets/bin/Data/Managed/Metadata/global-metadata.dat', metadata)
            with zipfile.ZipFile(arm_path, 'w') as z:
                z.writestr('lib/arm64-v8a/libil2cpp.so', native)
            output = root / 'out'
            with patch.object(probe, 'EXPECTED_BASE', hashlib.sha256(base_path.read_bytes()).hexdigest()), \
                 patch.object(probe, 'EXPECTED_ARM64_IL2CPP', hashlib.sha256(native).hexdigest()), \
                 patch.object(probe.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1,
                       stdout='FAIL metadata header rejected\n', stderr='')):
                report = probe.run_cpp2il(binary, base_path, arm_path, output, root)
            self.assertEqual(report['cpp2ilExitCode'], 1)
            self.assertFalse(report['metadataRecovered'])
            self.assertEqual(report['diagnosticLines'], ['FAIL metadata header rejected'])

    def test_rejects_unverified_sample_before_execution(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            base_path = root / 'base.apk'
            arm_path = root / 'arm64.apk'
            with zipfile.ZipFile(base_path, 'w') as z:
                z.writestr('assets/bin/Data/Managed/Metadata/global-metadata.dat', b'meta')
            with zipfile.ZipFile(arm_path, 'w') as z:
                z.writestr('lib/arm64-v8a/libil2cpp.so', b'il2cpp')
            with self.assertRaisesRegex(ValueError, 'Base APK hash mismatch'):
                probe.make_combined_apk(base_path, arm_path, root / 'merged.apk')


if __name__ == '__main__':
    unittest.main()

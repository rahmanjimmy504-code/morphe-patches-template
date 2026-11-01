import hashlib
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / '.github' / 'scripts'))
import worldbox_mfuscator_probe as probe


class MfuscatorProbeTests(unittest.TestCase):
    def test_requires_fixup_and_generated_assemblies_before_claiming_recovery(self):
        text = ('Using Plugin: Mfuscator Support\n'
                'Mfuscator header decrypted successfully.\n'
                'Metadata fixup function returned non-null result, using this as fixed metadata.')
        report = probe.classify(0, text, 3)
        self.assertTrue(report['mfuscatorPluginLoaded'])
        self.assertTrue(report['headerDecrypted'])
        self.assertTrue(report['fixupReturnedData'])
        self.assertTrue(report['metadataRecovered'])
        self.assertEqual(report['generatedDllCount'], 3)

    def test_does_not_claim_recovery_for_fixup_only_or_nonzero_exit(self):
        text = ('Mfuscator header decrypted successfully.\n'
                'Metadata fixup function returned non-null result, using this as fixed metadata.')
        self.assertFalse(probe.classify(0, text, 0)['metadataRecovered'])
        self.assertFalse(probe.classify(1, text, 3)['metadataRecovered'])
        self.assertFalse(probe.classify(0, 'Using Plugin: Mfuscator Support\\nMetadata fixup function returned non-null result', 3)['metadataRecovered'])
        self.assertFalse(probe.classify(0, 'magic number check failed', 3)['metadataRecovered'])
        failed_header = ('Using Plugin: Mfuscator Support\\n'
                         'Metadata fixup function threw an exception: Failed to determine header size')
        failure_report = probe.classify(255, failed_header, 0)
        self.assertTrue(failure_report['mfuscatorPluginLoaded'])
        self.assertFalse(failure_report['headerDecrypted'])
        self.assertFalse(failure_report['fixupReturnedData'])
        self.assertFalse(failure_report['metadataRecovered'])

    def test_runs_only_after_sample_hash_and_size_checks(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            binary = root / 'Cpp2IL.dll'
            base_apk = root / 'base.apk'
            native = root / 'libil2cpp.so'
            metadata = root / 'global-metadata.dat'
            binary.write_bytes(b'cli fixture')
            with zipfile.ZipFile(base_apk, 'w') as archive:
                archive.writestr('assets/bin/Data/Managed/Metadata/global-metadata.dat', b'meta')
            native.write_bytes(b'native fixture')
            metadata.write_bytes(b'meta')
            output = root / 'output'
            work = root / 'work'
            plugin = work / 'Plugins' / 'Cpp2IL.Plugin.Mfuscator.dll'
            plugin.parent.mkdir(parents=True)
            plugin.write_bytes(b'plugin fixture')

            completed = subprocess.CompletedProcess([], 0,
                stdout=('Using Plugin: Mfuscator Support\n'
                        'Mfuscator header decrypted successfully.\n'
                        'Metadata fixup function returned non-null result, using this as fixed metadata.'),
                stderr='')

            def fake_run(command, **kwargs):
                self.assertIn('--force-unity-version=2022.3.62', command)
                self.assertEqual(kwargs['cwd'], work)
                assembly = output / 'Assembly-CSharp.dll'
                assembly.parent.mkdir(parents=True, exist_ok=True)
                assembly.write_bytes(b'fixture output')
                return completed

            with patch.object(probe, 'EXPECTED_BASE', hashlib.sha256(base_apk.read_bytes()).hexdigest()), \
                 patch.object(probe, 'EXPECTED_ARM64_IL2CPP', hashlib.sha256(b'native fixture').hexdigest()), \
                 patch.object(probe, 'EXPECTED_METADATA_BYTES', 4), \
                 patch.object(probe.shutil, 'which', return_value='/usr/bin/dotnet'), \
                 patch.object(probe.subprocess, 'run', side_effect=fake_run):
                report = probe.run_probe(binary, base_apk, native, metadata, output, work)
            self.assertTrue(report['metadataRecovered'])
            self.assertEqual(report['generatedDllCount'], 1)
            self.assertEqual(report['toolCommit'], probe.BETTERCPP2IL_COMMIT)

    def test_refuses_unverified_native_library_before_running_tool(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            binary = root / 'Cpp2IL.dll'
            base_apk = root / 'base.apk'
            native = root / 'libil2cpp.so'
            metadata = root / 'global-metadata.dat'
            binary.write_bytes(b'cli fixture')
            with zipfile.ZipFile(base_apk, 'w') as archive:
                archive.writestr('assets/bin/Data/Managed/Metadata/global-metadata.dat', b'fixture')
            native.write_bytes(b'fixture')
            metadata.write_bytes(b'fixture')
            with patch.object(probe, 'EXPECTED_BASE', hashlib.sha256(base_apk.read_bytes()).hexdigest()), \
                 patch.object(probe.subprocess, 'run') as run:
                with self.assertRaisesRegex(ValueError, 'ARM64 libil2cpp.so hash mismatch'):
                    probe.run_probe(binary, base_apk, native, metadata, root / 'out', root / 'work')
                run.assert_not_called()

    def test_sanitizes_temporary_paths_and_limits_diagnostics(self):
        lines = probe.diagnostic_lines('/tmp/private/game ERROR metadata', '/tmp/private', '/tmp/out')
        self.assertEqual(lines, ['<work>/game ERROR metadata'])


if __name__ == '__main__':
    unittest.main()

import hashlib
import os
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / '.github' / 'scripts'))
import worldbox_il2cpp_dumper_probe as probe


class Il2CppDumperRecoveryProbeTests(unittest.TestCase):
    def test_success_requires_parsed_types_and_generated_dlls(self):
        log = ('Metadata Version │ v31\n'
               'Types Dumped │ 12\n'
               'Dumping Pipeline Complete\n'
               'Success! All files generated in output')
        report = probe.classify(0, log, 2)
        self.assertEqual(report['metadataVersion'], '31')
        self.assertEqual(report['typeCount'], 12)
        self.assertTrue(report['metadataRecovered'])
        self.assertFalse(probe.classify(0, log, 0)['metadataRecovered'])
        self.assertFalse(probe.classify(1, log, 2)['metadataRecovered'])
        self.assertFalse(probe.classify(0, 'Dumper failed: invalid metadata', 2)['metadataRecovered'])

    def test_runs_only_with_hash_verified_tool_and_sample(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            binary = root / 'Il2CppDumper'
            archive_path = root / 'Il2CppDumper-linux-x64.tar.gz'
            base_apk = root / 'base.apk'
            native = root / 'libil2cpp.so'
            metadata = root / 'global-metadata.dat'
            executable = b'pinned executable fixture'
            binary.write_bytes(executable)
            with tarfile.open(archive_path, 'w:gz') as archive:
                member = tarfile.TarInfo('Il2CppDumper')
                member.size = len(executable)
                member.mode = 0o755
                import io
                archive.addfile(member, io.BytesIO(executable))
            with zipfile.ZipFile(base_apk, 'w') as archive:
                archive.writestr('assets/bin/Data/Managed/Metadata/global-metadata.dat', b'meta')
            native.write_bytes(b'native fixture')
            metadata.write_bytes(b'meta')
            output = root / 'output'
            temp = root / 'temp'

            completed = subprocess.CompletedProcess([], 0,
                stdout=('Metadata Version │ v31\nTypes Dumped │ 12\n'
                        'Dumping Pipeline Complete\nSuccess! All files generated'), stderr='')

            def fake_run(command, **kwargs):
                self.assertIn('--ignore-magic', command)
                self.assertIn('--arch', command)
                self.assertIn('arm64', command)
                dll = output / 'DummyDll' / 'Assembly-CSharp.dll'
                dll.parent.mkdir(parents=True)
                dll.write_bytes(b'dll fixture')
                return completed

            with patch.object(probe, 'TOOL_ASSET_SHA256', hashlib.sha256(archive_path.read_bytes()).hexdigest()), \
                 patch.object(probe, 'EXPECTED_BASE', hashlib.sha256(base_apk.read_bytes()).hexdigest()), \
                 patch.object(probe, 'EXPECTED_ARM64_IL2CPP', hashlib.sha256(b'native fixture').hexdigest()), \
                 patch.object(probe, 'EXPECTED_METADATA_BYTES', 4), \
                 patch.object(probe.subprocess, 'run', side_effect=fake_run):
                report = probe.run_probe(binary, archive_path, base_apk, native, metadata, output, temp)
            self.assertTrue(report['metadataRecovered'])
            self.assertEqual(report['generatedDllCount'], 1)
            self.assertEqual(report['toolRelease'], 'v1.4.0')

    def test_refuses_unverified_release_asset_before_running_tool(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            binary = root / 'Il2CppDumper'
            archive_path = root / 'Il2CppDumper-linux-x64.tar.gz'
            binary.write_bytes(b'executable')
            archive_path.write_bytes(b'wrong archive')
            base_apk = root / 'base.apk'
            native = root / 'libil2cpp.so'
            metadata = root / 'global-metadata.dat'
            base_apk.write_bytes(b'base')
            native.write_bytes(b'native')
            metadata.write_bytes(b'metadata')
            with patch.object(probe.subprocess, 'run') as run:
                with self.assertRaisesRegex(ValueError, 'release asset hash/content mismatch'):
                    probe.run_probe(binary, archive_path, base_apk, native, metadata,
                                    root / 'out', root / 'temp')
                run.assert_not_called()


if __name__ == '__main__':
    unittest.main()

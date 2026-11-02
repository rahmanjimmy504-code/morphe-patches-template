import hashlib
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / '.github' / 'scripts'))
import worldbox_memory_metadata_extractor_probe as probe


def metadata_bytes(version=31, size=256):
    return ((0xFAB11BAF).to_bytes(4, 'little')
            + version.to_bytes(4, 'little', signed=True)
            + bytes(max(0, size - 8)))[:size]


class WorldBoxMemoryMetadataExtractorProbeTests(unittest.TestCase):
    def test_recovery_requires_exit_success_exact_size_and_v31_magic(self):
        with tempfile.TemporaryDirectory() as td:
            dump = Path(td) / 'dump.dat'
            dump.write_bytes(metadata_bytes())
            with patch.object(probe, 'EXPECTED_METADATA_BYTES', 256):
                result = probe.classify(0, dump)
                self.assertTrue(result['metadataCandidateValidated'])
                self.assertEqual(result['metadataVersion'], 31)
                self.assertFalse(probe.classify(1, dump)['metadataCandidateValidated'])
                self.assertFalse(probe.classify(0, dump, timed_out=True)['metadataCandidateValidated'])
                dump.write_bytes(metadata_bytes(version=30))
                self.assertFalse(probe.classify(0, dump)['metadataCandidateValidated'])
                dump.write_bytes(metadata_bytes(size=255))
                self.assertFalse(probe.classify(0, dump)['metadataCandidateValidated'])

    def test_hash_gated_spawn_and_dump_classification(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            archive = root / 'extractor.zip'
            archive.write_bytes(b'pinned archive fixture')
            source = root / 'source'
            tool_dir = source / f'Il2CppMetadataExtractor-{probe.TOOL_COMMIT}'
            tool_dir.mkdir(parents=True)
            py_script, js_script = tool_dir / 'dump-metadata.py', tool_dir / 'dump-metadata.js'
            py_script.write_bytes(b'python extractor fixture')
            js_script.write_bytes(b'javascript extractor fixture')
            raw_metadata = b'e' * 256
            raw = root / 'raw.dat'
            raw.write_bytes(raw_metadata)
            base = root / 'base.apk'
            with zipfile.ZipFile(base, 'w') as apk:
                apk.writestr('assets/bin/Data/Managed/Metadata/global-metadata.dat', raw_metadata)
            native = root / 'libil2cpp.so'
            native.write_bytes(b'arm64 native sample')
            output = root / 'output'
            output.mkdir()

            def fake_run(command, **kwargs):
                if command[1:4] == ['shell', 'am', 'force-stop']:
                    return subprocess.CompletedProcess(command, 0, '', '')
                self.assertIn('--size', command)
                (output / 'global-metadata.dump.dat').write_bytes(metadata_bytes())
                return subprocess.CompletedProcess(command, 0, 'File Dumped From Memory', '')

            with patch.object(probe, 'TOOL_ARCHIVE_SHA256', hashlib.sha256(archive.read_bytes()).hexdigest()), \
                 patch.object(probe, 'PY_SCRIPT_SHA256', hashlib.sha256(py_script.read_bytes()).hexdigest()), \
                 patch.object(probe, 'JS_SCRIPT_SHA256', hashlib.sha256(js_script.read_bytes()).hexdigest()), \
                 patch.object(probe, 'EXPECTED_BASE', hashlib.sha256(base.read_bytes()).hexdigest()), \
                 patch.object(probe, 'EXPECTED_ARM64_IL2CPP', hashlib.sha256(native.read_bytes()).hexdigest()), \
                 patch.object(probe, 'EXPECTED_METADATA_SHA256', hashlib.sha256(raw_metadata).hexdigest()), \
                 patch.object(probe, 'EXPECTED_METADATA_BYTES', 256), \
                 patch.object(probe.subprocess, 'run', side_effect=fake_run):
                report = probe.run_probe(archive, source, base, native, raw, output)

            self.assertTrue(report['metadataCandidateValidated'])
            self.assertEqual(report['toolCommit'], probe.TOOL_COMMIT)
            self.assertEqual(report['dumpBytes'], 256)
            self.assertEqual(report['metadataVersion'], 31)

    def test_runtime_diagnostics_are_filtered_and_bounded(self):
        def fake_run(command, **kwargs):
            key = tuple(command[1:])
            output = {
                ('shell', 'pidof', probe.PACKAGE): '4242',
                ('shell', 'cat', '/proc/4242/status'): 'Name:\tworldbox\nState:\tT (stopped)\nTracerPid:\t0\nUid:\t0',
                ('shell', 'readlink', '/proc/4242/exe'): '/system/bin/app_process64',
                ('shell', 'cat', '/proc/4242/maps'): '7f00 r-xp 0 0:00 0 /vendor/lib64/libndk_translation.so\n7f01 r-xp 0 0:00 0 /data/app/libil2cpp.so',
                ('shell', 'cat', '/data/local/tmp/worldbox-frida.log'): 'Error: unable to attach at 0x7ff123\nnormal startup',
                ('shell', 'logcat', '-d', '-t', '400'): 'E frida: agent connection closed for com.mkarpenko.worldbox at 0x7ff123\nI unrelated: ignore me',
            }
            return subprocess.CompletedProcess(command, 0, output.get(key, ''), '')

        with patch.object(probe.subprocess, 'run', side_effect=fake_run):
            report = probe.collect_runtime_diagnostics('adb')
        self.assertEqual(report['spawnedProcessPid'], 4242)
        self.assertEqual(report['processStatus'], ['Name:\tworldbox', 'State:\tT (stopped)', 'TracerPid:\t0'])
        self.assertEqual(report['processExecutable'], '/system/bin/app_process64')
        self.assertTrue(report['nativeBridgeMapped'])
        self.assertEqual(report['targetLibrariesMapped'], ['libil2cpp.so'])
        self.assertIn('unable to attach at <address>', report['fridaServerLines'][0])
        self.assertIn('agent connection closed', report['filteredLogcatLines'][0])
        self.assertNotIn('0x7ff123', str(report))
        self.assertLessEqual(len(report['filteredLogcatLines']), 12)

    def test_refuses_unverified_release_before_stopping_or_spawning_app(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            archive, source = root / 'extractor.zip', root / 'source'
            archive.write_bytes(b'unverified archive')
            source.mkdir()
            base, native, metadata = root / 'base.apk', root / 'libil2cpp.so', root / 'raw.dat'
            base.write_bytes(b'base')
            native.write_bytes(b'native')
            metadata.write_bytes(b'metadata')
            with patch.object(probe.subprocess, 'run') as run:
                with self.assertRaisesRegex(ValueError, 'Pinned extractor archive/source hash mismatch'):
                    probe.run_probe(archive, source, base, native, metadata, root / 'output')
                run.assert_not_called()


if __name__ == '__main__':
    unittest.main()

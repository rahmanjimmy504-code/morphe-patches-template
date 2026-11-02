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
            self.assertEqual(report['driverMode'], 'spawn-before-attach')
            self.assertEqual(report['dumpBytes'], 256)
            self.assertEqual(report['metadataVersion'], 31)

    def test_crash_tombstone_summary_keeps_modules_not_addresses(self):
        tombstone = '''
ABI: 'x86_64'
Cmdline: com.mkarpenko.worldbox
signal 11 (SIGSEGV), code 2 (SEGV_ACCERR), fault addr 0x7ff123
backtrace:
  #00 pc 0000000000012345 /vendor/lib64/libndk_translation.so (translate+42)
  #01 pc 000000000006789a /system/lib64/libc.so (abort+10)
'''
        report = probe.summarize_crash_tombstone(tombstone)
        self.assertEqual(report['abi'], 'x86_64')
        self.assertEqual(report['signal'], {'number': 11, 'name': 'SIGSEGV', 'code': 2})
        self.assertEqual(report['backtraceModules'], ['libndk_translation.so', 'libc.so'])
        self.assertNotIn('0x7ff123', str(report))
        self.assertNotIn('0000000000012345', str(report))

    def test_runtime_diagnostics_are_filtered_and_bounded(self):
        def fake_run(command, **kwargs):
            key = tuple(command[1:])
            output = {
                ('get-state',): 'device',
                ('shell', 'pidof', probe.PACKAGE): '4242',
                ('shell', 'pidof', 'worldbox-frida-server'): '4001',
                ('shell', 'cat', '/proc/4242/status'): 'Name:\tworldbox\nState:\tT (stopped)\nTracerPid:\t0\nUid:\t0',
                ('shell', 'readlink', '/proc/4242/exe'): '/system/bin/app_process64',
                ('shell', 'grep', '-E', 'libndk_translation\\.so|libil2cpp\\.so|libunity\\.so', '/proc/4242/maps'): '7f00 r-xp 0 0:00 0 /vendor/lib64/libndk_translation.so\n7f01 r-xp 0 0:00 0 /data/app/libil2cpp.so',
                ('shell', 'cat', '/data/local/tmp/worldbox-frida.log'): 'Error: unable to attach at 0x7ff123\nnormal startup',
                ('shell', 'logcat', '-d', '-t', '400'): 'E frida: agent connection closed for com.mkarpenko.worldbox at 0x7ff123\nI unrelated: ignore me',
            }
            return subprocess.CompletedProcess(command, 0, output.get(key, ''), '')

        with patch.object(probe.subprocess, 'run', side_effect=fake_run):
            report = probe.collect_runtime_diagnostics('adb')
        self.assertEqual(report['adbState'], 'device')
        self.assertEqual(report['spawnedProcessPid'], 4242)
        self.assertEqual(report['fridaServerPidProbeExitCode'], 0)
        self.assertEqual(report['fridaServerPid'], '4001')
        self.assertEqual(report['processStatus'], ['Name:\tworldbox', 'State:\tT (stopped)', 'TracerPid:\t0'])
        self.assertEqual(report['processExecutable'], '/system/bin/app_process64')
        self.assertTrue(report['nativeBridgeMapped'])
        self.assertEqual(report['targetLibrariesMapped'], ['libil2cpp.so'])
        self.assertIn('unable to attach at <address>', report['fridaServerLines'][0])
        self.assertIn('agent connection closed', report['filteredLogcatLines'][0])
        self.assertNotIn('0x7ff123', str(report))
        self.assertLessEqual(len(report['filteredLogcatLines']), 12)

    def test_attach_running_uses_live_pid_and_pinned_scan_script(self):
        created_sources = []

        class FakeScript:
            def on(self, name, callback):
                self.callback = callback
            def load(self):
                self.callback({'type': 'send', 'payload': 'dump ready'}, metadata_bytes())
            def unload(self):
                pass

        class FakeSession:
            def create_script(self, source):
                created_sources.append(source)
                return FakeScript()
            def detach(self):
                pass

        class FakeDevice:
            def attach(self, pid):
                self.pid = pid
                return FakeSession()

        device = FakeDevice()
        fake_frida = type('FakeFrida', (), {'get_usb_device': staticmethod(lambda timeout: device)})
        with tempfile.TemporaryDirectory() as td:
            js_path = Path(td) / 'dump-metadata.js'
            js_path.write_text('// pinned script fixture', encoding='utf-8')
            dump_path = Path(td) / 'dump.dat'
            with (
                patch.dict(sys.modules, {'frida': fake_frida}),
                patch.object(probe.subprocess, 'run',
                             return_value=subprocess.CompletedProcess(['adb'], 0, '1234', '')),
                patch.object(probe, 'EXPECTED_METADATA_BYTES', 256),
            ):
                probe.run_attached_extractor(js_path, dump_path, 2, 'adb')
            self.assertEqual(device.pid, 1234)
            self.assertIn('fileSize=256', created_sources[0])
            self.assertIn("filePattern='af 1b b1 fa 1? 00 00 00 00'", created_sources[0])
            self.assertEqual(dump_path.read_bytes(), metadata_bytes())

    def test_runtime_diagnostics_handle_missing_spawned_process(self):
        def fake_run(command, **kwargs):
            output = 'device' if command[1:] == ['get-state'] else ''
            return subprocess.CompletedProcess(command, 0, output, '')

        with patch.object(probe.subprocess, 'run', side_effect=fake_run):
            report = probe.collect_runtime_diagnostics('adb')
        self.assertEqual(report['adbState'], 'device')
        self.assertIsNone(report['spawnedProcessPid'])
        self.assertEqual(report['fridaServerLines'], [])
        self.assertEqual(report['filteredLogcatLines'], [])
        self.assertNotIn('processExecutable', report)

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

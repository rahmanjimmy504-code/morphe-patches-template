import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / '.github' / 'scripts'))
import worldbox_inspector_redux_probe as probe


def valid_metadata(version=31):
    return (0xFAB11BAF).to_bytes(4, 'little') + version.to_bytes(4, 'little', signed=True) + bytes(244)


class Il2CppInspectorReduxProbeTests(unittest.TestCase):
    def test_metadata_recovery_requires_valid_analysis_and_normalized_v31(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            report = root / 'metadata.json'
            metadata = root / 'normalized.dat'
            report.write_text(json.dumps({'assemblies': []}), encoding='utf-8')
            metadata.write_bytes(valid_metadata())
            result = probe.classify(0, report, metadata)
            self.assertTrue(result['analysisReportValid'])
            self.assertTrue(result['metadataAccepted'])
            self.assertTrue(result['metadataRecovered'])
            self.assertEqual(result['metadataVersion'], 31)

            metadata.write_bytes(valid_metadata(version=30))
            self.assertFalse(probe.classify(0, report, metadata)['metadataRecovered'])
            metadata.unlink()
            self.assertFalse(probe.classify(0, report, metadata)['metadataRecovered'])
            self.assertFalse(probe.classify(1, report, metadata)['metadataAccepted'])

    def test_runs_only_with_verified_release_and_worldbox_sample(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            binary = root / 'Il2CppInspector.Redux.CLI'
            archive_path = root / 'redux.zip'
            binary_bytes = b'pinned executable fixture'
            binary.write_bytes(binary_bytes)
            with zipfile.ZipFile(archive_path, 'w') as archive:
                archive.writestr('linux/Il2CppInspector.Redux.CLI', binary_bytes)
            raw_metadata = b'worldbox encrypted metadata fixture'
            base_apk = root / 'base.apk'
            with zipfile.ZipFile(base_apk, 'w') as archive:
                archive.writestr('assets/bin/Data/Managed/Metadata/global-metadata.dat', raw_metadata)
            native = root / 'libil2cpp.so'
            native.write_bytes(b'arm64 native fixture')
            metadata = root / 'global-metadata.dat'
            metadata.write_bytes(raw_metadata)
            output, temp = root / 'out', root / 'work'

            def fake_run(command, **kwargs):
                self.assertIn('--bin', command)
                self.assertIn('--metadata', command)
                self.assertIn('--metadata-out', command)
                self.assertIn('2022.3.62', command)
                json_path = Path(command[command.index('--json-out') + 1])
                metadata_path = Path(command[command.index('--metadata-out') + 1])
                json_path.write_text(json.dumps({'assemblies': ['Assembly-CSharp']}), encoding='utf-8')
                metadata_path.write_bytes(valid_metadata())
                return subprocess.CompletedProcess(command, 0, stdout='Metadata Version v31', stderr='')

            with patch.object(probe, 'TOOL_ASSET_SHA256', hashlib.sha256(archive_path.read_bytes()).hexdigest()), \
                 patch.object(probe, 'EXPECTED_BASE', hashlib.sha256(base_apk.read_bytes()).hexdigest()), \
                 patch.object(probe, 'EXPECTED_ARM64_IL2CPP', hashlib.sha256(native.read_bytes()).hexdigest()), \
                 patch.object(probe, 'EXPECTED_METADATA_BYTES', len(raw_metadata)), \
                 patch.object(probe.subprocess, 'run', side_effect=fake_run):
                result = probe.run_probe(binary, archive_path, base_apk, native, metadata, output, temp)

            self.assertTrue(result['metadataRecovered'])
            self.assertTrue(result['metadataAccepted'])
            self.assertEqual(result['metadataVersion'], 31)
            self.assertEqual(result['normalizedMetadataBytes'], 252)
            self.assertEqual(result['toolRelease'], '2026.2')

    def test_refuses_asset_mismatch_without_launching_tool(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            binary, archive = root / 'cli', root / 'release.zip'
            binary.write_bytes(b'executable')
            archive.write_bytes(b'unverified')
            base, native, metadata = root / 'base.apk', root / 'libil2cpp.so', root / 'metadata.dat'
            base.write_bytes(b'base')
            native.write_bytes(b'native')
            metadata.write_bytes(b'metadata')
            with patch.object(probe.subprocess, 'run') as run:
                with self.assertRaisesRegex(ValueError, 'release asset hash/content mismatch'):
                    probe.run_probe(binary, archive, base, native, metadata, root / 'out', root / 'work')
                run.assert_not_called()


if __name__ == '__main__':
    unittest.main()

#!/usr/bin/env python3
"""Run BetterCpp2IL's pinned MFuscator fixup against the hash-gated WorldBox sample."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import zipfile

EXPECTED_BASE = 'ab7c6bab7d2233c26a9e18426aa58dd60fa0ae0ad9be6fa0b2a6673dd8f89c3f'
EXPECTED_METADATA_BYTES = 12_878_248
EXPECTED_ARM64_IL2CPP = '1d644b98fec97a35630495c695515861acd2c18209beaae6471a650db65def87'
BETTERCPP2IL_COMMIT = '43850f644a1584a8ca700cab2f71f4b2462eb255'
UNITY_VERSION = '2022.3.62'


def sha256(path):
    with Path(path).open('rb') as handle:
        return hashlib.file_digest(handle, 'sha256').hexdigest()


def count_dlls(root):
    return sum(1 for path in Path(root).rglob('*.dll') if path.is_file())


def metadata_matches_base(base_apk, metadata):
    entry = 'assets/bin/Data/Managed/Metadata/global-metadata.dat'
    try:
        with zipfile.ZipFile(base_apk) as archive:
            with archive.open(entry) as source:
                return hashlib.file_digest(source, 'sha256').hexdigest() == sha256(metadata)
    except (KeyError, OSError, zipfile.BadZipFile):
        return False


def diagnostic_lines(text, work_dir, output_dir):
    selected = []
    for line in text.splitlines():
        if not re.search(r'Mfuscator|metadata|fixup|exception|error|failed|initialized|pipeline', line, re.I):
            continue
        line = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', line)
        line = line.replace(str(work_dir), '<work>').replace(str(output_dir), '<output>')
        line = re.sub(r'/tmp/[^\s]+', '<temp-path>', line)
        line = re.sub(r'\s+', ' ', line).strip()
        if line and len(line) <= 360:
            selected.append(line)
        if len(selected) >= 16:
            break
    return selected


def classify(returncode, combined_log, dll_count):
    plugin_loaded = 'Using Plugin: Mfuscator Support' in combined_log
    fixup_returned_data = 'Metadata fixup function returned non-null result' in combined_log
    header_decrypted = 'Mfuscator header decrypted successfully' in combined_log
    return {
        'exitCode': returncode,
        'mfuscatorPluginLoaded': plugin_loaded,
        'fixupReturnedData': fixup_returned_data,
        'headerDecrypted': header_decrypted,
        'generatedDllCount': dll_count,
        'metadataRecovered': (returncode == 0 and plugin_loaded and header_decrypted
                              and fixup_returned_data and dll_count > 0),
    }


def run_probe(binary, base_apk, native, metadata, output_dir, work_dir, timeout=1500):
    binary, base_apk, native, metadata = map(Path, (binary, base_apk, native, metadata))
    output_dir, work_dir = Path(output_dir), Path(work_dir)
    for label, path in (('BetterCpp2IL assembly', binary), ('base APK', base_apk),
                        ('ARM64 libil2cpp.so', native), ('global-metadata.dat', metadata)):
        if not path.is_file():
            raise ValueError(f'{label} is missing')
    if sha256(base_apk) != EXPECTED_BASE:
        raise ValueError('Base APK hash mismatch; refusing MFuscator analysis')
    if sha256(native) != EXPECTED_ARM64_IL2CPP:
        raise ValueError('ARM64 libil2cpp.so hash mismatch; refusing MFuscator analysis')
    if metadata.stat().st_size != EXPECTED_METADATA_BYTES:
        raise ValueError('global-metadata.dat size mismatch; refusing MFuscator analysis')
    if not metadata_matches_base(base_apk, metadata):
        raise ValueError('global-metadata.dat does not match the hash-gated base APK; refusing MFuscator analysis')
    if not shutil.which('dotnet'):
        raise ValueError('dotnet runtime is missing')

    output_dir.mkdir(parents=True, exist_ok=True)
    work_dir.mkdir(parents=True, exist_ok=True)
    plugin = work_dir / 'Plugins' / 'Cpp2IL.Plugin.Mfuscator.dll'
    if not plugin.is_file():
        raise ValueError('Mfuscator plugin DLL is missing from the configured Plugins directory')
    command = [
        shutil.which('dotnet'), str(binary),
        f'--force-binary-path={native}',
        f'--force-metadata-path={metadata}',
        f'--force-unity-version={UNITY_VERSION}',
        '--output-as=dll_empty',
        f'--output-to={output_dir}',
    ]
    child_env = dict(os.environ)
    child_env['NO_COLOR'] = 'true'
    try:
        result = subprocess.run(command, cwd=work_dir, capture_output=True, text=True,
                                timeout=timeout, env=child_env)
        combined_log = (result.stdout or '') + '\n' + (result.stderr or '')
        classification = classify(result.returncode, combined_log, count_dlls(output_dir))
    except subprocess.TimeoutExpired as exc:
        out = exc.stdout.decode(errors='replace') if isinstance(exc.stdout, bytes) else (exc.stdout or '')
        err = exc.stderr.decode(errors='replace') if isinstance(exc.stderr, bytes) else (exc.stderr or '')
        combined_log = out + '\n' + err
        classification = classify(124, combined_log, count_dlls(output_dir))
        classification['timedOut'] = True

    return {
        'kind': 'worldbox-bettercpp2il-mfuscator-probe',
        'tool': 'BetterCpp2IL',
        'toolCommit': BETTERCPP2IL_COMMIT,
        'unityVersion': UNITY_VERSION,
        'metadataBytes': metadata.stat().st_size,
        'baseApkSha256': sha256(base_apk),
        'metadataSha256': sha256(metadata),
        'arm64Il2CppSha256': sha256(native),
        **classification,
        'diagnosticLines': diagnostic_lines(combined_log, work_dir, output_dir),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', required=True, help='Path to published Cpp2IL.dll')
    parser.add_argument('--base-apk', required=True, help='Hash-gated WorldBox base APK')
    parser.add_argument('--native', required=True, help='Hash-gated ARM64 libil2cpp.so')
    parser.add_argument('--metadata', required=True, help='Expected WorldBox global-metadata.dat')
    parser.add_argument('--output-dir', required=True)
    parser.add_argument('--work-dir', required=True, help='Working directory containing the Plugins folder')
    parser.add_argument('--timeout', type=int, default=1500)
    args = parser.parse_args()
    print(json.dumps(run_probe(args.binary, args.base_apk, args.native, args.metadata,
                               args.output_dir, args.work_dir, args.timeout), separators=(',', ':')))


if __name__ == '__main__':
    main()

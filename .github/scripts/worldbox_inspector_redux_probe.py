#!/usr/bin/env python3
"""Run a pinned Il2CppInspectorRedux release against the hash-gated WorldBox sample."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import zipfile

EXPECTED_BASE = 'ab7c6bab7d2233c26a9e18426aa58dd60fa0ae0ad9be6fa0b2a6673dd8f89c3f'
EXPECTED_METADATA_BYTES = 12_878_248
EXPECTED_ARM64_IL2CPP = '1d644b98fec97a35630495c695515861acd2c18209beaae6471a650db65def87'
TOOL_RELEASE = '2026.2'
TOOL_ASSET_SHA256 = '10429eb06f007a5e011f680e83109eca2a7a1cef4d946f37bf2adf439280f269'
EXPECTED_METADATA_VERSION = 31


def sha256(path):
    with Path(path).open('rb') as handle:
        return hashlib.file_digest(handle, 'sha256').hexdigest()


def verified_release_binary(release_archive, binary):
    if sha256(release_archive) != TOOL_ASSET_SHA256:
        return False
    try:
        with zipfile.ZipFile(release_archive) as archive:
            matches = [member for member in archive.infolist()
                       if not member.is_dir() and Path(member.filename).name == Path(binary).name]
            if len(matches) != 1:
                return False
            with archive.open(matches[0]) as source:
                return hashlib.file_digest(source, 'sha256').hexdigest() == sha256(binary)
    except (OSError, zipfile.BadZipFile):
        return False


def metadata_matches_base(base_apk, metadata):
    entry = 'assets/bin/Data/Managed/Metadata/global-metadata.dat'
    try:
        with zipfile.ZipFile(base_apk) as archive:
            with archive.open(entry) as source:
                return hashlib.file_digest(source, 'sha256').hexdigest() == sha256(metadata)
    except (KeyError, OSError, zipfile.BadZipFile):
        return False


def metadata_header(path):
    path = Path(path)
    if not path.is_file() or path.stat().st_size < 252:
        return None, None
    with path.open('rb') as handle:
        header = handle.read(8)
    if len(header) < 8:
        return None, None
    magic = int.from_bytes(header[:4], 'little')
    version = int.from_bytes(header[4:8], 'little', signed=True)
    return magic, version


def classify(returncode, json_path, normalized_metadata):
    magic, version = metadata_header(normalized_metadata)
    report_exists = Path(json_path).is_file() and Path(json_path).stat().st_size > 0
    json_valid = False
    if report_exists:
        try:
            json.loads(Path(json_path).read_text(encoding='utf-8'))
            json_valid = True
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            pass
    parsed = returncode == 0 and json_valid
    normalized = magic == 0xFAB11BAF and version == EXPECTED_METADATA_VERSION
    return {
        'exitCode': returncode,
        'analysisReportValid': json_valid,
        'metadataVersion': version,
        'normalizedMagicValid': magic == 0xFAB11BAF,
        'normalizedMetadataValid': normalized,
        'metadataAccepted': parsed,
        'metadataRecovered': parsed and normalized,
    }


def diagnostic_lines(text, temp_dir, output_dir):
    selected = []
    text = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', text)
    for line in text.splitlines():
        if not re.search(r'metadata|xor|deobfus|loader|error|warning|analysis|parse|version|success|failed', line, re.I):
            continue
        line = line.replace(str(temp_dir), '<temp>').replace(str(output_dir), '<output>')
        line = re.sub(r'/tmp/[^\s]+', '<temp-path>', line)
        line = re.sub(r'\s+', ' ', line).strip()
        if line and len(line) <= 320:
            selected.append(line)
        if len(selected) >= 16:
            break
    return selected


def run_probe(binary, release_archive, base_apk, native, metadata, output_dir, temp_dir, timeout=1500):
    binary, release_archive, base_apk, native, metadata = map(Path,
        (binary, release_archive, base_apk, native, metadata))
    output_dir, temp_dir = Path(output_dir), Path(temp_dir)
    for label, path in (('Il2CppInspectorRedux executable', binary), ('release archive', release_archive),
                        ('base APK', base_apk), ('ARM64 libil2cpp.so', native),
                        ('global-metadata.dat', metadata)):
        if not path.is_file():
            raise ValueError(f'{label} is missing')
    if not verified_release_binary(release_archive, binary):
        raise ValueError('Il2CppInspectorRedux release asset hash/content mismatch; refusing analysis')
    if sha256(base_apk) != EXPECTED_BASE:
        raise ValueError('Base APK hash mismatch; refusing analysis')
    if sha256(native) != EXPECTED_ARM64_IL2CPP:
        raise ValueError('ARM64 libil2cpp.so hash mismatch; refusing analysis')
    if metadata.stat().st_size != EXPECTED_METADATA_BYTES:
        raise ValueError('global-metadata.dat size mismatch; refusing analysis')
    if not metadata_matches_base(base_apk, metadata):
        raise ValueError('global-metadata.dat does not match the hash-gated base APK; refusing analysis')

    output_dir.mkdir(parents=True, exist_ok=True)
    temp_dir.mkdir(parents=True, exist_ok=True)
    json_output = output_dir / 'inspector-metadata.json'
    normalized_metadata = output_dir / 'normalized-global-metadata.dat'
    command = [str(binary), '--bin', str(native), '--metadata', str(metadata),
               '--metadata-out', str(normalized_metadata), '--select-outputs',
               '--json-out', str(json_output), '--unity-version', '2022.3.62']
    child_env = dict(os.environ)
    child_env['NO_COLOR'] = 'true'
    child_env['TERM'] = 'dumb'
    try:
        result = subprocess.run(command, cwd=temp_dir, capture_output=True, text=True,
                                timeout=timeout, env=child_env)
        combined_log = (result.stdout or '') + '\n' + (result.stderr or '')
        classification = classify(result.returncode, json_output, normalized_metadata)
    except subprocess.TimeoutExpired as exc:
        out = exc.stdout.decode(errors='replace') if isinstance(exc.stdout, bytes) else (exc.stdout or '')
        err = exc.stderr.decode(errors='replace') if isinstance(exc.stderr, bytes) else (exc.stderr or '')
        combined_log = out + '\n' + err
        classification = classify(124, json_output, normalized_metadata)
        classification['timedOut'] = True

    normalized_exists = normalized_metadata.is_file()
    return {
        'kind': 'worldbox-il2cppinspector-redux-probe',
        'tool': 'LukeFZ/Il2CppInspectorRedux',
        'toolRelease': TOOL_RELEASE,
        'toolAssetSha256': sha256(release_archive),
        'toolExecutableSha256': sha256(binary),
        'metadataBytes': metadata.stat().st_size,
        'baseApkSha256': sha256(base_apk),
        'metadataSha256': sha256(metadata),
        'arm64Il2CppSha256': sha256(native),
        'normalizedMetadataBytes': normalized_metadata.stat().st_size if normalized_exists else 0,
        'normalizedMetadataSha256': sha256(normalized_metadata) if normalized_exists else None,
        **classification,
        'diagnosticLines': diagnostic_lines(combined_log, temp_dir, output_dir),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', required=True, help='Executable extracted from the pinned Redux release')
    parser.add_argument('--release-archive', required=True, help='Pinned Linux x64 release archive')
    parser.add_argument('--base-apk', required=True, help='Hash-gated WorldBox base APK')
    parser.add_argument('--native', required=True, help='Hash-gated ARM64 libil2cpp.so')
    parser.add_argument('--metadata', required=True, help='Expected WorldBox global-metadata.dat')
    parser.add_argument('--output-dir', required=True)
    parser.add_argument('--temp-dir', required=True)
    parser.add_argument('--timeout', type=int, default=1500)
    args = parser.parse_args()
    print(json.dumps(run_probe(args.binary, args.release_archive, args.base_apk,
        args.native, args.metadata, args.output_dir, args.temp_dir, args.timeout), separators=(',', ':')))


if __name__ == '__main__':
    main()

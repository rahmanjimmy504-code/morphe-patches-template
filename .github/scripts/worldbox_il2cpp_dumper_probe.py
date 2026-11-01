#!/usr/bin/env python3
"""Try a pinned IL2CPP metadata-recovery tool against the hash-gated WorldBox sample."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
import zipfile

EXPECTED_BASE = 'ab7c6bab7d2233c26a9e18426aa58dd60fa0ae0ad9be6fa0b2a6673dd8f89c3f'
EXPECTED_METADATA_BYTES = 12_878_248
EXPECTED_ARM64_IL2CPP = '1d644b98fec97a35630495c695515861acd2c18209beaae6471a650db65def87'
TOOL_RELEASE = 'v1.4.0'
TOOL_ASSET_SHA256 = '66ace171cc9acd550f95ec4c42805c419492033ed44186e7e5921c9dc23abfec'


def sha256(path):
    with Path(path).open('rb') as handle:
        return hashlib.file_digest(handle, 'sha256').hexdigest()


def verified_release_binary(release_archive, binary):
    if sha256(release_archive) != TOOL_ASSET_SHA256:
        return False
    try:
        with tarfile.open(release_archive, 'r:gz') as archive:
            matches = [member for member in archive.getmembers()
                       if member.isfile() and member.name.rstrip('/') == 'Il2CppDumper']
            if len(matches) != 1:
                return False
            source = archive.extractfile(matches[0])
            if source is None:
                return False
            with source:
                return hashlib.file_digest(source, 'sha256').hexdigest() == sha256(binary)
    except (OSError, tarfile.TarError):
        return False


def metadata_matches_base(base_apk, metadata):
    entry = 'assets/bin/Data/Managed/Metadata/global-metadata.dat'
    try:
        with zipfile.ZipFile(base_apk) as archive:
            with archive.open(entry) as source:
                return hashlib.file_digest(source, 'sha256').hexdigest() == sha256(metadata)
    except (KeyError, OSError, zipfile.BadZipFile):
        return False


def count_dlls(root):
    return sum(1 for path in Path(root).rglob('*.dll') if path.is_file())


def strip_ansi(text):
    return re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', text)


def classify(returncode, combined_log, dll_count):
    clean = strip_ansi(combined_log)
    version_match = re.search(r'Metadata Version[^\d]{0,24}v?(\d+(?:\.\d+)?)', clean, re.I)
    types_match = re.search(r'Types Dumped[^\d]{0,24}([\d,]+)', clean, re.I)
    type_count = int(types_match.group(1).replace(',', '')) if types_match else 0
    recovery_match = re.search(r'Metadata Recovery\s+([^\r\n]+)', clean, re.I)
    succeeded = ('Success! All files generated' in clean or 'Dumping Pipeline Complete' in clean)
    return {
        'exitCode': returncode,
        'recoveryAttemptReported': recovery_match is not None,
        'recoveryDescription': recovery_match.group(1).strip()[:120] if recovery_match else None,
        'metadataVersion': version_match.group(1) if version_match else None,
        'typeCount': type_count,
        'generatedDllCount': dll_count,
        'metadataRecovered': returncode == 0 and succeeded and type_count > 0 and dll_count > 0,
    }


def diagnostic_lines(text, temp_dir, output_dir):
    selected = []
    for line in strip_ansi(text).splitlines():
        if not re.search(r'recover|metadata|version|type|dumped|success|fail|error|magic|xor|confidence|parsed|assembly', line, re.I):
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
    binary, release_archive, base_apk, native, metadata = map(Path, (binary, release_archive, base_apk, native, metadata))
    output_dir, temp_dir = Path(output_dir), Path(temp_dir)
    for label, path in (('Il2CppDumper v1.4.0 executable', binary), ('release archive', release_archive),
                        ('base APK', base_apk), ('ARM64 libil2cpp.so', native),
                        ('global-metadata.dat', metadata)):
        if not path.is_file():
            raise ValueError(f'{label} is missing')
    if not verified_release_binary(release_archive, binary):
        raise ValueError('Il2CppDumper release asset hash/content mismatch; refusing analysis')
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
    command = [str(binary), str(native), str(metadata), str(output_dir),
               '--arch', 'arm64', '--unity', '2022.3.62', '--ignore-magic', '--dummy', '--no-open']
    child_env = dict(os.environ)
    child_env['NO_COLOR'] = 'true'
    child_env['TERM'] = 'dumb'
    try:
        result = subprocess.run(command, cwd=temp_dir, capture_output=True, text=True,
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
        'kind': 'worldbox-il2cpp-dumper-recovery-probe',
        'tool': 'MyDearMoon/il2cpp-Dumper',
        'toolRelease': TOOL_RELEASE,
        'toolAssetSha256': sha256(release_archive),
        'toolExecutableSha256': sha256(binary),
        'metadataBytes': metadata.stat().st_size,
        'baseApkSha256': sha256(base_apk),
        'metadataSha256': sha256(metadata),
        'arm64Il2CppSha256': sha256(native),
        **classification,
        'diagnosticLines': diagnostic_lines(combined_log, temp_dir, output_dir),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', required=True, help='Il2CppDumper executable extracted from the pinned archive')
    parser.add_argument('--release-archive', required=True, help='Pinned release asset archive')
    parser.add_argument('--base-apk', required=True, help='Hash-gated WorldBox base APK')
    parser.add_argument('--native', required=True, help='Hash-gated ARM64 libil2cpp.so')
    parser.add_argument('--metadata', required=True, help='Expected WorldBox global-metadata.dat')
    parser.add_argument('--output-dir', required=True)
    parser.add_argument('--temp-dir', required=True)
    parser.add_argument('--timeout', type=int, default=1500)
    args = parser.parse_args()
    print(json.dumps(run_probe(args.binary, args.release_archive, args.base_apk, args.native,
                               args.metadata, args.output_dir, args.temp_dir, args.timeout), separators=(',', ':')))


if __name__ == '__main__':
    main()

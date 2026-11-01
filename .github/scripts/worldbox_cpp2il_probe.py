#!/usr/bin/env python3
"""Try pinned Cpp2IL metadata recovery on the hash-gated WorldBox ARM64 sample."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import zipfile

EXPECTED_BASE = 'ab7c6bab7d2233c26a9e18426aa58dd60fa0ae0ad9be6fa0b2a6673dd8f89c3f'
EXPECTED_ARM64_IL2CPP = '1d644b98fec97a35630495c695515861acd2c18209beaae6471a650db65def87'


def sha256(path):
    with Path(path).open('rb') as handle:
        return hashlib.file_digest(handle, 'sha256').hexdigest()


def make_combined_apk(base_apk, arm64_apk, destination):
    base_apk, arm64_apk = Path(base_apk), Path(arm64_apk)
    if sha256(base_apk) != EXPECTED_BASE:
        raise ValueError('Base APK hash mismatch; refusing Cpp2IL analysis')
    with zipfile.ZipFile(base_apk) as base, zipfile.ZipFile(arm64_apk) as abi:
        native = [item for item in abi.infolist()
                  if item.filename.startswith('lib/arm64-v8a/') and item.filename.endswith('.so')]
        il2cpp = next((item for item in native if item.filename == 'lib/arm64-v8a/libil2cpp.so'), None)
        if il2cpp is None:
            raise ValueError('ARM64 split has no libil2cpp.so')
        digest = hashlib.sha256()
        with abi.open(il2cpp) as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b''):
                digest.update(chunk)
        if digest.hexdigest() != EXPECTED_ARM64_IL2CPP:
            raise ValueError('ARM64 libil2cpp.so hash mismatch; refusing Cpp2IL analysis')
        if not any(item.filename == 'assets/bin/Data/Managed/Metadata/global-metadata.dat'
                   for item in base.infolist()):
            raise ValueError('Base APK does not contain the expected IL2CPP metadata entry')
        seen = set()
        with zipfile.ZipFile(destination, 'w', allowZip64=True) as merged:
            for item in base.infolist():
                if item.filename in seen:
                    raise ValueError('Duplicate entry in base APK')
                seen.add(item.filename)
                merged.writestr(item, base.read(item.filename))
            for item in native:
                if item.filename in seen:
                    raise ValueError('ABI library unexpectedly duplicates a base entry')
                seen.add(item.filename)
                merged.writestr(item, abi.read(item.filename))
    return len(native), sha256(destination)


def run_cpp2il(binary, base_apk, arm64_apk, output_root, temp_dir):
    binary, output_root, temp_dir = Path(binary), Path(output_root), Path(temp_dir)
    if not binary.is_file():
        raise ValueError('Cpp2IL executable is missing')
    merged = temp_dir / 'worldbox-arm64-combined.apk'
    native_count, merged_hash = make_combined_apk(base_apk, arm64_apk, merged)
    output_root.mkdir(parents=True, exist_ok=True)
    command = [str(binary), f'--game-path={merged}', '--skip-analysis',
               '--skip-method-dumps', '--skip-metadata-txts', '--disable-registration-prompts',
               f'--output-root={output_root}']
    child_env = dict(os.environ)
    child_env['NO_COLOR'] = 'true'
    result = subprocess.run(command, capture_output=True, text=True, timeout=1200, env=child_env)
    dlls = sum(1 for path in output_root.rglob('*.dll') if path.is_file())
    combined_log = (result.stdout or '') + '\n' + (result.stderr or '')
    safe_lines = []
    for line in combined_log.splitlines():
        if not re.search(r'FAIL|ERROR|metadata|version|registration|exception|unsupported', line, re.I):
            continue
        line = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', line)
        line = line.replace(str(temp_dir), '<temp>').replace(str(output_root), '<output>')
        line = re.sub(r'/tmp/[^\s]+', '<temp-path>', line)
        line = re.sub(r'\s+', ' ', line).strip()
        if line and len(line) <= 300:
            safe_lines.append(line)
        if len(safe_lines) >= 8:
            break
    return {
        'kind': 'worldbox-cpp2il-probe',
        'cpp2ilExitCode': result.returncode,
        'generatedDllCount': dlls,
        'combinedApkBytes': merged.stat().st_size,
        'combinedApkSha256': merged_hash,
        'arm64NativeLibraryCount': native_count,
        'diagnosticLines': safe_lines,
        'metadataRecovered': result.returncode == 0 and dlls > 0,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', required=True)
    parser.add_argument('--base-apk', required=True)
    parser.add_argument('--arm64-apk', required=True)
    parser.add_argument('--output-root', required=True)
    parser.add_argument('--temp-dir', required=True)
    args = parser.parse_args()
    print(json.dumps(run_cpp2il(args.binary, args.base_apk, args.arm64_apk,
                                args.output_root, args.temp_dir), separators=(',', ':')))


if __name__ == '__main__':
    main()

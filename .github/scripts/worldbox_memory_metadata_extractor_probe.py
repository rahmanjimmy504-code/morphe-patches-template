#!/usr/bin/env python3
"""Run the pinned Frida metadata extractor in a bounded, hash-gated emulator probe."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import zipfile

REPOSITORY = 'CameroonD/Il2CppMetadataExtractor'
TOOL_COMMIT = 'c31281b43a67a1a7b17a255d930cd3fe8640f489'
TOOL_ARCHIVE_SHA256 = '56a1350f979f7beebe0e4cbda93b3f4db4c23221565e93bd2b3d6a8e3e8568d0'
PY_SCRIPT_SHA256 = 'ee0107565327dd9bccce9fae58c5b21905900ce78861f65a580be91cf1108df8'
JS_SCRIPT_SHA256 = '7a177b29be0ea619834f4dfd12ab1e93372a06e87d51c37dd78eda16d1ce7459'
PACKAGE = 'com.mkarpenko.worldbox'
EXPECTED_BASE = 'ab7c6bab7d2233c26a9e18426aa58dd60fa0ae0ad9be6fa0b2a6673dd8f89c3f'
EXPECTED_METADATA_SHA256 = '0c843e9807d351f193580e178f4826845534cdcd86563e634ca8a48ad3b7bc88'
EXPECTED_METADATA_BYTES = 12_878_248
EXPECTED_ARM64_IL2CPP = '1d644b98fec97a35630495c695515861acd2c18209beaae6471a650db65def87'
IL2CPP_METADATA_MAGIC = 0xFAB11BAF
IL2CPP_METADATA_VERSION = 31


def sha256(path):
    with Path(path).open('rb') as handle:
        return hashlib.file_digest(handle, 'sha256').hexdigest()


def verify_extractor(archive_path, source_dir):
    archive_path = Path(archive_path)
    source_dir = Path(source_dir)
    if sha256(archive_path) != TOOL_ARCHIVE_SHA256:
        return False
    try:
        root = source_dir / f'Il2CppMetadataExtractor-{TOOL_COMMIT}'
        py_path, js_path = root / 'dump-metadata.py', root / 'dump-metadata.js'
        return (py_path.is_file() and js_path.is_file()
                and sha256(py_path) == PY_SCRIPT_SHA256
                and sha256(js_path) == JS_SCRIPT_SHA256)
    except OSError:
        return False


def metadata_matches_base(base_apk, metadata):
    entry = 'assets/bin/Data/Managed/Metadata/global-metadata.dat'
    try:
        with zipfile.ZipFile(base_apk) as apk, apk.open(entry) as source:
            return hashlib.file_digest(source, 'sha256').hexdigest() == sha256(metadata)
    except (KeyError, OSError, zipfile.BadZipFile):
        return False


def classify(returncode, dump_path, timed_out=False):
    dump = Path(dump_path)
    exists = dump.is_file()
    size = dump.stat().st_size if exists else 0
    magic = version = None
    if exists and size >= 8:
        with dump.open('rb') as handle:
            header = handle.read(8)
        magic = int.from_bytes(header[:4], 'little')
        version = int.from_bytes(header[4:8], 'little', signed=True)
    accepted = (not timed_out and returncode == 0 and size == EXPECTED_METADATA_BYTES
                and magic == IL2CPP_METADATA_MAGIC and version == IL2CPP_METADATA_VERSION)
    return {
        'exitCode': 124 if timed_out else returncode,
        'timedOut': timed_out,
        'dumpExists': exists,
        'dumpBytes': size,
        'metadataMagicValid': magic == IL2CPP_METADATA_MAGIC,
        'metadataVersion': version,
        'metadataSizeMatchesExpected': size == EXPECTED_METADATA_BYTES,
        'metadataCandidateValidated': accepted,
        'validationLevel': 'exact size, IL2CPP magic, and version; structural parsing not performed',
    }


def diagnostic_lines(text):
    selected = []
    for line in text.splitlines():
        if re.search(r'hexdump|your hex|^[\s|+\-0-9a-f]{8,}$', line, re.I):
            continue
        if not re.search(r'metadata|il2cpp|dump|error|failed|success|detected|size|pattern', line, re.I):
            continue
        line = re.sub(r'0x[0-9a-fA-F]+', '<address>', line)
        line = re.sub(r'/tmp/[^\s]+', '<temp-path>', line)
        line = re.sub(r'\s+', ' ', line).strip()
        if line and len(line) <= 240:
            selected.append(line)
        if len(selected) >= 12:
            break
    return selected


def run_probe(archive_path, source_dir, base_apk, native, raw_metadata,
              output_dir, timeout=180, adb='adb'):
    archive_path, source_dir, base_apk, native, raw_metadata = map(Path,
        (archive_path, source_dir, base_apk, native, raw_metadata))
    output_dir = Path(output_dir)
    for label, path in (('extractor archive', archive_path), ('extractor source directory', source_dir),
                        ('base APK', base_apk), ('ARM64 libil2cpp.so', native),
                        ('bundled global-metadata.dat', raw_metadata)):
        if not path.exists():
            raise ValueError(f'{label} is missing')
    if not verify_extractor(archive_path, source_dir):
        raise ValueError('Pinned extractor archive/source hash mismatch; refusing to run')
    if sha256(base_apk) != EXPECTED_BASE:
        raise ValueError('Base APK hash mismatch; refusing to run')
    if sha256(native) != EXPECTED_ARM64_IL2CPP:
        raise ValueError('ARM64 libil2cpp.so hash mismatch; refusing to run')
    if raw_metadata.stat().st_size != EXPECTED_METADATA_BYTES:
        raise ValueError('Bundled metadata size mismatch; refusing to run')
    if sha256(raw_metadata) != EXPECTED_METADATA_SHA256:
        raise ValueError('Bundled metadata hash mismatch; refusing to run')
    if not metadata_matches_base(base_apk, raw_metadata):
        raise ValueError('Bundled metadata does not match the hash-gated base APK; refusing to run')

    output_dir.mkdir(parents=True, exist_ok=True)
    dump_path = output_dir / 'global-metadata.dump.dat'
    py_script = source_dir / f'Il2CppMetadataExtractor-{TOOL_COMMIT}' / 'dump-metadata.py'
    # Ensure the old game process cannot collide with the tool's controlled spawn.
    stop = subprocess.run([adb, 'shell', 'am', 'force-stop', PACKAGE], capture_output=True, text=True, timeout=30)
    if stop.returncode:
        raise RuntimeError('Could not stop the existing WorldBox process before Frida spawn')

    timed_out = False
    combined_log = ''
    returncode = 125
    try:
        result = subprocess.run([sys.executable, str(py_script), PACKAGE,
                                 '--size', str(EXPECTED_METADATA_BYTES)],
                                cwd=output_dir, capture_output=True, text=True, timeout=timeout)
        returncode = result.returncode
        combined_log = (result.stdout or '') + '\n' + (result.stderr or '')
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        out = exc.stdout.decode(errors='replace') if isinstance(exc.stdout, bytes) else (exc.stdout or '')
        err = exc.stderr.decode(errors='replace') if isinstance(exc.stderr, bytes) else (exc.stderr or '')
        combined_log = out + '\n' + err
    finally:
        subprocess.run([adb, 'shell', 'am', 'force-stop', PACKAGE],
                       capture_output=True, text=True, timeout=30)

    return {
        'kind': 'worldbox-memory-metadata-extractor-probe',
        'tool': REPOSITORY,
        'toolCommit': TOOL_COMMIT,
        'toolArchiveSha256': sha256(archive_path),
        'rawMetadataSha256': sha256(raw_metadata),
        'baseApkSha256': sha256(base_apk),
        'arm64Il2CppSha256': sha256(native),
        **classify(returncode, dump_path, timed_out),
        'diagnosticLines': diagnostic_lines(combined_log),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--archive', required=True)
    parser.add_argument('--source-dir', required=True)
    parser.add_argument('--base-apk', required=True)
    parser.add_argument('--native', required=True)
    parser.add_argument('--metadata', required=True)
    parser.add_argument('--output-dir', required=True)
    parser.add_argument('--timeout', type=int, default=180)
    parser.add_argument('--adb', default='adb')
    args = parser.parse_args()
    print(json.dumps(run_probe(args.archive, args.source_dir, args.base_apk, args.native,
        args.metadata, args.output_dir, args.timeout, args.adb), separators=(',', ':')))


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""Run a bounded AssetRipper type-tree cross-check on fixed Premium Unity assets.

The probe emits only aggregate counts for predefined labels. It does not retain
or print exported asset contents, arbitrary strings, or generated project files.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import tempfile
import time
import zipfile

from worldbox_bounded_reference_report import annotation

EXPECTED_BASE = 'ab7c6bab7d2233c26a9e18426aa58dd60fa0ae0ad9be6fa0b2a6673dd8f89c3f'
ASSETS = (
    'assets/bin/Data/globalgamemanagers.assets',
    'assets/bin/Data/13cfff6f881b80049833c82202d4227a',
    'assets/bin/Data/6f7d4abbd6fb14eabaad2266d6de4adf',
    'assets/bin/Data/7c7dd69ec9c748445ac2b5ecff11e69f',
    'assets/bin/Data/abba007fcc231f946bb3ba988fe9ddfb',
    'assets/bin/Data/1a521a104aa73fa45843e973963a7d49',
    'assets/bin/Data/1ec40a398dedbc646b5e9781b279f212',
    'assets/bin/Data/305f73ca61e203b4984f15c4a2a1fb07',
    'assets/bin/Data/3d6d3728b940f884589bdfedcb346773',
)
LABELS = ('ButtonPremium', 'clickPremium', 'PremiumUnlockAnimation',
          'premium_unlocked', 'm_Script', 'm_EditorClassIdentifier')
MAX_TOTAL_BYTES = 256 * 1024 * 1024
MAX_EXPORT_FILES = 100_000
MAX_EXPORT_TEXT = 512 * 1024 * 1024
LIMITATIONS = (
    'Independent AssetRipper 2.0.0 cross-check of nine fixed, hash-gated Unity files. '
    'Only aggregate counts of predefined labels and export-size/status metadata are emitted; '
    'exported asset contents, unknown strings, and project files are not retained. '
    'Finding a script/type-tree label does not reveal IL2CPP method bodies or prove Premium entitlement behavior.'
)


def sha256(path: Path) -> str:
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def extract_inputs(base_apk: Path, root: Path) -> tuple[int, int]:
    root.mkdir(parents=True, exist_ok=True)
    total = 0
    count = 0
    with zipfile.ZipFile(base_apk) as apk:
        infos = {info.filename: info for info in apk.infolist()}
        if len(infos) != len(apk.infolist()):
            raise ValueError('duplicate APK entry names')
        for name in ASSETS:
            info = infos.get(name)
            if info is None or info.is_dir() or info.flag_bits & 1:
                raise ValueError('required hash-gated Unity entry missing or unreadable')
            total += info.file_size
            if total > MAX_TOTAL_BYTES:
                raise ValueError('selected Unity files exceed extraction bound')
            relative = PurePosixPath(name)
            if relative.is_absolute() or '..' in relative.parts:
                raise ValueError('unsafe Unity entry path')
            destination = root.joinpath(*relative.parts)
            destination.parent.mkdir(parents=True, exist_ok=True)
            with apk.open(info) as source, destination.open('wb') as output:
                shutil.copyfileobj(source, output, 1024 * 1024)
            if destination.stat().st_size != info.file_size:
                raise ValueError('short Unity entry extraction')
            count += 1
    return count, total


def start_server(binary: Path, temp: Path, port: int):
    import requests

    log = temp / 'assetripper.log'
    command = [str(binary), '--headless', '--port', str(port)]
    output = log.open('wb')
    process = subprocess.Popen(command, cwd=temp, stdout=output, stderr=subprocess.STDOUT)
    session = requests.Session()
    session.trust_env = False
    base_url = f'http://127.0.0.1:{port}'
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        if process.poll() is not None:
            output.close()
            tail = log.read_text(errors='replace')[-1200:]
            raise RuntimeError('AssetRipper exited before startup: ' + tail)
        try:
            response = session.get(base_url + '/', timeout=2)
            if response.status_code < 500:
                return process, output, session, base_url
        except requests.RequestException:
            time.sleep(1)
    process.terminate()
    output.close()
    raise TimeoutError('AssetRipper web interface did not start')


def summarize_export(root: Path) -> dict:
    file_count = 0
    text_bytes = 0
    marker_counts = {label: 0 for label in LABELS}
    candidate_files = 0
    truncated = False
    for path in root.rglob('*'):
        if not path.is_file():
            continue
        file_count += 1
        if file_count > MAX_EXPORT_FILES:
            truncated = True
            break
        if path.suffix.lower() not in {'.yaml', '.yml', '.cs', '.json', '.txt', '.asset', '.prefab'}:
            continue
        size = path.stat().st_size
        if text_bytes + size > MAX_EXPORT_TEXT:
            truncated = True
            break
        text_bytes += size
        data = path.read_bytes()
        for label in LABELS:
            marker_counts[label] += data.count(label.encode('ascii'))
        if (b'ButtonPremium' in data or b'PremiumUnlockAnimation' in data or
                b'clickPremium' in data):
            candidate_files += 1
    return {'exportFileCount': min(file_count, MAX_EXPORT_FILES),
            'textBytesScanned': text_bytes,
            'targetLabelCounts': marker_counts,
            'filesWithTargetLabels': candidate_files,
            'scanTruncated': truncated}


def inspect(base_apk: str | Path, assetripper: str | Path, *, port: int = 48127) -> dict:
    base_apk, assetripper = Path(base_apk), Path(assetripper)
    if not base_apk.is_file() or sha256(base_apk) != EXPECTED_BASE:
        raise ValueError('base APK hash mismatch; refusing AssetRipper analysis')
    if not assetripper.is_file() or not os.access(assetripper, os.X_OK):
        raise ValueError('AssetRipper executable missing or not executable')
    with tempfile.TemporaryDirectory(prefix='worldbox-assetripper-') as name:
        temp = Path(name)
        inputs = temp / 'input'
        output_dir = temp / 'export'
        input_count, input_bytes = extract_inputs(base_apk, inputs)
        process = output = session = None
        try:
            process, output, session, base_url = start_server(assetripper, temp, port)
            load = session.post(base_url + '/LoadFolder', data={'Path': str(inputs)},
                                timeout=900, allow_redirects=False)
            if load.status_code >= 500:
                raise RuntimeError(f'AssetRipper LoadFolder returned HTTP {load.status_code}')
            export = session.post(base_url + '/Export/UnityProject',
                                  data={'Path': str(output_dir)}, timeout=1200,
                                  allow_redirects=False)
            if export.status_code >= 500 or not output_dir.is_dir():
                raise RuntimeError(f'AssetRipper export returned HTTP {export.status_code}')
            summary = summarize_export(output_dir)
            return {'kind': 'worldbox-assetripper-probe',
                    'tool': 'AssetRipper', 'toolRelease': '2.0.0',
                    'baseApkSha256': EXPECTED_BASE,
                    'inputEntryCount': input_count, 'inputBytes': input_bytes,
                    'loadHttpStatus': load.status_code,
                    'exportHttpStatus': export.status_code,
                    **summary,
                    'limitations': LIMITATIONS}
        finally:
            if session is not None:
                session.close()
            if process is not None and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
            if output is not None and not output.closed:
                output.close()


def emit(report: dict) -> None:
    message = annotation(json.dumps(report, separators=(',', ':')))
    if len(message) > 3800:
        raise ValueError('AssetRipper report exceeds annotation safety bound')
    print('::notice title=WorldBox AssetRipper type-tree cross-check::' + message)


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--base-apk', required=True)
    parser.add_argument('--assetripper', required=True)
    parser.add_argument('--port', type=int, default=48127)
    args = parser.parse_args()
    emit(inspect(args.base_apk, args.assetripper, port=args.port))

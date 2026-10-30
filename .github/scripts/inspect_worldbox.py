#!/usr/bin/env python3
"""Inspect the public WorldBox 0.51.4 bundle without committing game files."""
import hashlib
import html
import os
from pathlib import Path
import re
import sys
import shutil
import subprocess
import tempfile
from urllib.parse import urljoin
import zipfile

import requests

PAGE = 'https://www.apkmirror.com/apk/mako-mako/worldbox-sandbox-god-simulator/worldbox-sandbox-god-sim-0-51-4-release/worldbox-sandbox-god-sim-0-51-4-android-apk-download/'
session = requests.Session()
session.headers.update({'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36'})

def fetch(url, referer=None):
    response = session.get(url, headers={'Referer': referer} if referer else {}, timeout=60)
    response.raise_for_status()
    return response

try:
    page = fetch(PAGE)
    matches = re.findall(r'href=["\']([^"\']+/download/\?key=[^"\']+)', page.text)
    if not matches:
        raise RuntimeError('APKMirror did not expose a download link (possibly blocked by its anti-bot protection).')
    download_page = fetch(urljoin(PAGE, html.unescape(matches[0])), PAGE)
    # APKMirror's download page normally links to download.php; do not print the temporary URL.
    links = re.findall(r'href=["\']([^"\']*(?:download\.php|download\.apkmirror\.com)[^"\']*)', download_page.text)
    if not links:
        raise RuntimeError('APKMirror did not provide a direct bundle link (possibly blocked by its anti-bot protection).')
    url = urljoin(download_page.url, html.unescape(links[0]))
    with tempfile.TemporaryDirectory(prefix='worldbox-inspect-') as td:
        target = Path(td) / 'original.apkm'
        with session.get(url, headers={'Referer': download_page.url}, timeout=(30, 180), stream=True) as response:
            response.raise_for_status()
            with target.open('wb') as out:
                for chunk in response.iter_content(1024 * 1024):
                    out.write(chunk)
        if target.stat().st_size != 190320343 or not zipfile.is_zipfile(target):
            raise RuntimeError('Downloaded file is not the expected WorldBox 0.51.4 (725) APKM.')
        print('Downloaded expected-size bundle. SHA-256:', hashlib.file_digest(target.open('rb'), 'sha256').hexdigest())
        native = None
        metadata = None
        with zipfile.ZipFile(target) as bundle:
            apks = [n for n in bundle.namelist() if n.endswith('.apk')]
            if not apks:
                raise RuntimeError('No APK splits found in bundle.')
            print('APK splits:', ', '.join(apks))
            for name in apks:
                path = Path(td) / Path(name).name
                with bundle.open(name) as src, path.open('wb') as dst:
                    shutil.copyfileobj(src, dst)
                with zipfile.ZipFile(path) as apk:
                    relevant = [n for n in apk.namelist() if n.endswith('libil2cpp.so') or n.endswith('global-metadata.dat')]
                    for entry in relevant:
                        info = apk.getinfo(entry)
                        print(f'::notice title=WorldBox file::{name}: {entry} ({info.file_size} bytes)')
                        if entry == 'lib/arm64-v8a/libil2cpp.so':
                            native = Path(td) / 'libil2cpp.so'
                            with apk.open(entry) as src, native.open('wb') as dst:
                                shutil.copyfileobj(src, dst)
                        elif entry.endswith('global-metadata.dat'):
                            metadata = Path(td) / 'global-metadata.dat'
                            with apk.open(entry) as src, metadata.open('wb') as dst:
                                shutil.copyfileobj(src, dst)
        if not native or not metadata:
            raise RuntimeError('Missing ARM64 native library or Unity metadata.')
        print('::notice title=WorldBox SHA-256::ARM64 library ' + hashlib.file_digest(native.open('rb'), 'sha256').hexdigest())
        dumper = Path(td) / 'dumper'
        dumper.mkdir()
        release = 'https://github.com/Perfare/Il2CppDumper/releases/download/v6.7.46/Il2CppDumper-net7-v6.7.46.zip'
        tool = Path(td) / 'dumper.zip'
        with session.get(release, timeout=90, stream=True) as response:
            response.raise_for_status()
            with tool.open('wb') as dst:
                shutil.copyfileobj(response.raw, dst)
        with zipfile.ZipFile(tool) as z:
            z.extractall(dumper)
        dlls = list(dumper.rglob('Il2CppDumper.dll'))
        if len(dlls) != 1:
            raise RuntimeError('Il2CppDumper executable not found.')
        output = Path(td) / 'dump'
        output.mkdir()
        result = subprocess.run(['dotnet', str(dlls[0]), str(native), str(metadata), str(output)],
                                input='', capture_output=True, text=True, timeout=180)
        print(result.stdout[-4000:])
        if result.returncode != 0 or not (output / 'dump.cs').exists():
            raise RuntimeError('IL2CPP dump failed: ' + result.stderr[-1000:])
        lines = (output / 'dump.cs').read_text(errors='replace').splitlines()
        matches = [i for i, line in enumerate(lines) if re.search(r'premium|purchased|purchase|buyproduct', line, re.I)]
        print(f'::notice title=WorldBox scan::{len(matches)} premium/purchase symbol matches')
        for i in matches[:70]:
            context = ' | '.join(lines[max(0, i-1):i+1]).strip().replace('%', '%25').replace('\r', '%0D').replace('\n', '%0A')
            print('::notice title=WorldBox symbol::' + context[:800])
except Exception as exc:
    print('WorldBox inspection failed:', exc, file=sys.stderr)
    sys.exit(1)

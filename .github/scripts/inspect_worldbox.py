#!/usr/bin/env python3
"""Inspect the public WorldBox 0.51.4 bundle without committing game files."""
import hashlib
import collections
import math
import json
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

from worldbox_metadata_string_counts import NEEDLES as METADATA_NEEDLES, candidate_string_heap_bases, count_string_leads, nearby_null_identifiers, occurrence_offsets, printable_run_contexts
from worldbox_bounded_reference_report import annotation, emit_ghidra_annotations, emit_ghidra_failure, emit_reference_annotations

PAGE = 'https://www.apkmirror.com/apk/mako-mako/worldbox-sandbox-god-simulator/worldbox-sandbox-god-sim-0-51-4-release/worldbox-sandbox-god-sim-0-51-4-android-apk-download/'
EXPECTED_ARM64 = '1d644b98fec97a35630495c695515861acd2c18209beaae6471a650db65def87'
EXPECTED_UNITY = '8c04ad3b7d482cab925541cfe9839844c87732f7419aaaa71e170ccff916f082'
EXPECTED_BASE_APK = 'ab7c6bab7d2233c26a9e18426aa58dd60fa0ae0ad9be6fa0b2a6673dd8f89c3f'
EXPECTED_METADATA = '0c843e9807d351f193580e178f4826845534cdcd86563e634ca8a48ad3b7bc88'
session = requests.Session()
session.headers.update({'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36'})

def fetch(url, referer=None):
    response = session.get(url, headers={'Referer': referer} if referer else {}, timeout=60)
    response.raise_for_status()
    return response


def verify_file(path, expected, label):
    if not path or not Path(path).is_file():
        raise RuntimeError(label + ' not found in the bundle.')
    with Path(path).open('rb') as handle:
        observed = hashlib.file_digest(handle, 'sha256').hexdigest()
    if observed != expected:
        raise RuntimeError(label + ' hash does not match the observed 0.51.4 sample; refusing analysis.')
    return observed


def run_bounded_ghidra(native, addresses, targets, label):
    """Decompile unwind-bounded addresses; emit a safe notice on tool failure."""
    tool = os.environ.get('GHIDRA_HEADLESS', '')
    command = [sys.executable, '.github/scripts/worldbox_ghidra_callees.py',
               '--headless', tool, '--binary', str(native)]
    for address in addresses:
        command += ['--address', address]
    for target in targets:
        command += ['--trace-target', target]
    result = subprocess.run(command, capture_output=True, text=True, timeout=1200)
    if result.returncode:
        emit_ghidra_failure(label, (result.stderr or result.stdout)[-600:])
        return None
    ghidra_report = json.loads(result.stdout)
    emit_ghidra_annotations(ghidra_report, label, tuple(addresses),
                            tuple(targets))
    return ghidra_report

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
        native_v7 = None
        metadata = None
        unity = None
        base_apk = None
        arm64_apk = None
        apk_paths = []
        with zipfile.ZipFile(target) as bundle:
            apks = [n for n in bundle.namelist() if n.endswith('.apk')]
            if not apks:
                raise RuntimeError('No APK splits found in bundle.')
            print('APK splits:', ', '.join(apks))
            for name in apks:
                path = Path(td) / Path(name).name
                with bundle.open(name) as src, path.open('wb') as dst:
                    shutil.copyfileobj(src, dst)
                apk_paths.append(path)
                if Path(name).name == 'base.apk':
                    base_apk = path
                elif Path(name).name == 'split_config.arm64_v8a.apk':
                    arm64_apk = path
                with zipfile.ZipFile(path) as apk:
                    relevant = [n for n in apk.namelist() if n.endswith('libil2cpp.so') or n.endswith('global-metadata.dat') or n == 'lib/arm64-v8a/libunity.so']
                    for entry in relevant:
                        info = apk.getinfo(entry)
                        print(f'::notice title=WorldBox file::{name}: {entry} ({info.file_size} bytes)')
                        if entry == 'lib/arm64-v8a/libil2cpp.so':
                            native = Path(td) / 'libil2cpp.so'
                            with apk.open(entry) as src, native.open('wb') as dst:
                                shutil.copyfileobj(src, dst)
                        elif entry == 'lib/armeabi-v7a/libil2cpp.so':
                            native_v7 = Path(td) / 'libil2cpp-armv7.so'
                            with apk.open(entry) as src, native_v7.open('wb') as dst:
                                shutil.copyfileobj(src, dst)
                        elif entry == 'lib/arm64-v8a/libunity.so':
                            unity = Path(td) / 'libunity.so'
                            with apk.open(entry) as src, unity.open('wb') as dst:
                                shutil.copyfileobj(src, dst)
                        elif entry.endswith('global-metadata.dat'):
                            metadata = Path(td) / 'global-metadata.dat'
                            with apk.open(entry) as src, metadata.open('wb') as dst:
                                shutil.copyfileobj(src, dst)
        if os.environ.get('WORLDBOX_GHIDRA_BROTLI_EXPORT_CONSUMERS_PROBE') == '1':
            verify_file(native, EXPECTED_ARM64, 'ARM64 libil2cpp.so')
            from worldbox_brotli_export_consumers import (export_consumers_report,
                                                          emit_export_consumer_annotations)
            native_report = export_consumers_report(native)
            emit_export_consumer_annotations(native_report)
            addresses = native_report['ghidraAddresses']
            targets = native_report['traceTargets']
            if not addresses:
                print('::notice title=WorldBox Brotli export consumer Ghidra::' +
                      annotation(json.dumps({'status': 'no-bounded-consumer-functions'},
                                            separators=(',', ':'))))
            else:
                run_bounded_ghidra(native, addresses, targets,
                                   'Brotli export consumer')
            if os.environ.get('WORLDBOX_PREMIUM_GHIDRA_PROBE') != '1':
                sys.exit(0)
        if os.environ.get('WORLDBOX_PREMIUM_GHIDRA_PROBE') == '1':
            verify_file(native, EXPECTED_ARM64, 'ARM64 libil2cpp.so')
            verify_file(unity, EXPECTED_UNITY, 'ARM64 libunity.so')
            verify_file(metadata, EXPECTED_METADATA, 'global-metadata.dat')
            from worldbox_premium_entitlement_probe import (premium_report,
                                                            emit_premium_annotations)
            report = premium_report(native, unity, metadata)
            emit_premium_annotations(report)
            addresses = report['ghidraAddresses']
            targets = report['traceTargets']
            if not addresses:
                print('::notice title=WorldBox Premium entitlement Ghidra::' +
                      annotation(json.dumps({'status': 'no-bounded-native-needle-functions'},
                                            separators=(',', ':'))))
                sys.exit(0)
            run_bounded_ghidra(native, addresses, targets, 'Premium entitlement')
            sys.exit(0)
        if os.environ.get('WORLDBOX_BROTLI_EXPORT_CONSUMER_PROBE') == '1':
            verify_file(native, EXPECTED_ARM64, 'ARM64 libil2cpp.so')
            from worldbox_brotli_export_consumers import (export_consumers_report,
                                                          emit_export_consumer_annotations)
            emit_export_consumer_annotations(export_consumers_report(native))
            if os.environ.get('WORLDBOX_PREMIUM_NATIVE_PROBE') != '1':
                sys.exit(0)
        if os.environ.get('WORLDBOX_PREMIUM_ANDROID_PROBE') == '1':
            verify_file(native, EXPECTED_ARM64, 'ARM64 libil2cpp.so')
            verify_file(unity, EXPECTED_UNITY, 'ARM64 libunity.so')
            verify_file(base_apk, EXPECTED_BASE_APK, 'base.apk')
            verify_file(metadata, EXPECTED_METADATA, 'global-metadata.dat')
            from worldbox_premium_entitlement_probe import (premium_report,
                                                            emit_premium_annotations)
            emit_premium_annotations(premium_report(native, unity, metadata,
                                                    apk_paths))
            sys.exit(0)
        if os.environ.get('WORLDBOX_PREMIUM_NATIVE_PROBE') == '1':
            verify_file(native, EXPECTED_ARM64, 'ARM64 libil2cpp.so')
            verify_file(unity, EXPECTED_UNITY, 'ARM64 libunity.so')
            verify_file(metadata, EXPECTED_METADATA, 'global-metadata.dat')
            from worldbox_premium_entitlement_probe import (premium_report,
                                                            emit_premium_annotations)
            emit_premium_annotations(premium_report(native, unity, metadata))
            sys.exit(0)
        if os.environ.get('WORLDBOX_GHIDRA_BROTLI_CALLERS_PROBE') == '1':
            if not native or not native.is_file():
                raise RuntimeError('ARM64 libil2cpp.so not found in the bundle.')
            with native.open('rb') as f:
                observed = hashlib.file_digest(f, 'sha256').hexdigest()
            if observed != '1d644b98fec97a35630495c695515861acd2c18209beaae6471a650db65def87':
                raise RuntimeError('ARM64 library hash does not match the observed 0.51.4 sample; refusing analysis.')
            from worldbox_brotli_callers import (callers_report,
                                                 emit_callers_annotations)
            native_report = callers_report(native)
            emit_callers_annotations(native_report)
            addresses = native_report['ghidraAddresses']
            targets = native_report['traceTargets']
            if not addresses:
                print('::notice title=WorldBox brotli caller consumer Ghidra::' +
                      annotation(json.dumps({'status': 'no-bounded-caller-functions'},
                                            separators=(',', ':'))))
                sys.exit(0)
            tool = os.environ.get('GHIDRA_HEADLESS', '')
            command = [sys.executable, '.github/scripts/worldbox_ghidra_callees.py',
                       '--headless', tool, '--binary', str(native)]
            for address in addresses:
                command += ['--address', address]
            for target in targets:
                command += ['--trace-target', target]
            result = subprocess.run(command, capture_output=True, text=True, timeout=1200)
            if result.returncode:
                emit_ghidra_failure('brotli caller consumer',
                                    (result.stderr or result.stdout)[-600:])
                sys.exit(0)
            ghidra_report = json.loads(result.stdout)
            emit_ghidra_annotations(ghidra_report, 'brotli caller consumer',
                                    tuple(addresses), tuple(targets), native_report)
            sys.exit(0)
        if os.environ.get('WORLDBOX_GHIDRA_BROTLI_PROBE') == '1':
            if not native or not native.is_file():
                raise RuntimeError('ARM64 libil2cpp.so not found in the bundle.')
            if not unity or not unity.is_file():
                raise RuntimeError('ARM64 libunity.so not found in the bundle.')
            with native.open('rb') as f:
                observed = hashlib.file_digest(f, 'sha256').hexdigest()
            if observed != '1d644b98fec97a35630495c695515861acd2c18209beaae6471a650db65def87':
                raise RuntimeError('ARM64 library hash does not match the observed 0.51.4 sample; refusing analysis.')
            with unity.open('rb') as f:
                observed_unity = hashlib.file_digest(f, 'sha256').hexdigest()
            if observed_unity != '8c04ad3b7d482cab925541cfe9839844c87732f7419aaaa71e170ccff916f082':
                raise RuntimeError('libunity.so hash does not match the observed 0.51.4 sample; refusing analysis.')
            from worldbox_native_import_probe import (emit_import_annotations,
                                                      import_report)
            native_report = import_report(native, unity)
            emit_import_annotations(native_report)
            addresses = ('0x189941c', '0x1913f84', '0x1914114',
                         '0x1946e80', '0x1947248', '0x1946d70',
                         '0x1946e08', '0x1890ed4')
            targets = ('0x3bf9220', '0x3bf8f20', '0x3bf9030', '0x3bf90c0',
                       '0x3bf9700', '0x3bf9710', '0x3bf9d50', '0x3bf9d60',
                       '0x3bf9d70', '0x3bf9d80', '0x18904e0', '0x18eb1a0',
                       '0x1890260', '0x18eb7a4', '0x18edbb8', '0x18ee1b8')
            tool = os.environ.get('GHIDRA_HEADLESS', '')
            command = [sys.executable, '.github/scripts/worldbox_ghidra_callees.py',
                       '--headless', tool, '--binary', str(native)]
            for address in addresses:
                command += ['--address', address]
            for target in targets:
                command += ['--trace-target', target]
            result = subprocess.run(command, capture_output=True, text=True, timeout=1200)
            if result.returncode:
                emit_ghidra_failure('brotli caller',
                                    (result.stderr or result.stdout)[-600:])
                sys.exit(0)
            ghidra_report = json.loads(result.stdout)
            emit_ghidra_annotations(ghidra_report, 'brotli caller',
                                    addresses, targets, native_report)
            sys.exit(0)
        if os.environ.get('WORLDBOX_GHIDRA_NATIVE_IMPORT_PROBE') == '1':
            if not native or not native.is_file():
                raise RuntimeError('ARM64 libil2cpp.so not found in the bundle.')
            if not unity or not unity.is_file():
                raise RuntimeError('ARM64 libunity.so not found in the bundle.')
            with native.open('rb') as f:
                observed = hashlib.file_digest(f, 'sha256').hexdigest()
            if observed != '1d644b98fec97a35630495c695515861acd2c18209beaae6471a650db65def87':
                raise RuntimeError('ARM64 library hash does not match the observed 0.51.4 sample; refusing analysis.')
            with unity.open('rb') as f:
                observed_unity = hashlib.file_digest(f, 'sha256').hexdigest()
            if observed_unity != '8c04ad3b7d482cab925541cfe9839844c87732f7419aaaa71e170ccff916f082':
                raise RuntimeError('libunity.so hash does not match the observed 0.51.4 sample; refusing analysis.')
            from worldbox_native_import_probe import (emit_import_annotations,
                                                      import_report)
            native_report = import_report(native, unity)
            emit_import_annotations(native_report)
            addresses = native_report['ghidraAddresses']
            targets = native_report['traceTargets']
            if not addresses:
                print('::notice title=WorldBox native import caller Ghidra::' +
                      annotation(json.dumps({'status': 'no-bounded-import-caller-functions'},
                                            separators=(',', ':'))))
                sys.exit(0)
            tool = os.environ.get('GHIDRA_HEADLESS', '')
            command = [sys.executable, '.github/scripts/worldbox_ghidra_callees.py',
                       '--headless', tool, '--binary', str(native)]
            for address in addresses:
                command += ['--address', address]
            for target in targets:
                command += ['--trace-target', target]
            result = subprocess.run(command, capture_output=True, text=True, timeout=1200)
            if result.returncode:
                emit_ghidra_failure('native import caller',
                                    (result.stderr or result.stdout)[-600:])
                sys.exit(0)
            ghidra_report = json.loads(result.stdout)
            emit_ghidra_annotations(ghidra_report, 'native import caller',
                                    tuple(addresses), tuple(targets), native_report)
            sys.exit(0)
        if os.environ.get('WORLDBOX_METADATA_TRANSFORM_PROBE') == '1':
            if not native or not native.is_file():
                raise RuntimeError('ARM64 libil2cpp.so not found in the bundle.')
            if not base_apk or not base_apk.is_file():
                raise RuntimeError('base.apk not found in the bundle.')
            if not metadata or not metadata.is_file():
                raise RuntimeError('global-metadata.dat not found in the bundle.')
            with native.open('rb') as f:
                observed = hashlib.file_digest(f, 'sha256').hexdigest()
            if observed != '1d644b98fec97a35630495c695515861acd2c18209beaae6471a650db65def87':
                raise RuntimeError('ARM64 library hash does not match the observed 0.51.4 sample; refusing analysis.')
            with base_apk.open('rb') as f:
                base_hash = hashlib.file_digest(f, 'sha256').hexdigest()
            if base_hash != 'ab7c6bab7d2233c26a9e18426aa58dd60fa0ae0ad9be6fa0b2a6673dd8f89c3f':
                raise RuntimeError('base.apk hash does not match the observed 0.51.4 sample; refusing analysis.')
            from worldbox_metadata_transform_probe import (emit_transform_annotations,
                                                           transform_report)
            emit_transform_annotations(transform_report(metadata))
            if os.environ.get('WORLDBOX_NATIVE_IMPORT_PROBE') != '1':
                sys.exit(0)
        if os.environ.get('WORLDBOX_NATIVE_IMPORT_PROBE') == '1':
            if not native or not native.is_file():
                raise RuntimeError('ARM64 libil2cpp.so not found in the bundle.')
            if not unity or not unity.is_file():
                raise RuntimeError('ARM64 libunity.so not found in the bundle.')
            from worldbox_native_import_probe import (emit_import_annotations,
                                                      import_report)
            report = import_report(native, unity)
            emit_import_annotations(report)
            if not (os.environ.get('WORLDBOX_METADATA_STREAM_PROBE') == '1' or
                    os.environ.get('WORLDBOX_METADATA_BROTLI_OFFSETS_PROBE') == '1'):
                sys.exit(0)
        if os.environ.get('WORLDBOX_METADATA_STREAM_PROBE') == '1':
            if not native or not native.is_file():
                raise RuntimeError('ARM64 libil2cpp.so not found in the bundle.')
            if not base_apk or not base_apk.is_file():
                raise RuntimeError('base.apk not found in the bundle.')
            if not metadata or not metadata.is_file():
                raise RuntimeError('global-metadata.dat not found in the bundle.')
            with native.open('rb') as f:
                observed = hashlib.file_digest(f, 'sha256').hexdigest()
            if observed != '1d644b98fec97a35630495c695515861acd2c18209beaae6471a650db65def87':
                raise RuntimeError('ARM64 library hash does not match the observed 0.51.4 sample; refusing analysis.')
            with base_apk.open('rb') as f:
                base_hash = hashlib.file_digest(f, 'sha256').hexdigest()
            if base_hash != 'ab7c6bab7d2233c26a9e18426aa58dd60fa0ae0ad9be6fa0b2a6673dd8f89c3f':
                raise RuntimeError('base.apk hash does not match the observed 0.51.4 sample; refusing analysis.')
            from worldbox_metadata_stream_probe import (emit_stream_annotations,
                                                        stream_report)
            emit_stream_annotations(stream_report(metadata))
            if os.environ.get('WORLDBOX_METADATA_BROTLI_OFFSETS_PROBE') != '1':
                sys.exit(0)
        if os.environ.get('WORLDBOX_METADATA_BROTLI_OFFSETS_PROBE') == '1':
            if not native or not native.is_file():
                raise RuntimeError('ARM64 libil2cpp.so not found in the bundle.')
            if not base_apk or not base_apk.is_file():
                raise RuntimeError('base.apk not found in the bundle.')
            if not metadata or not metadata.is_file():
                raise RuntimeError('global-metadata.dat not found in the bundle.')
            with native.open('rb') as f:
                observed = hashlib.file_digest(f, 'sha256').hexdigest()
            if observed != '1d644b98fec97a35630495c695515861acd2c18209beaae6471a650db65def87':
                raise RuntimeError('ARM64 library hash does not match the observed 0.51.4 sample; refusing analysis.')
            with base_apk.open('rb') as f:
                base_hash = hashlib.file_digest(f, 'sha256').hexdigest()
            if base_hash != 'ab7c6bab7d2233c26a9e18426aa58dd60fa0ae0ad9be6fa0b2a6673dd8f89c3f':
                raise RuntimeError('base.apk hash does not match the observed 0.51.4 sample; refusing analysis.')
            from worldbox_metadata_brotli_offsets import (emit_offset_annotations,
                                                           offset_report)
            emit_offset_annotations(offset_report(metadata))
            sys.exit(0)
        if os.environ.get('WORLDBOX_METADATA_FILE_DESCRIPTOR_PROBE') == '1':
            if not native or not native.is_file():
                raise RuntimeError('ARM64 libil2cpp.so not found in the bundle.')
            if not base_apk or not base_apk.is_file():
                raise RuntimeError('base.apk not found in the bundle.')
            if not metadata or not metadata.is_file():
                raise RuntimeError('global-metadata.dat not found in the bundle.')
            with native.open('rb') as f:
                observed = hashlib.file_digest(f, 'sha256').hexdigest()
            if observed != '1d644b98fec97a35630495c695515861acd2c18209beaae6471a650db65def87':
                raise RuntimeError('ARM64 library hash does not match the observed 0.51.4 sample; refusing analysis.')
            from worldbox_metadata_file_descriptor import (emit_metadata_file_annotations,
                                                           metadata_file_report)
            emit_metadata_file_annotations(metadata_file_report(base_apk, metadata))
            sys.exit(0)
        if os.environ.get('WORLDBOX_METADATA_JAVA_PROBE') == '1':
            if not native or not native.is_file():
                raise RuntimeError('ARM64 libil2cpp.so not found in the bundle.')
            if not unity or not unity.is_file():
                raise RuntimeError('ARM64 libunity.so not found in the bundle.')
            if not base_apk or not base_apk.is_file():
                raise RuntimeError('base.apk not found in the bundle.')
            with native.open('rb') as f:
                native_hash = hashlib.file_digest(f, 'sha256').hexdigest()
            if native_hash != '1d644b98fec97a35630495c695515861acd2c18209beaae6471a650db65def87':
                raise RuntimeError('ARM64 libil2cpp.so hash does not match the observed 0.51.4 sample; refusing analysis.')
            with unity.open('rb') as f:
                unity_hash = hashlib.file_digest(f, 'sha256').hexdigest()
            if unity_hash != '8c04ad3b7d482cab925541cfe9839844c87732f7419aaaa71e170ccff916f082':
                raise RuntimeError('ARM64 libunity.so hash does not match the observed 0.51.4 sample; refusing analysis.')
            with base_apk.open('rb') as f:
                base_hash = hashlib.file_digest(f, 'sha256').hexdigest()
            from worldbox_metadata_java_probe import analyze_apks
            report = analyze_apks(apk_paths)
            if report.get('kind') != 'worldbox-metadata-java-probe':
                raise RuntimeError('Unexpected WorldBox metadata Java report.')
            print('WorldBox full metadata Java report: ' + json.dumps(report, separators=(',', ':')))
            summary = {
                'needles': report['needles'], 'encodings': report['encodings'],
                'baseApkSha256': base_hash,
                'dexFiles': [{'apk': row['apk'], 'dex': row['dex'], 'bytes': row['bytes'],
                              'sha256': row['sha256'],
                              'parseStatus': row['parsed']['status'],
                              'stringCount': row['parsed'].get('stringCount'),
                              'rawCounts': {label: {encoding: value['count']
                                                    for encoding, value in encodings.items()}
                                            for label, encodings in row['raw']['results'].items()}}
                             for row in report['dexFiles']],
                'limitations': report['limitations']}
            print('::warning title=WorldBox metadata Java summary::' +
                  json.dumps(summary, separators=(',', ':')).replace('%', '%25'))
            for index, row in enumerate(report['dexFiles'], 1):
                label = row['apk'] + ' ' + str(index)
                raw_examples = []
                for needle, encodings in row['raw']['results'].items():
                    for encoding, value in encodings.items():
                        for example in value['examples']:
                            raw_examples.append({'needle': needle, 'encoding': encoding, **example})
                if raw_examples:
                    parts = [raw_examples[start:start + 12] for start in range(0, len(raw_examples), 12)]
                    raw_truncated = any(value['examplesTruncated']
                                        for encodings in row['raw']['results'].values()
                                        for value in encodings.values())
                    for number, part in enumerate(parts, 1):
                        payload = {'apk': row['apk'], 'dex': row['dex'],
                                   'chunk': [number, len(parts)], 'examples': part,
                                   'truncated': raw_truncated}
                        print('::warning title=WorldBox metadata Java raw hits ' + label +
                              ' ' + str(number) + '/' + str(len(parts)) + '::' +
                              json.dumps(payload, separators=(',', ':')).replace('%', '%25'))
                else:
                    print('::notice title=WorldBox metadata Java raw hits ' + label + '::' +
                          json.dumps({'status': 'no-examples'}, separators=(',', ':')))
                parsed = {'apk': row['apk'], 'dex': row['dex'], **row['parsed']}
                print('::warning title=WorldBox metadata Java DEX strings ' + label + '::' +
                      json.dumps(parsed, separators=(',', ':')).replace('%', '%25'))
            sys.exit(0)
        if os.environ.get('WORLDBOX_DEX_CALLBACK_PROBE') == '1':
            command = [sys.executable, '.github/scripts/worldbox_dex_callbacks.py', *map(str, apk_paths)]
            result = subprocess.run(command, capture_output=True, text=True, timeout=300)
            if result.returncode:
                raise RuntimeError('DEX callback analysis failed: ' + (result.stderr or result.stdout)[-1200:])
            report = json.loads(result.stdout)
            if report.get('kind') != 'worldbox-dex-callback-map':
                raise RuntimeError('Unexpected DEX callback report.')
            for dex in report.get('dexFiles', []):
                header = {'apk': dex.get('apk'), 'dex': dex.get('dex'),
                    'classesScanned': dex.get('classesScanned'),
                    'callbackInterfaceFound': dex.get('callbackInterfaceFound'),
                    'callbackMethods': dex.get('callbackMethods', []),
                    'directImplementerCount': len(dex.get('callbackImplementers', [])),
                    'constructorCallCount': len(dex.get('purchasingConstructorCalls', []))}
                print('::notice title=WorldBox DEX callback inventory::' + json.dumps(header, separators=(',', ':')).replace('%', '%25'))
                for row in dex.get('callbackImplementers', []):
                    print('::warning title=WorldBox DEX callback implementer::' + json.dumps(row, separators=(',', ':')).replace('%', '%25'))
                for row in dex.get('callbackReferenceClasses', []):
                    print('::warning title=WorldBox DEX callback field reference::' + json.dumps(row, separators=(',', ':')).replace('%', '%25'))
                for row in dex.get('callbackReferenceMethods', []):
                    print('::warning title=WorldBox DEX callback method reference::' + json.dumps(row, separators=(',', ':')).replace('%', '%25'))
                for row in dex.get('purchasingConstructorCalls', []):
                    print('::warning title=WorldBox UnityPurchasing constructor callsite::' + json.dumps(row, separators=(',', ':')).replace('%', '%25'))
                for bridge in dex.get('purchasingBridgeClasses', []):
                    for row in bridge.get('methods', []):
                        print('::warning title=WorldBox UnityPurchasing bridge method::' + json.dumps(row, separators=(',', ':')).replace('%', '%25'))
        if os.environ.get('WORLDBOX_CPP2IL_PROBE') == '1':
            if not base_apk or not arm64_apk:
                raise RuntimeError('Base APK and ARM64 split are required for Cpp2IL analysis.')
            output_root = Path(td) / 'cpp2il-out'
            command = [sys.executable, '.github/scripts/worldbox_cpp2il_probe.py',
                       '--binary', os.environ.get('CPP2IL_BIN', ''),
                       '--base-apk', str(base_apk), '--arm64-apk', str(arm64_apk),
                       '--output-root', str(output_root), '--temp-dir', td]
            result = subprocess.run(command, capture_output=True, text=True, timeout=1300)
            if result.returncode:
                raise RuntimeError('Cpp2IL wrapper failed: ' + (result.stderr or result.stdout)[-1200:])
            report = json.loads(result.stdout)
            if report.get('kind') != 'worldbox-cpp2il-probe':
                raise RuntimeError('Unexpected Cpp2IL result.')
            print('::warning title=WorldBox ARM64 Cpp2IL metadata probe::' +
                  json.dumps(report, separators=(',', ':')).replace('%', '%25'))
            sys.exit(0)
        if os.environ.get('WORLDBOX_MFUSCATOR_PROBE') == '1':
            if not native or not metadata or not base_apk or not arm64_apk:
                raise RuntimeError('Base APK, ARM64 split, native library, and metadata are required for MFuscator analysis.')
            output_root = Path(td) / 'bettercpp2il-out'
            work_root = Path(os.environ.get('BETTER_CPP2IL_WORK_DIR', Path(td) / 'bettercpp2il-work'))
            command = [sys.executable, '.github/scripts/worldbox_mfuscator_probe.py',
                       '--binary', os.environ.get('BETTER_CPP2IL_DLL', ''),
                       '--base-apk', str(base_apk), '--native', str(native), '--metadata', str(metadata),
                       '--output-dir', str(output_root), '--work-dir', str(work_root)]
            result = subprocess.run(command, capture_output=True, text=True, timeout=1600)
            if result.returncode:
                raise RuntimeError('BetterCpp2IL MFuscator wrapper failed: ' + (result.stderr or result.stdout)[-1200:])
            report = json.loads(result.stdout)
            if report.get('kind') != 'worldbox-bettercpp2il-mfuscator-probe':
                raise RuntimeError('Unexpected BetterCpp2IL MFuscator report.')
            print('::warning title=WorldBox BetterCpp2IL MFuscator probe::' +
                  json.dumps(report, separators=(',', ':')).replace('%', '%25'))
            sys.exit(0)
        if os.environ.get('WORLDBOX_IL2CPP_DUMPER_PROBE') == '1':
            if not native or not metadata or not base_apk or not arm64_apk:
                raise RuntimeError('Base APK, ARM64 split, native library, and metadata are required for IL2CPP recovery analysis.')
            output_root = Path(td) / 'mydearmoon-il2cpp-out'
            temp_root = Path(td) / 'mydearmoon-il2cpp-work'
            command = [sys.executable, '.github/scripts/worldbox_il2cpp_dumper_probe.py',
                       '--binary', os.environ.get('MYDEARMOON_IL2CPP_DUMPER_BIN', ''),
                       '--release-archive', os.environ.get('MYDEARMOON_IL2CPP_DUMPER_ARCHIVE', ''),
                       '--base-apk', str(base_apk), '--native', str(native), '--metadata', str(metadata),
                       '--output-dir', str(output_root), '--temp-dir', str(temp_root)]
            result = subprocess.run(command, capture_output=True, text=True, timeout=1600)
            if result.returncode:
                raise RuntimeError('MyDearMoon Il2CppDumper wrapper failed: ' + (result.stderr or result.stdout)[-1200:])
            report = json.loads(result.stdout)
            if report.get('kind') != 'worldbox-il2cpp-dumper-recovery-probe':
                raise RuntimeError('Unexpected MyDearMoon Il2CppDumper report.')
            print('::warning title=WorldBox Il2CppDumper recovery probe::' +
                  json.dumps(report, separators=(',', ':')).replace('%', '%25'))
            sys.exit(0)
        if os.environ.get('WORLDBOX_INSPECTOR_REDUX_PROBE') == '1':
            if not native or not metadata or not base_apk or not arm64_apk:
                raise RuntimeError('Base APK, ARM64 split, native library, and metadata are required for Il2CppInspectorRedux analysis.')
            output_root = Path(td) / 'inspector-redux-out'
            temp_root = Path(td) / 'inspector-redux-work'
            command = [sys.executable, '.github/scripts/worldbox_inspector_redux_probe.py',
                       '--binary', os.environ.get('IL2CPP_INSPECTOR_REDUX_BIN', ''),
                       '--release-archive', os.environ.get('IL2CPP_INSPECTOR_REDUX_ARCHIVE', ''),
                       '--base-apk', str(base_apk), '--native', str(native), '--metadata', str(metadata),
                       '--output-dir', str(output_root), '--temp-dir', str(temp_root)]
            result = subprocess.run(command, capture_output=True, text=True, timeout=1600)
            if result.returncode:
                raise RuntimeError('Il2CppInspectorRedux wrapper failed: ' + (result.stderr or result.stdout)[-1200:])
            report = json.loads(result.stdout)
            if report.get('kind') != 'worldbox-il2cppinspector-redux-probe':
                raise RuntimeError('Unexpected Il2CppInspectorRedux report.')
            print('::warning title=WorldBox Il2CppInspectorRedux probe::' +
                  json.dumps(report, separators=(',', ':')).replace('%', '%25'))
            sys.exit(0)
        if os.environ.get('WORLDBOX_GHIDRA_ARMV7_PROBE') == '1':
            if not native_v7 or not native_v7.is_file():
                raise RuntimeError('ARMv7 libil2cpp.so not found in the bundle.')
            with native_v7.open('rb') as f:
                observed = hashlib.file_digest(f, 'sha256').hexdigest()
            if observed != '1a8879d10d23b65c540ad5841882779fff06c9d60cf09f48fa79cf1428734052':
                raise RuntimeError('ARMv7 library hash does not match the observed 0.51.4 sample; refusing analysis.')
            command = [sys.executable, '.github/scripts/worldbox_ghidra_armv7.py',
                       '--headless', os.environ.get('GHIDRA_HEADLESS', ''), '--binary', str(native_v7)]
            result = subprocess.run(command, capture_output=True, text=True, timeout=700)
            if result.returncode:
                raise RuntimeError('Bounded ARMv7 Ghidra probe failed: ' + (result.stderr or result.stdout)[-1200:])
            report = json.loads(result.stdout)
            if report.get('kind') != 'worldbox-armv7-jni':
                raise RuntimeError('Unexpected ARMv7 Ghidra JNI result.')
            print('::warning title=WorldBox ARMv7 Ghidra JNI_OnLoad::' + json.dumps(report, separators=(',', ':')))
            sys.exit(0)
        if os.environ.get('WORLDBOX_GHIDRA_UNITY_PROBE') == '1':
            if not unity or not unity.is_file():
                raise RuntimeError('ARM64 libunity.so not found in the bundle.')
            with unity.open('rb') as f:
                observed = hashlib.file_digest(f, 'sha256').hexdigest()
            if observed != '8c04ad3b7d482cab925541cfe9839844c87732f7419aaaa71e170ccff916f082':
                raise RuntimeError('ARM64 libunity.so hash does not match the observed 0.51.4 sample; refusing analysis.')
            tool = os.environ.get('GHIDRA_HEADLESS', '')
            command = [sys.executable, '.github/scripts/worldbox_ghidra_callees.py',
                       '--headless', tool, '--binary', str(unity),
                       '--address', '0x752efc', '--address', '0x7537ac',
                       '--address', '0x606668', '--address', '0x607050',
                       '--trace-target', '0x10c9920']
            result = subprocess.run(command, capture_output=True, text=True, timeout=1000)
            if result.returncode:
                raise RuntimeError('Bounded libunity Ghidra probe failed: ' + (result.stderr or result.stdout)[-1200:])
            report = json.loads(result.stdout)
            if report.get('kind') != 'ghidra-callees-probe':
                raise RuntimeError('Unexpected libunity Ghidra callee result.')
            from worldbox_ghidra_callees import compact_callee
            for row in report.get('functions', []):
                print('::warning title=WorldBox libunity callback string xref::' + compact_callee(row))
                for call in row.get('indirectCallEvidence', []):
                    message = json.dumps({'function': row.get('entry'), **call}, separators=(',', ':'))
                    print('::warning title=WorldBox libunity indirect-call dataflow::' + message.replace('%', '%25'))
            print('::warning title=WorldBox libunity Ghidra limitations::' + report.get('limitations', ''))
            sys.exit(0)
        if os.environ.get('WORLDBOX_THUNK_CALLERS_PROBE') == '1':
            if not native or not native.is_file():
                raise RuntimeError('ARM64 libil2cpp.so not found in the bundle.')
            with native.open('rb') as f:
                observed = hashlib.file_digest(f, 'sha256').hexdigest()
            if observed != '1d644b98fec97a35630495c695515861acd2c18209beaae6471a650db65def87':
                raise RuntimeError('ARM64 library hash does not match the observed 0.51.4 sample; refusing analysis.')
            from worldbox_thunk_callers import reference_report
            from worldbox_native_flow import disassemble_fde
            tool = os.environ.get('GHIDRA_HEADLESS', '')
            report = reference_report(native)
            if report.get('kind') != 'worldbox-thunk-references':
                raise RuntimeError('Unexpected WorldBox thunk reference report.')
            print('WorldBox full thunk reference report: ' + json.dumps(report, separators=(',', ':')))
            summary = {key: report[key] for key in
                       ('unwindStatus', 'unwindRanges', 'executableBytes', 'executableScanned', 'execTruncated',
                        'allocatedDataBytes', 'allocatedDataScanned', 'dataTruncated',
                        'unsupportedRelocationSections')}
            print('::warning title=WorldBox thunk reference summary::' +
                  json.dumps(summary, separators=(',', ':')).replace('%', '%25'))
            for target_hex, info in report['thunks'].items():
                compact = {'target': target_hex, 'directCalls': info['directCalls'],
                           'tailBranches': info['tailBranches'],
                           'alignedPointerValues': info['alignedPointerValues'],
                           'pointerSamples': info['pointerSamples'],
                           'matchingRelocations': info['matchingRelocations'],
                           'relocationSamples': info['relocationSamples'],
                           'sampleSites': info['sampleSites']}
                print('::warning title=WorldBox thunk reference sites ' + target_hex + '::' +
                      json.dumps(compact, separators=(',', ':')).replace('%', '%25'))
            for row in report['staticData']:
                print('::warning title=WorldBox thunk static data ' + row['address'] + '::' +
                      json.dumps(row, separators=(',', ':')).replace('%', '%25'))
            def compact_thunk_row(row):
                return {'entry': row.get('entry'), 'anchorSites': row.get('anchorSites', []),
                        'fdeBytes': row.get('fdeBytes'), 'decompiled': row.get('decompiled'),
                        'status': row.get('status'), 'directCallCount': row.get('directCallCount'),
                        'operationCounts': row.get('operationCounts', {}),
                        'calls': [{'site': call.get('site'), 'target': call.get('target'),
                                   'verifiedDirect': call.get('verifiedDirect'),
                                   'importCategory': call.get('importCategory')}
                                  for call in row.get('calls', [])[:10]],
                        'tracedTargetArguments': [{key: item.get(key) for key in
                           ('site', 'target', 'argumentIndex', 'stringCategories', 'rootKinds',
                            'inputRegisters', 'nodes', 'limited')}
                           for item in row.get('tracedTargetArguments', [])[:12]],
                        'returnGraphs': [{'roots': graph.get('rootKinds', []),
                                          'strings': graph.get('stringCategories', []),
                                          'operations': sorted(graph.get('operationCounts', {})),
                                          'nodes': graph.get('nodes'),
                                          'limited': bool(graph.get('nodeLimitReached') or graph.get('depthLimitReached'))}
                                         for graph in row.get('returnGraphs', [])],
                        'stringCategories': row.get('stringCategories', []),
                        'truncated': row.get('truncated')}
            for target_hex, info in report['thunks'].items():
                sites = [item for item in info['sampleSites']
                         if item['function'] and item['size'] is not None and item['size'] <= 4096][:4]
                if not sites:
                    print('::notice title=WorldBox thunk caller Ghidra ' + target_hex + '::' +
                          json.dumps({'status': 'no-bounded-caller-samples'}, separators=(',', ':')))
                else:
                    command = [sys.executable, '.github/scripts/worldbox_ghidra_callees.py',
                               '--headless', tool, '--binary', str(native)]
                    for item in sites:
                        command += ['--address', item['site']]
                    command += ['--trace-target', target_hex]
                    result = subprocess.run(command, capture_output=True, text=True, timeout=1000)
                    if result.returncode:
                        diagnostic = (result.stderr or result.stdout)[-300:]
                        print('::notice title=WorldBox thunk caller Ghidra ' + target_hex + '::' +
                              json.dumps({'status': 'failed', 'diagnostic': diagnostic}, separators=(',', ':'))
                              .replace('%', '%25').replace('\r', '%0D').replace('\n', '%0A'))
                    else:
                        ghidra_report = json.loads(result.stdout)
                        if ghidra_report.get('kind') != 'ghidra-callees-probe':
                            raise RuntimeError('Unexpected thunk caller Ghidra report.')
                        for row in ghidra_report.get('functions', []):
                            print('::warning title=WorldBox thunk caller Ghidra ' + target_hex + '::' +
                                  json.dumps(compact_thunk_row(row), separators=(',', ':')).replace('%', '%25'))
                for fde_start in sorted({int(item['function'], 16) for item in sites}):
                    try:
                        fde_report = disassemble_fde(native, fde_start, max_size=2048)
                    except ValueError as exc:
                        print('::notice title=WorldBox thunk caller instructions ' + hex(fde_start) + '::' +
                              json.dumps({'status': 'unavailable', 'reason': str(exc)},
                                         separators=(',', ':')).replace('%', '%25'))
                    else:
                        print('WorldBox thunk caller full instruction report: ' +
                              json.dumps(fde_report, separators=(',', ':')))
                        lines = [f"{item['address']} {item['mnemonic']} {item['operands']}".strip().replace('%', '%25')
                                 for item in fde_report['instructions']]
                        parts, current = [], []
                        for line in lines:
                            candidate = current + [line]
                            if current and len('|'.join(candidate)) > 3400:
                                parts.append(current)
                                current = [line]
                            else:
                                current = candidate
                        if current:
                            parts.append(current)
                        for number, part in enumerate(parts, 1):
                            bounded = {'entry': fde_report['entry'], 'size': fde_report['size'],
                                       'decodedInstructions': fde_report['decodedInstructions'],
                                       'fullyDecoded': fde_report['fullyDecoded'],
                                       'chunk': [number, len(parts)], 'instructions': '|'.join(part)}
                            print('::warning title=WorldBox thunk caller instructions compact ' +
                                  hex(fde_start) + ' ' + str(number) + '/' + str(len(parts)) + '::' +
                                  json.dumps(bounded, separators=(',', ':')).replace('%', '%25'))
            print('::notice title=WorldBox thunk limitations::' +
                  report.get('limitations', '').replace('%', '%25').replace('\r', '%0D').replace('\n', '%0A'))
            sys.exit(0)
        if os.environ.get('WORLDBOX_GHIDRA_INDIRECT_SLOT_PROBE') == '1':
            if not native or not native.is_file():
                raise RuntimeError('ARM64 libil2cpp.so not found in the bundle.')
            with native.open('rb') as f:
                observed = hashlib.file_digest(f, 'sha256').hexdigest()
            if observed != '1d644b98fec97a35630495c695515861acd2c18209beaae6471a650db65def87':
                raise RuntimeError('ARM64 library hash does not match the observed 0.51.4 sample; refusing analysis.')
            from worldbox_indirect_slot_probe import emit_indirect_slot_annotations, indirect_slot_report
            from worldbox_native_flow import MAX_FUNCTION
            native_report = indirect_slot_report(native)
            emit_indirect_slot_annotations(native_report)
            addresses = []
            for row in native_report['rows']:
                for key in ('gotLoadSamples', 'slotLoadSamples', 'indirectCallSamples'):
                    for item in row[key]:
                        if (item.get('function') and item.get('size') is not None and
                                item['size'] <= MAX_FUNCTION):
                            addresses.append(item['function'])
            addresses = sorted(set(addresses))[:6]
            if not addresses:
                print('::notice title=WorldBox indirect slot Ghidra::' +
                      annotation(json.dumps({'status': 'no-bounded-consumer-functions'},
                                            separators=(',', ':'))))
                sys.exit(0)
            targets = ('0x3adeaf8', '0x3ae26c4', '0x18904e0', '0x18eb1a0',
                       '0x1890260', '0x18ee1b8', '0x18eb7a4', '0x18edbb8')
            tool = os.environ.get('GHIDRA_HEADLESS', '')
            command = [sys.executable, '.github/scripts/worldbox_ghidra_callees.py',
                       '--headless', tool, '--binary', str(native)]
            for address in addresses:
                command += ['--address', address]
            for target in targets:
                command += ['--trace-target', target]
            result = subprocess.run(command, capture_output=True, text=True, timeout=1200)
            if result.returncode:
                emit_ghidra_failure('indirect slot',
                                    (result.stderr or result.stdout)[-600:])
                sys.exit(0)
            ghidra_report = json.loads(result.stdout)
            emit_ghidra_annotations(ghidra_report, 'indirect slot', tuple(addresses),
                                    targets, native_report)
            sys.exit(0)
        if os.environ.get('WORLDBOX_GHIDRA_FILE_HELPER_PROBE') == '1':
            if not native or not native.is_file():
                raise RuntimeError('ARM64 libil2cpp.so not found in the bundle.')
            with native.open('rb') as f:
                observed = hashlib.file_digest(f, 'sha256').hexdigest()
            if observed != '1d644b98fec97a35630495c695515861acd2c18209beaae6471a650db65def87':
                raise RuntimeError('ARM64 library hash does not match the observed 0.51.4 sample; refusing analysis.')
            from worldbox_adjacent_thunks import (FILE_HELPER_KIND, FILE_HELPER_TARGETS,
                                                  FILE_HELPER_TRACE_TARGETS, reference_report)
            from worldbox_native_flow import MAX_FUNCTION
            from worldbox_static_literal_probe import emit_literal_annotations, literal_report
            native_report = reference_report(native, thunks=FILE_HELPER_TARGETS,
                                             kind=FILE_HELPER_KIND)
            emit_literal_annotations(literal_report(native))
            by_target = {row['target']: row for row in native_report['rows']}
            addresses, skipped = [], []
            for target in FILE_HELPER_TARGETS:
                row = by_target.get(hex(target))
                if (row and row['fdeStart'] and row['fdeSize'] is not None and
                        row['fdeSize'] <= MAX_FUNCTION):
                    addresses.append(hex(target))
                else:
                    skipped.append({'target': hex(target),
                                    'fdeStart': row.get('fdeStart') if row else None,
                                    'fdeSize': row.get('fdeSize') if row else None,
                                    'reason': 'no bounded FDE'})
            for row in native_report['rows']:
                if row['fdeStart'] and row['fdeSize'] is not None and row['fdeSize'] <= MAX_FUNCTION:
                    addresses.append(row['fdeStart'])
                for item in row['tailSamples'] + row['pcRelativeSamples']:
                    if (item.get('function') and item.get('size') is not None and
                            item['size'] <= MAX_FUNCTION):
                        addresses.append(item['function'])
            addresses = sorted(set(addresses))[:6]
            for item in skipped:
                print('::notice title=WorldBox file helper callee Ghidra skipped::' +
                      annotation(json.dumps(item, separators=(',', ':'))))
            if not addresses:
                emit_ghidra_failure('file helper callee',
                                    'No bounded FDE addresses were available.')
                sys.exit(0)
            tool = os.environ.get('GHIDRA_HEADLESS', '')
            command = [sys.executable, '.github/scripts/worldbox_ghidra_callees.py',
                       '--headless', tool, '--binary', str(native)]
            for address in addresses:
                command += ['--address', address]
            for target in FILE_HELPER_TRACE_TARGETS:
                command += ['--trace-target', target]
            result = subprocess.run(command, capture_output=True, text=True, timeout=1200)
            if result.returncode:
                emit_ghidra_failure('file helper callee',
                                    (result.stderr or result.stdout)[-600:])
                sys.exit(0)
            report = json.loads(result.stdout)
            emit_ghidra_annotations(report, 'file helper callee', tuple(addresses),
                                    FILE_HELPER_TRACE_TARGETS, native_report)
            sys.exit(0)
        if os.environ.get('WORLDBOX_GHIDRA_FILE_ADAPTER_PROBE') == '1':
            if not native or not native.is_file():
                raise RuntimeError('ARM64 libil2cpp.so not found in the bundle.')
            with native.open('rb') as f:
                observed = hashlib.file_digest(f, 'sha256').hexdigest()
            if observed != '1d644b98fec97a35630495c695515861acd2c18209beaae6471a650db65def87':
                raise RuntimeError('ARM64 library hash does not match the observed 0.51.4 sample; refusing analysis.')
            from worldbox_adjacent_thunks import (FILE_ADAPTER_KIND, FILE_ADAPTER_TARGETS,
                                                  FILE_ADAPTER_TRACE_TARGETS, reference_report)
            from worldbox_native_flow import MAX_FUNCTION
            native_report = reference_report(native, thunks=FILE_ADAPTER_TARGETS,
                                             kind=FILE_ADAPTER_KIND)
            by_target = {row['target']: row for row in native_report['rows']}
            addresses, skipped = [], []
            for target in FILE_ADAPTER_TARGETS:
                row = by_target.get(hex(target))
                if (row and row['fdeStart'] and row['fdeSize'] is not None and
                        row['fdeSize'] <= MAX_FUNCTION):
                    addresses.append(hex(target))
                else:
                    skipped.append({'target': hex(target),
                                    'fdeStart': row.get('fdeStart') if row else None,
                                    'fdeSize': row.get('fdeSize') if row else None,
                                    'reason': 'no bounded FDE'})
            for row in native_report['rows']:
                if row['fdeStart'] and row['fdeSize'] is not None and row['fdeSize'] <= MAX_FUNCTION:
                    addresses.append(row['fdeStart'])
                for item in row['tailSamples'] + row['pcRelativeSamples']:
                    if (item.get('function') and item.get('size') is not None and
                            item['size'] <= MAX_FUNCTION):
                        addresses.append(item['function'])
            addresses = sorted(set(addresses))[:6]
            for item in skipped:
                print('::notice title=WorldBox file adapter callee Ghidra skipped::' +
                      annotation(json.dumps(item, separators=(',', ':'))))
            if not addresses:
                emit_ghidra_failure('file adapter callee',
                                    'No bounded FDE addresses were available.')
                sys.exit(0)
            tool = os.environ.get('GHIDRA_HEADLESS', '')
            command = [sys.executable, '.github/scripts/worldbox_ghidra_callees.py',
                       '--headless', tool, '--binary', str(native)]
            for address in addresses:
                command += ['--address', address]
            for target in FILE_ADAPTER_TRACE_TARGETS:
                command += ['--trace-target', target]
            result = subprocess.run(command, capture_output=True, text=True, timeout=1200)
            if result.returncode:
                emit_ghidra_failure('file adapter callee',
                                    (result.stderr or result.stdout)[-600:])
                sys.exit(0)
            report = json.loads(result.stdout)
            emit_ghidra_annotations(report, 'file adapter callee', tuple(addresses),
                                    FILE_ADAPTER_TRACE_TARGETS, native_report)
            sys.exit(0)
        if os.environ.get('WORLDBOX_GHIDRA_DESTINATION_PROBE') == '1':
            if not native or not native.is_file():
                raise RuntimeError('ARM64 libil2cpp.so not found in the bundle.')
            with native.open('rb') as f:
                observed = hashlib.file_digest(f, 'sha256').hexdigest()
            if observed != '1d644b98fec97a35630495c695515861acd2c18209beaae6471a650db65def87':
                raise RuntimeError('ARM64 library hash does not match the observed 0.51.4 sample; refusing analysis.')
            from worldbox_adjacent_thunks import BRANCH_DESTINATIONS, reference_report
            native_report = reference_report(native, thunks=BRANCH_DESTINATIONS,
                                             kind='worldbox-branch-destination-probe')
            addresses = [hex(target) for target in BRANCH_DESTINATIONS]
            for row in native_report['rows']:
                if row['fdeStart']:
                    addresses.append(row['fdeStart'])
                for item in row['tailSamples'] + row['pcRelativeSamples']:
                    if item.get('function'):
                        addresses.append(item['function'])
            addresses = sorted(set(addresses))[:6]
            targets = ('0x1890260', '0x3adec0c', '0x3ae2828', '0x3ae2594',
                       '0x18904e0', '0x18eb1a0', '0x3adeaf8', '0x3ae26c4')
            tool = os.environ.get('GHIDRA_HEADLESS', '')
            command = [sys.executable, '.github/scripts/worldbox_ghidra_callees.py',
                       '--headless', tool, '--binary', str(native)]
            for address in addresses:
                command += ['--address', address]
            for target in targets:
                command += ['--trace-target', target]
            result = subprocess.run(command, capture_output=True, text=True, timeout=1000)
            if result.returncode:
                emit_ghidra_failure('branch destination',
                                    (result.stderr or result.stdout)[-600:])
                sys.exit(0)
            report = json.loads(result.stdout)
            emit_ghidra_annotations(report, 'branch destination', tuple(addresses),
                                    targets, native_report)
            sys.exit(0)
        if os.environ.get('WORLDBOX_GHIDRA_ADJACENT_PROBE') == '1':
            if not native or not native.is_file():
                raise RuntimeError('ARM64 libil2cpp.so not found in the bundle.')
            with native.open('rb') as f:
                observed = hashlib.file_digest(f, 'sha256').hexdigest()
            if observed != '1d644b98fec97a35630495c695515861acd2c18209beaae6471a650db65def87':
                raise RuntimeError('ARM64 library hash does not match the observed 0.51.4 sample; refusing analysis.')
            from worldbox_adjacent_thunks import reference_report
            native_report = reference_report(native)
            addresses = []
            for row in native_report['rows']:
                if row['fdeStart']:
                    addresses.append(row['fdeStart'])
                for item in row['tailSamples'] + row['pcRelativeSamples']:
                    if item.get('function'):
                        addresses.append(item['function'])
            addresses = sorted(set(addresses))[:6]
            targets = ('0x3ae2828', '0x3ae2594', '0x3adeaf8', '0x3ae26c4',
                       '0x18904e0', '0x18eb1a0')
            tool = os.environ.get('GHIDRA_HEADLESS', '')
            command = [sys.executable, '.github/scripts/worldbox_ghidra_callees.py',
                       '--headless', tool, '--binary', str(native)]
            for address in addresses:
                command += ['--address', address]
            for target in targets:
                command += ['--trace-target', target]
            result = subprocess.run(command, capture_output=True, text=True, timeout=1000)
            if result.returncode:
                diagnostic = (result.stderr or result.stdout)[-600:]
                print('::notice title=WorldBox adjacent thunk Ghidra::' + json.dumps(
                    {'status': 'failed', 'diagnostic': diagnostic}, separators=(',', ':'))
                    .replace('%', '%25').replace('\r', '%0D').replace('\n', '%0A'))
                sys.exit(0)
            report = json.loads(result.stdout)
            if report.get('kind') != 'ghidra-callees-probe':
                raise RuntimeError('Unexpected adjacent-thunk Ghidra report.')
            print('WorldBox full adjacent-thunk Ghidra report: ' +
                  json.dumps(report, separators=(',', ':')))
            summary = {'addresses': addresses, 'traceTargets': targets,
                       'functionCount': len(report.get('functions', [])),
                       'limitations': report.get('limitations')}
            print('::warning title=WorldBox adjacent thunk Ghidra summary::' +
                  json.dumps(summary, separators=(',', ':')).replace('%', '%25'))
            for row in report.get('functions', []):
                compact = {'entry': row.get('entry'), 'anchorSites': row.get('anchorSites', []),
                           'fdeBytes': row.get('fdeBytes'), 'decompiled': row.get('decompiled'),
                           'status': row.get('status'), 'directCallCount': row.get('directCallCount'),
                           'operationCounts': row.get('operationCounts', {}),
                           'calls': [{'site': call.get('site'), 'target': call.get('target'),
                                      'verifiedDirect': call.get('verifiedDirect'),
                                      'importCategory': call.get('importCategory')}
                                     for call in row.get('calls', [])[:10]],
                           'tracedTargetArguments': [{key: item.get(key) for key in
                              ('site', 'target', 'argumentIndex', 'stringCategories', 'rootKinds',
                               'inputRegisters', 'nodes', 'limited')}
                              for item in row.get('tracedTargetArguments', [])[:12]],
                           'returnGraphs': [{'roots': graph.get('rootKinds', []),
                                             'strings': graph.get('stringCategories', []),
                                             'operations': sorted(graph.get('operationCounts', {})),
                                             'nodes': graph.get('nodes'),
                                             'limited': bool(graph.get('nodeLimitReached') or graph.get('depthLimitReached'))}
                                            for graph in row.get('returnGraphs', [])],
                           'stringCategories': row.get('stringCategories', []),
                           'truncated': row.get('truncated')}
                print('::warning title=WorldBox adjacent thunk Ghidra::' +
                      json.dumps(compact, separators=(',', ':')).replace('%', '%25'))
            for native_row in native_report['rows']:
                for fde in native_row['fdeReports']:
                    if fde.get('status') == 'unavailable':
                        print('::notice title=WorldBox adjacent thunk FDE unavailable ' + fde['entry'] + '::' +
                              json.dumps(fde, separators=(',', ':')).replace('%', '%25'))
                        continue
                    lines = [f"{item['address']} {item['mnemonic']} {item['operands']}".strip().replace('%', '%25')
                             for item in fde['instructions']]
                    selected = lines[:100]
                    parts = [selected[start:start + 50] for start in range(0, len(selected), 50)]
                    for number, part in enumerate(parts, 1):
                        payload = {'entry': fde['entry'], 'size': fde['size'],
                                   'decodedInstructions': fde['decodedInstructions'],
                                   'fullyDecoded': fde['fullyDecoded'],
                                   'chunk': [number, len(parts)],
                                   'instructionsTruncated': len(lines) > len(selected),
                                   'instructions': '|'.join(part)}
                        print('::notice title=WorldBox adjacent thunk FDE instructions ' + fde['entry'] +
                              ' ' + str(number) + '/' + str(len(parts)) + '::' +
                              json.dumps(payload, separators=(',', ':')).replace('%', '%25'))
            sys.exit(0)
        if os.environ.get('WORLDBOX_GHIDRA_SLOT_PROBE') == '1':
            if not native or not native.is_file():
                raise RuntimeError('ARM64 libil2cpp.so not found in the bundle.')
            with native.open('rb') as f:
                observed = hashlib.file_digest(f, 'sha256').hexdigest()
            if observed != '1d644b98fec97a35630495c695515861acd2c18209beaae6471a650db65def87':
                raise RuntimeError('ARM64 library hash does not match the observed 0.51.4 sample; refusing analysis.')
            tool = os.environ.get('GHIDRA_HEADLESS', '')
            addresses = ('0x3524bf0', '0x358e170', '0x3590634')
            targets = ('0x3ae26c4', '0x3adeaf8', '0x18904e0', '0x18eb1a0',
                       '0x3ae2828', '0x3ae2594')
            command = [sys.executable, '.github/scripts/worldbox_ghidra_callees.py',
                       '--headless', tool, '--binary', str(native)]
            for address in addresses:
                command += ['--address', address]
            for target in targets:
                command += ['--trace-target', target]
            result = subprocess.run(command, capture_output=True, text=True, timeout=1000)
            if result.returncode:
                diagnostic = (result.stderr or result.stdout)[-600:]
                print('::notice title=WorldBox slot consumer Ghidra::' + json.dumps(
                    {'status': 'failed', 'diagnostic': diagnostic}, separators=(',', ':'))
                    .replace('%', '%25').replace('\r', '%0D').replace('\n', '%0A'))
                sys.exit(0)
            report = json.loads(result.stdout)
            if report.get('kind') != 'ghidra-callees-probe':
                raise RuntimeError('Unexpected slot-consumer Ghidra report.')
            anchors = {site for row in report.get('functions', [])
                       for site in row.get('anchorSites', [])}
            if not set(addresses).issubset(anchors):
                raise RuntimeError('Slot-consumer Ghidra report omitted a requested anchor address.')
            print('WorldBox full slot consumer Ghidra report: ' +
                  json.dumps(report, separators=(',', ':')))
            summary = {'addresses': addresses, 'traceTargets': targets,
                       'functionCount': len(report.get('functions', [])),
                       'limitations': report.get('limitations')}
            print('::warning title=WorldBox slot consumer Ghidra summary::' +
                  json.dumps(summary, separators=(',', ':')).replace('%', '%25'))
            for row in report.get('functions', []):
                compact = {'entry': row.get('entry'), 'anchorSites': row.get('anchorSites', []),
                           'fdeBytes': row.get('fdeBytes'), 'decompiled': row.get('decompiled'),
                           'status': row.get('status'), 'directCallCount': row.get('directCallCount'),
                           'operationCounts': row.get('operationCounts', {}),
                           'calls': [{'site': call.get('site'), 'target': call.get('target'),
                                      'verifiedDirect': call.get('verifiedDirect'),
                                      'importCategory': call.get('importCategory')}
                                     for call in row.get('calls', [])[:10]],
                           'tracedTargetArguments': [{key: item.get(key) for key in
                              ('site', 'target', 'argumentIndex', 'stringCategories', 'rootKinds',
                               'inputRegisters', 'nodes', 'limited')}
                              for item in row.get('tracedTargetArguments', [])[:12]],
                           'returnGraphs': [{'roots': graph.get('rootKinds', []),
                                             'strings': graph.get('stringCategories', []),
                                             'operations': sorted(graph.get('operationCounts', {})),
                                             'nodes': graph.get('nodes'),
                                             'limited': bool(graph.get('nodeLimitReached') or graph.get('depthLimitReached'))}
                                            for graph in row.get('returnGraphs', [])],
                           'stringCategories': row.get('stringCategories', []),
                           'truncated': row.get('truncated')}
                print('::warning title=WorldBox slot consumer Ghidra::' +
                      json.dumps(compact, separators=(',', ':')).replace('%', '%25'))
            from worldbox_native_flow import disassemble_fde
            for address in addresses:
                try:
                    fde_report = disassemble_fde(native, int(address, 0), max_size=8192)
                except ValueError as exc:
                    print('::notice title=WorldBox slot consumer instructions unavailable ' + address + '::' +
                          json.dumps({'status': 'unavailable', 'reason': str(exc)},
                                     separators=(',', ':')).replace('%', '%25'))
                    continue
                print('WorldBox full slot consumer instruction report: ' +
                      json.dumps(fde_report, separators=(',', ':')))
                lines = [f"{item['address']} {item['mnemonic']} {item['operands']}".strip().replace('%', '%25')
                         for item in fde_report['instructions']]
                selected = lines[:100]
                parts = [selected[start:start + 50] for start in range(0, len(selected), 50)]
                for number, part in enumerate(parts, 1):
                    payload = {'entry': fde_report['entry'], 'size': fde_report['size'],
                               'decodedInstructions': fde_report['decodedInstructions'],
                               'fullyDecoded': fde_report['fullyDecoded'],
                               'chunk': [number, len(parts)],
                               'instructionsTruncated': len(lines) > len(selected),
                               'instructions': '|'.join(part)}
                    print('::notice title=WorldBox slot consumer instructions ' + address +
                          ' ' + str(number) + '/' + str(len(parts)) + '::' +
                          json.dumps(payload, separators=(',', ':')).replace('%', '%25'))
            sys.exit(0)
        if os.environ.get('WORLDBOX_GHIDRA_HELPER_PROBE') == '1':
            if not native or not native.is_file():
                raise RuntimeError('ARM64 libil2cpp.so not found in the bundle.')
            with native.open('rb') as f:
                observed = hashlib.file_digest(f, 'sha256').hexdigest()
            if observed != '1d644b98fec97a35630495c695515861acd2c18209beaae6471a650db65def87':
                raise RuntimeError('ARM64 library hash does not match the observed 0.51.4 sample; refusing analysis.')
            tool = os.environ.get('GHIDRA_HEADLESS', '')
            command = [sys.executable, '.github/scripts/worldbox_ghidra_callees.py',
                       '--headless', tool, '--binary', str(native), '--address', '0x192ff8c',
                       '--address', '0x1890508', '--trace-target', '0x192ff8c']
            result = subprocess.run(command, capture_output=True, text=True, timeout=1000)
            if result.returncode:
                raise RuntimeError('Focused helper-predecessor Ghidra probe failed: ' +
                                   (result.stderr or result.stdout)[-1200:])
            report = json.loads(result.stdout)
            if report.get('kind') != 'ghidra-callees-probe':
                raise RuntimeError('Unexpected focused helper-predecessor Ghidra report.')
            rows = report.get('functions', [])
            anchors = {site for row in rows for site in row.get('anchorSites', [])}
            if not {'0x192ff8c', '0x1890508'}.issubset(anchors):
                raise RuntimeError('Focused Ghidra report omitted a requested anchor address.')
            for row in rows:
                compact = {'entry': row.get('entry'), 'anchorSites': row.get('anchorSites', []),
                           'fdeBytes': row.get('fdeBytes'), 'decompiled': row.get('decompiled'),
                           'status': row.get('status'), 'directCallCount': row.get('directCallCount'),
                           'operationCounts': row.get('operationCounts', {}),
                           'returnGraphs': [{'roots': graph.get('rootKinds', []),
                                             'strings': graph.get('stringCategories', []),
                                             'operations': sorted(graph.get('operationCounts', {})),
                                             'nodes': graph.get('nodes'),
                                             'limited': bool(graph.get('nodeLimitReached') or graph.get('depthLimitReached'))}
                                            for graph in row.get('returnGraphs', [])],
                           'stringCategories': row.get('stringCategories', []),
                           'calls': [{'site': call.get('site'), 'target': call.get('target'),
                                      'verifiedDirect': call.get('verifiedDirect'),
                                      'importCategory': call.get('importCategory')}
                                     for call in row.get('calls', [])[:10]],
                           'tracedTargetArguments': [{key: item.get(key) for key in
                              ('site', 'target', 'argumentIndex', 'stringCategories', 'rootKinds',
                               'inputRegisters', 'nodes', 'limited')}
                              for item in row.get('tracedTargetArguments', [])[:12]],
                           'truncated': row.get('truncated')}
                print('::warning title=WorldBox focused helper predecessor::' +
                      json.dumps(compact, separators=(',', ':')).replace('%', '%25'))
            from worldbox_native_flow import disassemble_fde
            instructions = disassemble_fde(native, 0x192ff8c)
            print('::warning title=WorldBox focused helper predecessor instructions::' +
                  json.dumps(instructions, separators=(',', ':')).replace('%', '%25'))
            branch = instructions['instructions'][-1] if instructions['instructions'] else {}
            if branch.get('mnemonic') == 'b' and branch.get('operands', '').startswith('#'):
                branch_target = int(branch['operands'][1:], 0)
                target_command = [sys.executable, '.github/scripts/worldbox_ghidra_callees.py',
                                  '--headless', tool, '--binary', str(native), '--address', hex(branch_target),
                                  '--address', '0x1930028', '--trace-target', '0x3bf9130',
                                  '--trace-target', '0x1930028', '--trace-target', '0x19a67d8']
                target_result = subprocess.run(target_command, capture_output=True, text=True, timeout=1000)
                if target_result.returncode:
                    print('::notice title=WorldBox helper branch destination::' + json.dumps(
                        {'target': hex(branch_target), 'boundedFdeAvailable': False}, separators=(',', ':')))
                else:
                    target_report = json.loads(target_result.stdout)
                    if target_report.get('kind') != 'ghidra-callees-probe':
                        raise RuntimeError('Unexpected helper branch destination Ghidra report.')
                    target_rows = target_report.get('functions', [])
                    target_anchors = {site for row in target_rows for site in row.get('anchorSites', [])}
                    if hex(branch_target) not in target_anchors:
                        raise RuntimeError('Ghidra branch-destination report omitted the requested anchor.')
                    for row in target_rows:
                        compact = {'entry': row.get('entry'), 'anchorSites': row.get('anchorSites', []),
                                   'fdeBytes': row.get('fdeBytes'), 'decompiled': row.get('decompiled'),
                                   'status': row.get('status'), 'directCallCount': row.get('directCallCount'),
                                   'operationCounts': row.get('operationCounts', {}),
                                   'returnGraphs': [{'roots': graph.get('rootKinds', []),
                                                     'strings': graph.get('stringCategories', []),
                                                     'operations': sorted(graph.get('operationCounts', {})),
                                                     'nodes': graph.get('nodes'),
                                                     'limited': bool(graph.get('nodeLimitReached') or graph.get('depthLimitReached'))}
                                                    for graph in row.get('returnGraphs', [])],
                                   'stringCategories': row.get('stringCategories', []),
                                   'calls': [{'site': call.get('site'), 'target': call.get('target'),
                                              'verifiedDirect': call.get('verifiedDirect'),
                                              'importCategory': call.get('importCategory')}
                                             for call in row.get('calls', [])[:10]],
                                   'tracedTargetArguments': [{key: item.get(key) for key in
                                      ('site', 'target', 'argumentIndex', 'stringCategories', 'rootKinds',
                                       'inputRegisters', 'nodes', 'limited')}
                                      for item in row.get('tracedTargetArguments', [])[:12]],
                                   'truncated': row.get('truncated')}
                        print('::warning title=WorldBox helper branch destination::' +
                              json.dumps(compact, separators=(',', ':')).replace('%', '%25'))
                    from worldbox_native_flow import disassemble_fde
                    target_instructions = disassemble_fde(native, branch_target)
                    print('::warning title=WorldBox helper branch destination instructions::' +
                          json.dumps(target_instructions, separators=(',', ':')).replace('%', '%25'))
                    adjacent_instructions = disassemble_fde(native, 0x1930028, max_size=512)
                    print('::warning title=WorldBox adjacent conversion helper instructions::' +
                          json.dumps(adjacent_instructions, separators=(',', ':')).replace('%', '%25'))
                    caller_instructions = disassemble_fde(native, 0x18904e0)
                    print('::warning title=WorldBox conversion and file-helper caller instructions::' +
                          json.dumps(caller_instructions, separators=(',', ':')).replace('%', '%25'))
                    file_helper_instructions = disassemble_fde(native, 0x18eb1a0, max_size=1024)
                    print('::warning title=WorldBox file-helper instructions::' +
                          json.dumps(file_helper_instructions, separators=(',', ':')).replace('%', '%25'))
                    open_sequence = [item for item in file_helper_instructions['instructions']
                                     if 0x18eb28c <= int(item['address'], 16) <= 0x18eb3d0]
                    lines = [f"{item['address']} {item['mnemonic']} {item['operands']}".strip().replace('%', '%25')
                             for item in open_sequence]
                    parts, current = [], []
                    for line in lines:
                        candidate = current + [line]
                        if current and len('|'.join(candidate)) > 3400:
                            parts.append(current)
                            current = [line]
                        else:
                            current = candidate
                    if current:
                        parts.append(current)
                    for number, part in enumerate(parts, 1):
                        print(f'::warning title=WorldBox file-helper open sequence {number}/{len(parts)}::' +
                              '|'.join(part))
            adapter_command = [sys.executable, '.github/scripts/worldbox_ghidra_callees.py',
                               '--headless', tool, '--binary', str(native),
                               '--address', '0x3adeb90', '--address', '0x3ae26c4',
                               '--trace-target', '0x18904e0']
            adapter_result = subprocess.run(adapter_command, capture_output=True, text=True, timeout=1000)
            if adapter_result.returncode:
                diagnostic = (adapter_result.stderr or adapter_result.stdout)[-300:]
                print('::notice title=WorldBox adapter tail caller Ghidra::' + json.dumps(
                    {'status': 'failed', 'diagnostic': diagnostic}, separators=(',', ':'))
                    .replace('%', '%25').replace('\r', '%0D').replace('\n', '%0A'))
            else:
                adapter_report = json.loads(adapter_result.stdout)
                if adapter_report.get('kind') != 'ghidra-callees-probe':
                    raise RuntimeError('Unexpected adapter tail caller Ghidra report.')
                for row in adapter_report.get('functions', []):
                    compact = {'entry': row.get('entry'), 'anchorSites': row.get('anchorSites', []),
                               'fdeBytes': row.get('fdeBytes'), 'decompiled': row.get('decompiled'),
                               'status': row.get('status'), 'directCallCount': row.get('directCallCount'),
                               'operationCounts': row.get('operationCounts', {}),
                               'calls': [{'site': call.get('site'), 'target': call.get('target'),
                                          'verifiedDirect': call.get('verifiedDirect'),
                                          'importCategory': call.get('importCategory')}
                                         for call in row.get('calls', [])[:10]],
                               'tracedTargetArguments': [{key: item.get(key) for key in
                                  ('site', 'target', 'argumentIndex', 'stringCategories', 'rootKinds',
                                   'inputRegisters', 'nodes', 'limited')}
                                  for item in row.get('tracedTargetArguments', [])[:12]],
                               'returnGraphs': [{'roots': graph.get('rootKinds', []),
                                                 'strings': graph.get('stringCategories', []),
                                                 'operations': sorted(graph.get('operationCounts', {})),
                                                 'nodes': graph.get('nodes'),
                                                 'limited': bool(graph.get('nodeLimitReached') or graph.get('depthLimitReached'))}
                                                for graph in row.get('returnGraphs', [])],
                               'stringCategories': row.get('stringCategories', []),
                               'truncated': row.get('truncated')}
                    print('::warning title=WorldBox adapter tail caller Ghidra::' +
                          json.dumps(compact, separators=(',', ':')).replace('%', '%25'))
            for fde_start in (0x3adeaf8, 0x3ae26c4):
                try:
                    fde_report = disassemble_fde(native, fde_start)
                except ValueError as exc:
                    print('::notice title=WorldBox adapter tail caller instructions::' + json.dumps(
                        {'entry': hex(fde_start), 'status': 'unavailable', 'reason': str(exc)},
                        separators=(',', ':')).replace('%', '%25'))
                else:
                    print('::warning title=WorldBox adapter tail caller instructions::' +
                          json.dumps(fde_report, separators=(',', ':')).replace('%', '%25'))
            print('::warning title=WorldBox focused helper Ghidra limitations::' + report.get('limitations', ''))
            sys.exit(0)
        if (os.environ.get('WORLDBOX_GHIDRA_PROBE') == '1' or
                os.environ.get('WORLDBOX_GHIDRA_METADATA_PROBE') == '1' or
                os.environ.get('WORLDBOX_GHIDRA_IO_PROBE') == '1'):
            if not native or not native.is_file():
                raise RuntimeError('ARM64 libil2cpp.so not found in the bundle.')
            with native.open('rb') as f:
                observed = hashlib.file_digest(f, 'sha256').hexdigest()
            if observed != '1d644b98fec97a35630495c695515861acd2c18209beaae6471a650db65def87':
                raise RuntimeError('ARM64 library hash does not match the observed 0.51.4 sample; refusing analysis.')
            tool = os.environ.get('GHIDRA_HEADLESS', '')
            io_mode = os.environ.get('WORLDBOX_GHIDRA_IO_PROBE') == '1'
            if io_mode:
                command = [sys.executable, '.github/scripts/worldbox_ghidra_callees.py',
                           '--headless', tool, '--binary', str(native),
                           '--address', '0x18ebdf0', '--address', '0x18ebec4',
                           '--address', '0x18ebf70', '--address', '0x18ebfb0',
                           '--address', '0x18eb1a0', '--address', '0x18d3fd0', '--address', '0x18a8b60',
                           '--address', '0x18fad2c', '--address', '0x19022fc', '--address', '0x1890524',
                           '--address', '0x192ff8c', '--address', '0x1902fbc', '--trace-target', '0x18d3dd0',
                           '--trace-target', '0x3bf90c0', '--trace-target', '0x3bf9030',
                           '--trace-target', '0x3bf9700', '--trace-target', '0x3bf9710',
                           '--trace-target', '0x18ebcb4', '--trace-target', '0x18ebe74',
                           '--trace-target', '0x18eb1a0', '--trace-target', '0x192ff8c']
                result = subprocess.run(command, capture_output=True, text=True, timeout=1200)
                if result.returncode:
                    raise RuntimeError('File-access Ghidra probe failed: ' + (result.stderr or result.stdout)[-1200:])
                report = json.loads(result.stdout)
                if report.get('kind') != 'ghidra-callees-probe':
                    raise RuntimeError('Unexpected file-access Ghidra report.')
                print('::warning title=WorldBox file-access import targets::' + json.dumps(
                    report.get('traceImportTargets', {}), separators=(',', ':')).replace('%', '%25'))
                from worldbox_ghidra_callees import compact_callee
                for row in report.get('functions', []):
                    summary = {'entry': row.get('entry'), 'anchors': row.get('anchorSites', []),
                               'fdeBytes': row.get('fdeBytes'), 'decompiled': row.get('decompiled'),
                               'status': row.get('status'), 'directCallCount': row.get('directCallCount'),
                               'indirectCallCount': row.get('indirectCallCount'),
                               'stringCategories': row.get('stringCategories', [])}
                    print('::notice title=WorldBox file-access FDE summary::' + json.dumps(summary, separators=(',', ':')))
                    try:
                        payload = compact_callee(row)
                    except ValueError:
                        calls = [{'site': call.get('site'), 'target': call.get('target'),
                                  'verifiedDirect': call.get('verifiedDirect'),
                                  'importCategory': call.get('importCategory')}
                                 for call in row.get('calls', [])[:8]]
                        traced = []
                        for item in row.get('tracedTargetArguments', [])[:16]:
                            operations = item.get('operations', {})
                            traced.append({'site': item.get('site'), 'target': item.get('target'),
                                'argumentIndex': item.get('argumentIndex'),
                                'rootKinds': item.get('rootKinds', []),
                                'inputRegisters': item.get('inputRegisters', []),
                                'stringCategories': item.get('stringCategories', []),
                                'operations': sorted(operations)[:8] if isinstance(operations, dict) else [],
                                'nodes': item.get('nodes'), 'limited': item.get('limited')})
                        fallback = {'entry': row.get('entry'), 'anchorSites': row.get('anchorSites', []),
                            'status': row.get('status'), 'calls': calls, 'tracedTargetArguments': traced,
                            'tracedArgumentsOmitted': max(0, len(row.get('tracedTargetArguments', [])) - len(traced)),
                            'truncated': row.get('truncated')}
                        payload = json.dumps(fallback, separators=(',', ':'))
                        while len(payload) > 3700 and traced:
                            traced.pop()
                            fallback['tracedArgumentsOmitted'] = max(
                                0, len(row.get('tracedTargetArguments', [])) - len(traced))
                            payload = json.dumps(fallback, separators=(',', ':'))
                    print('::warning title=WorldBox file-access caller::' + payload)
                print('::warning title=WorldBox file-access Ghidra limitations::' + report.get('limitations', ''))
                sys.exit(0)
            metadata_mode = os.environ.get('WORLDBOX_GHIDRA_METADATA_PROBE') == '1'
            if metadata_mode:
                command = [sys.executable, '.github/scripts/worldbox_metadata_magic_probe.py',
                           '--headless', tool, '--binary', str(native)]
                result = subprocess.run(command, capture_output=True, text=True, timeout=1200)
                if result.returncode:
                    raise RuntimeError('Metadata magic/Ghidra probe failed: ' + (result.stderr or result.stdout)[-1200:])
                report = json.loads(result.stdout)
                if report.get('kind') != 'worldbox-il2cpp-metadata-magic-probe':
                    raise RuntimeError('Unexpected IL2CPP metadata magic report.')
                print('::warning title=WorldBox IL2CPP metadata magic scan::' + json.dumps({
                    'sha256': report['scan']['sha256'], 'fileSize': report['scan']['fileSize'],
                    'hitCount': report['scan']['hitCount'], 'hitsTruncated': report['scan']['hitsTruncated'],
                    'hits': report['scan']['hits'], 'dataTargets': report['dataTargets'],
                    'referenceCount': report['referenceCount'], 'referencesTruncated': report['referencesTruncated']
                }, separators=(',', ':')).replace('%', '%25'))
                ghidra_report = report.get('ghidra')
                if ghidra_report:
                    from worldbox_ghidra_callees import compact_callee
                    for row in ghidra_report.get('functions', []):
                        print('::warning title=WorldBox metadata magic reference caller::' + compact_callee(row))
                    print('::warning title=WorldBox metadata magic Ghidra limitations::' + ghidra_report.get('limitations', ''))
                else:
                    print('::notice title=WorldBox metadata magic follow-up::No bounded ADRP+ADD references to allocated, non-executable magic hits were found; Ghidra was not run.')
                print('::notice title=WorldBox metadata magic limitations::' + report['limitations'])
                sys.exit(0)
            origin_mode = os.environ.get('WORLDBOX_GHIDRA_ORIGIN_PROBE') == '1'
            tail_mode = os.environ.get('WORLDBOX_GHIDRA_TAIL_PROBE') == '1'
            return_mode = os.environ.get('WORLDBOX_GHIDRA_RETURN_PROBE') == '1'
            input_mode = os.environ.get('WORLDBOX_GHIDRA_INPUT_PROBE') == '1'
            children_mode = os.environ.get('WORLDBOX_GHIDRA_CHILDREN_PROBE') == '1'
            jni_mode = os.environ.get('WORLDBOX_GHIDRA_JNI_PROBE') == '1'
            callee_mode = os.environ.get('WORLDBOX_GHIDRA_CALLEE_PROBE') == '1' or origin_mode or tail_mode or return_mode or input_mode or children_mode or jni_mode
            source_mode = os.environ.get('WORLDBOX_GHIDRA_SOURCE_PROBE') == '1'
            chain_mode = os.environ.get('WORLDBOX_GHIDRA_CHAIN_PROBE') == '1'
            probe_script = 'worldbox_ghidra_callees.py' if callee_mode else 'worldbox_ghidra_probe.py'
            probe_args = [sys.executable, '.github/scripts/' + probe_script,
                          '--headless', tool, '--binary', str(native)]
            if jni_mode:
                # Inspect the known JNI caller and its direct callee as one bounded lead.
                probe_args += ['--address', '0x18d02c8', '--address', '0x191c8c4']
            elif children_mode:
                probe_args.append('--input-children')
            elif input_mode:
                probe_args.append('--input-origin')
            elif return_mode:
                probe_args.append('--return-origin')
            elif tail_mode:
                probe_args.append('--tail-origin')
            elif origin_mode:
                probe_args.append('--origin')
            elif chain_mode:
                probe_args.append('--input-chain')
            elif source_mode:
                probe_args.append('--input-source')
            result = subprocess.run(probe_args, capture_output=True, text=True, timeout=1000)
            if result.returncode:
                message = 'Bounded Ghidra probe failed: ' + result.stderr[-1200:]
                print('::error title=WorldBox Ghidra probe::' + message.replace('%', '%25').replace('\n', '%0A'))
                raise RuntimeError(message)
            report = json.loads(result.stdout)
            if callee_mode:
                if report.get('kind') != 'ghidra-callees-probe':
                    raise RuntimeError('Unexpected Ghidra callee result.')
                from worldbox_ghidra_callees import compact_callee
                for row in report.get('functions', []):
                    print('::warning title=WorldBox Ghidra callee::' + compact_callee(row))
                print('::warning title=WorldBox Ghidra callee limitations::' + report.get('limitations', ''))
                sys.exit(0)
            if report.get('kind') != 'ghidra-bounded-probe':
                raise RuntimeError('Unexpected Ghidra probe result.')
            rows = report.get('sites', [])
            print('::warning title=WorldBox Ghidra summary::' + json.dumps({
                'helperSignatureApplied': report.get('helperSignatureApplied'),
                'forcedPrototype': report.get('forcedPrototype'),
                'sites': len(rows), 'decompiled': sum(bool(row.get('decompiled')) for row in rows),
                'callsFound': sum(bool(row.get('callFound')) for row in rows),
                'limitation': report.get('limitations')}, separators=(',', ':')))
            from worldbox_ghidra_probe import compact_site
            for row in rows:
                print('::warning title=WorldBox Ghidra site::' + compact_site(row))
            sys.exit(0)
        if os.environ.get('WORLDBOX_UPSTREAM_PROBE') == '1':
            if not native or not native.is_file():
                raise RuntimeError('ARM64 libil2cpp.so not found in the bundle.')
            with native.open('rb') as f:
                observed = hashlib.file_digest(f, 'sha256').hexdigest()
            if observed != '1d644b98fec97a35630495c695515861acd2c18209beaae6471a650db65def87':
                raise RuntimeError('ARM64 library hash does not match the observed 0.51.4 sample; refusing analysis.')
            level2 = os.environ.get('WORLDBOX_UPSTREAM_LEVEL2') == '1'
            level3 = os.environ.get('WORLDBOX_UPSTREAM_LEVEL3') == '1'
            tail_mode = os.environ.get('WORLDBOX_UPSTREAM_TAIL_PROBE') == '1'
            return_mode = os.environ.get('WORLDBOX_UPSTREAM_RETURN_PROBE') == '1'
            input_mode = os.environ.get('WORLDBOX_UPSTREAM_INPUT_PROBE') == '1'
            children_mode = os.environ.get('WORLDBOX_UPSTREAM_CHILDREN_PROBE') == '1'
            probe_args = [sys.executable, '.github/scripts/worldbox_upstream.py', str(native)]
            if children_mode:
                probe_args += ['--batch-origin', '0x18d6fa8:0x18d6f00',
                               '--batch-origin', '0x1932b90:0x18d6f1c',
                               '--batch-origin', '0x1937d24:0x18d6f40']
            elif input_mode:
                probe_args += ['--only-origin', '--trace-origin', '0x18d6ecc',
                               '--caller', '0x18d838c', '--caller-kind', 'direct']
            elif return_mode:
                probe_args += ['--only-origin', '--trace-origin', '0x18d84bc',
                               '--caller', '0x18d83a0', '--caller-kind', 'direct']
            elif tail_mode:
                probe_args += ['--only-origin', '--trace-origin', '0x18d834c',
                               '--caller', '0x190399c', '--caller-kind', 'tail']
            elif level3:
                probe_args += ['--target', '0x3a90ae0', '--target', '0x3a90ae4', '--references',
                               '--trace-origin', '0x1903990', '--caller', '0x3995fc4']
            elif level2:
                probe_args += ['--target', '0x18fa1f4', '--target', '0x18fa520']
            result = subprocess.run(probe_args, capture_output=True, text=True, timeout=600)
            if result.returncode:
                message = 'Upstream probe failed: ' + result.stderr[-1200:]
                print('::error title=WorldBox upstream probe::' + message.replace('%', '%25').replace('\n', '%0A'))
                raise RuntimeError(message)
            from worldbox_upstream import annotation_payloads, multi_annotation_payloads
            report = json.loads(result.stdout)
            if children_mode:
                origins = report.get('origins', [])
                if report.get('kind') != 'arm64-upstream-origin-batch' or len(origins) != 3:
                    raise RuntimeError('Unexpected upstream origin batch')
                for origin in origins:
                    payload = json.dumps(origin, separators=(',', ':'))
                    if len(payload) > 3800:
                        raise RuntimeError('Upstream origin report exceeds annotation bound')
                    print('::warning title=WorldBox upstream origin::' + payload)
            elif tail_mode or return_mode or input_mode:
                if report.get('kind') != 'arm64-upstream-origin':
                    raise RuntimeError('Unexpected upstream origin report')
                payload = json.dumps(report.get('origin', {}), separators=(',', ':'))
                if len(payload) > 3800:
                    raise RuntimeError('Upstream origin report exceeds annotation bound')
                print('::warning title=WorldBox upstream origin::' + payload)
            elif level2 or level3:
                for kind, payload in multi_annotation_payloads(report):
                    print('::warning title=WorldBox upstream ' + kind + '::' + payload)
            else:
                payloads = annotation_payloads(report)
                print('::warning title=WorldBox upstream summary::' + payloads[0])
                for payload in payloads[1:]:
                    print('::warning title=WorldBox upstream example::' + payload)
            sys.exit(0)
        if os.environ.get('WORLDBOX_UNITY_SCHEMA') == '1':
            if not native or not native.is_file():
                raise RuntimeError('ARM64 libil2cpp.so not found in the bundle.')
            with native.open('rb') as f:
                observed = hashlib.file_digest(f, 'sha256').hexdigest()
            if observed != '1d644b98fec97a35630495c695515861acd2c18209beaae6471a650db65def87':
                raise RuntimeError('ARM64 libil2cpp hash mismatch; refusing analysis.')
            base = Path(td) / 'base.apk'
            if not base.is_file():
                raise RuntimeError('Base APK not found in the bundle.')
            with base.open('rb') as f:
                base_hash = hashlib.file_digest(f, 'sha256').hexdigest()
            if base_hash != 'ab7c6bab7d2233c26a9e18426aa58dd60fa0ae0ad9be6fa0b2a6673dd8f89c3f':
                raise RuntimeError('Base APK does not match the observed asset-scan sample.')
            result = subprocess.run([sys.executable, '.github/scripts/worldbox_unity_schema.py', str(base)],
                                    capture_output=True, text=True, timeout=360, check=True)
            report = json.loads(result.stdout)
            if report.get('kind') != 'worldbox-unity-schema-leads':
                raise RuntimeError('Unexpected Unity schema result.')
            print('Unity selected component schema report: ' + json.dumps(report, separators=(',', ':')))
            for file in report['files']:
                for obj in file['objects']:
                    print('::warning title=WorldBox component schema::' + json.dumps({'entry': file['entry'], **obj}, separators=(',', ':')))
            sys.exit(0)
        if os.environ.get('WORLDBOX_GUID_SCRIPT_REFS') == '1':
            if not native or not native.is_file():
                raise RuntimeError('ARM64 libil2cpp.so not found in the bundle.')
            with native.open('rb') as f:
                observed = hashlib.file_digest(f, 'sha256').hexdigest()
            if observed != '1d644b98fec97a35630495c695515861acd2c18209beaae6471a650db65def87':
                raise RuntimeError('ARM64 libil2cpp hash mismatch; refusing analysis.')
            base = Path(td) / 'base.apk'
            if not base.is_file():
                raise RuntimeError('Base APK not found in the bundle.')
            with base.open('rb') as f:
                base_hash = hashlib.file_digest(f, 'sha256').hexdigest()
            if base_hash != 'ab7c6bab7d2233c26a9e18426aa58dd60fa0ae0ad9be6fa0b2a6673dd8f89c3f':
                raise RuntimeError('Base APK does not match the observed asset-scan sample.')
            args = [sys.executable, '.github/scripts/worldbox_guid_script_refs.py', str(base)]
            if os.environ.get('WORLDBOX_GUID_ALL') == '1':
                args.append('--all')
            result = subprocess.run(args, capture_output=True, text=True, timeout=900, check=True)
            report = json.loads(result.stdout)
            if report.get('kind') != 'worldbox-guid-script-references':
                raise RuntimeError('Unexpected extensionless Unity-reference result.')
            print('WorldBox extensionless Unity-reference report: ' + json.dumps(report, separators=(',', ':')))
            summary = {k: v for k, v in report.items() if k != 'resultFiles'}
            print('::warning title=WorldBox extensionless Unity reference summary::' + json.dumps(summary, separators=(',', ':')))
            examples = []
            for file in report['resultFiles']:
                examples.extend({'entry': file['entry'], **row} for row in file['samples'])
            # One bounded annotation preserves a useful cross-file sample even
            # when Actions limits per-step annotations. Full report is in logs.
            compact = {'examples': examples[:12], 'truncated': len(examples) > 12 or report['resultFilesTruncated']
                       or any(f['samplesTruncated'] for f in report['resultFiles'])}
            print('::warning title=WorldBox extensionless Unity reference candidates::' + json.dumps(compact, separators=(',', ':')))
            sys.exit(0)
        if os.environ.get('WORLDBOX_BUNDLE_INVENTORY') == '1':
            if not native or not native.is_file():
                raise RuntimeError('ARM64 libil2cpp.so not found in the bundle.')
            with native.open('rb') as f:
                observed = hashlib.file_digest(f, 'sha256').hexdigest()
            if observed != '1d644b98fec97a35630495c695515861acd2c18209beaae6471a650db65def87':
                raise RuntimeError('ARM64 libil2cpp hash mismatch; refusing analysis.')
            base = Path(td) / 'base.apk'
            if not base.is_file():
                raise RuntimeError('Base APK not found in the bundle.')
            with base.open('rb') as f:
                base_hash = hashlib.file_digest(f, 'sha256').hexdigest()
            if base_hash != 'ab7c6bab7d2233c26a9e18426aa58dd60fa0ae0ad9be6fa0b2a6673dd8f89c3f':
                raise RuntimeError('Base APK does not match the observed asset-scan sample.')
            names = [Path(name).name for name in apks]
            if len(names) > 32 or len(set(names)) != len(names):
                raise RuntimeError('Too many APKs or duplicate APK basenames in bundle.')
            args = [str(Path(td) / name) for name in names]
            result = subprocess.run([sys.executable, '.github/scripts/worldbox_bundle_inventory.py', *args],
                                    capture_output=True, text=True, timeout=360, check=True)
            report = json.loads(result.stdout)
            if report.get('kind') != 'worldbox-bundle-inventory':
                raise RuntimeError('Unexpected Unity bundle inventory result.')
            print('WorldBox APK bundle inventory: ' + json.dumps(report, separators=(',', ':')))
            # Emit all APK summaries before any examples: Actions can cap the
            # number of annotations from a single step.
            for apk_report in report['apks']:
                summary = {k: v for k, v in apk_report.items() if k != 'samples'}
                print('::warning title=WorldBox APK bundle inventory::' + json.dumps(summary, separators=(',', ':')))
            samples_left = 4
            for apk_report in report['apks']:
                for row in apk_report['samples'][:samples_left]:
                    print('::warning title=WorldBox APK bundle candidate::' + json.dumps({'apk': apk_report['apk'], **row}, separators=(',', ':')))
                samples_left = max(0, samples_left - len(apk_report['samples']))
            sys.exit(0)
        if os.environ.get('WORLDBOX_UNITY_SCRIPT_REFS') == '1':
            if not native or not native.is_file():
                raise RuntimeError('ARM64 libil2cpp.so not found in the bundle.')
            with native.open('rb') as f:
                observed = hashlib.file_digest(f, 'sha256').hexdigest()
            if observed != '1d644b98fec97a35630495c695515861acd2c18209beaae6471a650db65def87':
                raise RuntimeError('ARM64 libil2cpp hash mismatch; refusing analysis.')
            base = Path(td) / 'base.apk'
            if not base.is_file():
                raise RuntimeError('Base APK not found in the bundle.')
            with base.open('rb') as f:
                base_hash = hashlib.file_digest(f, 'sha256').hexdigest()
            if base_hash != 'ab7c6bab7d2233c26a9e18426aa58dd60fa0ae0ad9be6fa0b2a6673dd8f89c3f':
                raise RuntimeError('Base APK does not match the observed asset-scan sample.')
            result = subprocess.run([sys.executable, '.github/scripts/worldbox_unity_script_refs.py', str(base)],
                                    capture_output=True, text=True, timeout=360, check=True)
            report = json.loads(result.stdout)
            if report.get('kind') != 'worldbox-unity-script-references':
                raise RuntimeError('Unexpected Unity script-reference result.')
            print('Unity script-reference aggregate report: ' + json.dumps(report, separators=(',', ':')))
            summary = {k: report[k] for k in ('eligibleFiles', 'filesAnalyzed', 'fileLimitReached', 'bytesRead', 'basenameUnique', 'skipped')}
            print('::warning title=WorldBox script references summary::' + json.dumps(summary, separators=(',', ':')))
            for row in report['files']:
                small = {key: row[key] for key in ('entry', 'bytes', 'objectCount', 'monoBehaviourCount', 'behaviourLimitReached', 'parseErrors', 'candidateCounts', 'samplesTruncated')}
                print('::warning title=WorldBox script references file::' + json.dumps(small, separators=(',', ':')))
                for match in row['samples']:
                    print('::warning title=WorldBox script reference candidate::' + json.dumps({'entry': row['entry'], **match}, separators=(',', ':')))
            sys.exit(0)
        if os.environ.get('WORLDBOX_UNITY_SCRIPTS') == '1':
            if not native or not native.is_file():
                raise RuntimeError('ARM64 libil2cpp.so not found in the bundle.')
            with native.open('rb') as f:
                observed = hashlib.file_digest(f, 'sha256').hexdigest()
            if observed != '1d644b98fec97a35630495c695515861acd2c18209beaae6471a650db65def87':
                raise RuntimeError('ARM64 libil2cpp hash mismatch; refusing analysis.')
            base = Path(td) / 'base.apk'
            if not base.is_file():
                raise RuntimeError('Base APK not found in the bundle.')
            with base.open('rb') as f:
                base_hash = hashlib.file_digest(f, 'sha256').hexdigest()
            if base_hash != 'ab7c6bab7d2233c26a9e18426aa58dd60fa0ae0ad9be6fa0b2a6673dd8f89c3f':
                raise RuntimeError('Base APK does not match the observed asset-scan sample.')
            result = subprocess.run([sys.executable, '.github/scripts/worldbox_unity_scripts.py', str(base)],
                                    capture_output=True, text=True, timeout=360, check=True)
            report = json.loads(result.stdout)
            if report.get('kind') != 'worldbox-premium-monoscripts':
                raise RuntimeError('Unexpected Unity MonoScript result.')
            print('Unity MonoScript identifier report: ' + json.dumps(report, separators=(',', ':')))
            summary = {k: report[k] for k in ('unityVersion', 'fileBytes', 'objectCount', 'candidateCount',
                                                'candidateLimitReached', 'oversizedCandidates', 'parseErrors')}
            summary['matchedCount'] = len(report['matchedIdentifiers'])
            summary['annotationsTruncated'] = len(report['matchedIdentifiers']) > 32
            print('::warning title=WorldBox Premium script summary::' + json.dumps(summary, separators=(',', ':')))
            for row in report['matchedIdentifiers'][:32]:
                print('::warning title=WorldBox Premium script identifier::' + json.dumps(row, separators=(',', ':')))
            sys.exit(0)
        if os.environ.get('WORLDBOX_UNITY_OBJECT_LEADS') == '1':
            if not native or not native.is_file():
                raise RuntimeError('ARM64 libil2cpp.so not found in the bundle.')
            with native.open('rb') as f:
                observed = hashlib.file_digest(f, 'sha256').hexdigest()
            if observed != '1d644b98fec97a35630495c695515861acd2c18209beaae6471a650db65def87':
                raise RuntimeError('ARM64 libil2cpp hash mismatch; refusing analysis.')
            base = Path(td) / 'base.apk'
            if not base.is_file():
                raise RuntimeError('Base APK not found in the bundle.')
            with base.open('rb') as f:
                base_hash = hashlib.file_digest(f, 'sha256').hexdigest()
            if base_hash != 'ab7c6bab7d2233c26a9e18426aa58dd60fa0ae0ad9be6fa0b2a6673dd8f89c3f':
                raise RuntimeError('Base APK does not match the observed asset-scan sample.')
            result = subprocess.run([sys.executable, '.github/scripts/worldbox_unity_object_leads.py', str(base)],
                                    capture_output=True, text=True, timeout=360, check=True)
            report = json.loads(result.stdout)
            if report.get('kind') != 'worldbox-unity-object-leads':
                raise RuntimeError('Unexpected Unity object lead result.')
            print('Unity object aggregate report: ' + json.dumps(report, separators=(',', ':')))
            for entry in report['entries']:
                meta = {k: entry[k] for k in ('entry', 'formatVersion', 'unityVersion', 'fileBytes', 'dataOffset', 'objectCount')}
                print('::warning title=WorldBox Unity object summary::' + json.dumps(meta, separators=(',', ':')))
                for category, value in entry['categories'].items():
                    print('::warning title=WorldBox Unity object category::' + json.dumps({'entry': entry['entry'], 'category': category, **value}, separators=(',', ':')))
            sys.exit(0)
        if os.environ.get('WORLDBOX_ASSET_LEADS') == '1':
            if not native or not native.is_file():
                raise RuntimeError('ARM64 libil2cpp.so not found in the bundle.')
            with native.open('rb') as f:
                observed = hashlib.file_digest(f, 'sha256').hexdigest()
            if observed != '1d644b98fec97a35630495c695515861acd2c18209beaae6471a650db65def87':
                raise RuntimeError('ARM64 libil2cpp hash mismatch; refusing analysis.')
            base = Path(td) / 'base.apk'
            if not base.is_file():
                raise RuntimeError('Base APK not found in the bundle.')
            result = subprocess.run([sys.executable, '.github/scripts/worldbox_asset_leads.py', str(base)],
                                    capture_output=True, text=True, timeout=360, check=True)
            report = json.loads(result.stdout)
            if report.get('kind') != 'worldbox-unity-asset-leads':
                raise RuntimeError('Unexpected asset name-lead result.')
            print('WorldBox Unity asset aggregate report: ' + json.dumps(report, separators=(',', ':')))
            summary = {key: report[key] for key in ('baseApkSha256', 'eligibleEntries', 'entriesScanned',
                       'eligibleBytes', 'scannedBytes', 'entriesLimitReached', 'truncated')}
            hits = [row for row in report['results'] if row['matches']]
            summary['entriesWithMatches'] = len(hits)
            summary['exampleEntriesTruncated'] = len(hits) > 16
            print('::warning title=WorldBox asset-name summary::' + json.dumps(summary, separators=(',', ':')))
            for row in hits[:16]:
                print('::warning title=WorldBox asset-name example::' + json.dumps(row, separators=(',', ':')))
            sys.exit(0)
        if os.environ.get('WORLDBOX_RAW_CONTEXT') == '1':
            if not native or not native.is_file():
                raise RuntimeError('ARM64 libil2cpp.so not found in the bundle.')
            with native.open('rb') as f:
                observed = hashlib.file_digest(f, 'sha256').hexdigest()
            if observed != '1d644b98fec97a35630495c695515861acd2c18209beaae6471a650db65def87':
                raise RuntimeError('ARM64 libil2cpp hash mismatch; refusing analysis.')
            result = subprocess.run([sys.executable, '.github/scripts/worldbox_raw_context.py', str(native)],
                                    capture_output=True, text=True, timeout=360, check=True)
            report = json.loads(result.stdout)
            if report.get('kind') != 'arm64-raw-name-context':
                raise RuntimeError('Unexpected raw-name context result.')
            print('::warning title=WorldBox raw-name context::' + json.dumps(report, separators=(',', ':')))
            sys.exit(0)
        if os.environ.get('WORLDBOX_RAW_LEADS') == '1':
            if not native or not native.is_file() or not unity or not unity.is_file():
                raise RuntimeError('Both ARM64 libil2cpp.so and libunity.so are required.')
            with native.open('rb') as f:
                observed = hashlib.file_digest(f, 'sha256').hexdigest()
            if observed != '1d644b98fec97a35630495c695515861acd2c18209beaae6471a650db65def87':
                raise RuntimeError('ARM64 libil2cpp hash mismatch; refusing analysis.')
            for label, library in [('libil2cpp', native), ('libunity', unity)]:
                completed = subprocess.run([sys.executable, '.github/scripts/worldbox_raw_leads.py', str(library)],
                                           capture_output=True, text=True, timeout=360, check=True)
                report = json.loads(completed.stdout)
                if report.get('kind') != 'arm64-raw-name-leads':
                    raise RuntimeError('Unexpected raw name-lead result.')
                # The independently observed libunity hash is recorded, not asserted
                # to be a previously verified canonical hash.
                print('ARM64 raw-name report for ' + label + ': ' + json.dumps(report, separators=(',', ':')))
                summary = {key: report[key] for key in ('sha256', 'fileBytes', 'scannedBytes', 'truncated')}
                summary['library'] = label
                summary['counts'] = {row['category'] + '/' + row['encoding']: row['count'] for row in report['results']}
                print('::warning title=WorldBox raw-name summary::' + json.dumps(summary, separators=(',', ':')))
                for row in report['results']:
                    if row['count']:
                        print('::warning title=WorldBox raw-name examples::' + json.dumps({'library': label, **row}, separators=(',', ':')))
            sys.exit(0)
        if os.environ.get('WORLDBOX_STRING_LEADS') == '1':
            if not native or not native.is_file():
                raise RuntimeError('ARM64 libil2cpp.so not found in the bundle.')
            with native.open('rb') as f:
                observed = hashlib.file_digest(f, 'sha256').hexdigest()
            if observed != '1d644b98fec97a35630495c695515861acd2c18209beaae6471a650db65def87':
                raise RuntimeError('ARM64 library hash does not match the observed 0.51.4 sample; refusing analysis.')
            libraries = [('libil2cpp.so', native), ('libunity.so', unity)]
            for label, library in libraries:
                if not library or not library.is_file():
                    if label == 'libil2cpp.so':
                        raise RuntimeError('Required ARM64 libil2cpp.so was not extracted.')
                    continue
                with library.open('rb') as f:
                    library_hash = hashlib.file_digest(f, 'sha256').hexdigest()
                result = subprocess.run([sys.executable, '.github/scripts/worldbox_string_leads.py', str(library)],
                                        capture_output=True, text=True, timeout=360, check=True)
                report = json.loads(result.stdout)
                if report.get('kind') != 'arm64-string-leads':
                    raise RuntimeError('Unexpected string-lead result for ' + label)
                summary = {'library': label, 'sha256': library_hash}
                summary.update({key: report[key] for key in ('dataBytesScanned', 'dataBytesTotal', 'execBytesRead', 'execBytesScanned', 'execBytesTotal', 'referenceSweepPerformed')})
                summary['categories'] = {name: {'matches': value['matches'], 'targetLimitReached': value['targetLimitReached'],
                                                'entriesWithRefs': sum(bool(row['startRefs'] or row['keywordRefs']) for row in value['entries'])}
                                         for name, value in report['categories'].items()}
                print('::warning title=WorldBox string-lead summary::' + json.dumps(summary, separators=(',', ':')))
                for category, value in report['categories'].items():
                    for row in value['entries']:
                        if row['startRefs'] or row['keywordRefs']:
                            print('::warning title=WorldBox string-lead reference::' + json.dumps({'library': label, 'category': category, **row}, separators=(',', ':')))
            sys.exit(0)
        if os.environ.get('WORLDBOX_METADATA_PATH_PROBE') == '1':
            if not native or not native.is_file():
                raise RuntimeError('ARM64 libil2cpp.so not found in the bundle.')
            if not unity or not unity.is_file():
                raise RuntimeError('ARM64 libunity.so not found in the bundle.')
            if not base_apk or not base_apk.is_file():
                raise RuntimeError('base.apk not found in the bundle.')
            with native.open('rb') as f:
                native_hash = hashlib.file_digest(f, 'sha256').hexdigest()
            if native_hash != '1d644b98fec97a35630495c695515861acd2c18209beaae6471a650db65def87':
                raise RuntimeError('ARM64 libil2cpp.so hash does not match the observed 0.51.4 sample; refusing analysis.')
            with unity.open('rb') as f:
                unity_hash = hashlib.file_digest(f, 'sha256').hexdigest()
            if unity_hash != '8c04ad3b7d482cab925541cfe9839844c87732f7419aaaa71e170ccff916f082':
                raise RuntimeError('ARM64 libunity.so hash does not match the observed 0.51.4 sample; refusing analysis.')
            from worldbox_metadata_path_probe import build_report
            report = build_report(native, unity, base_apk)
            if report.get('kind') != 'worldbox-metadata-path-probe':
                raise RuntimeError('Unexpected WorldBox metadata path report.')
            print('WorldBox full metadata path report: ' + json.dumps(report, separators=(',', ':')))
            summary = {
                'needles': report['needles'], 'encodings': report['encodings'],
                'files': [{'role': item['role'], 'sha256': item['sha256'], 'bytes': item['bytes'],
                           'counts': {label: {encoding: value['count']
                                              for encoding, value in encodings.items()}
                                      for label, encodings in item['scan']['results'].items()}}
                          for item in report['files']],
                'sectionContextAddresses': [row['address'] for row in report['sectionContexts']],
                'limitations': report['limitations']}
            print('::warning title=WorldBox metadata path summary::' +
                  json.dumps(summary, separators=(',', ':')).replace('%', '%25'))
            for item in report['files']:
                examples = []
                for label, encodings in item['scan']['results'].items():
                    for encoding, value in encodings.items():
                        for example in value['examples']:
                            examples.append({'needle': label, 'encoding': encoding, **example})
                if not examples:
                    print('::notice title=WorldBox metadata path hits ' + item['role'] + '::' +
                          json.dumps({'status': 'no-examples'}, separators=(',', ':')))
                    continue
                parts = [examples[index:index + 12] for index in range(0, len(examples), 12)]
                examples_truncated = any(value['examplesTruncated']
                                         for encodings in item['scan']['results'].values()
                                         for value in encodings.values())
                for number, part in enumerate(parts, 1):
                    payload = {'role': item['role'], 'chunk': [number, len(parts)],
                               'examples': part, 'truncated': examples_truncated}
                    print('::warning title=WorldBox metadata path hits ' + item['role'] +
                          ' ' + str(number) + '/' + str(len(parts)) + '::' +
                          json.dumps(payload, separators=(',', ':')).replace('%', '%25'))
            for row in report['sectionContexts']:
                print('::notice title=WorldBox metadata path section context ' + row['address'] + '::' +
                      json.dumps(row, separators=(',', ':')).replace('%', '%25'))
            characterization = report['sectionCharacterization']
            inventory = {'sectionName': characterization['sectionName'],
                         'sectionCount': characterization['sectionCount'],
                         'sections': characterization['sections'],
                         'limitations': characterization['limitations']}
            print('::warning title=WorldBox metadata path section inventory::' +
                  json.dumps(inventory, separators=(',', ':')).replace('%', '%25'))
            reference_keys = ('dataPointers', 'relocationAddends', 'adrpAddReferences',
                              'directCalls', 'tailBranches')
            reference_summary = {key: {'count': characterization[key]['count'],
                                       'samplesTruncated': characterization[key]['samplesTruncated']}
                                 for key in reference_keys}
            reference_summary.update({key: characterization[key]
                                      for key in ('unwindStatus', 'unwindRanges', 'executableBytes',
                                                  'executableScanned', 'execTruncated',
                                                  'allocatedDataBytes', 'allocatedDataScanned',
                                                  'dataTruncated', 'unsupportedRelocationSections')})
            print('::warning title=WorldBox metadata path section reference summary::' +
                  json.dumps(reference_summary, separators=(',', ':')).replace('%', '%25'))
            for key in reference_keys:
                payload = {'category': key, **{field: characterization[key][field]
                                              for field in ('count', 'samples', 'samplesTruncated')}}
                print('::warning title=WorldBox metadata path section references ' + key + '::' +
                      json.dumps(payload, separators=(',', ':')).replace('%', '%25'))
            sys.exit(0)
        if os.environ.get('WORLDBOX_INDIRECT_SLOT_PROBE') == '1':
            if not native or not native.is_file():
                raise RuntimeError('ARM64 libil2cpp.so not found in the bundle.')
            with native.open('rb') as f:
                observed = hashlib.file_digest(f, 'sha256').hexdigest()
            expected = '1d644b98fec97a35630495c695515861acd2c18209beaae6471a650db65def87'
            if observed != expected:
                raise RuntimeError('ARM64 library hash does not match the observed 0.51.4 sample; refusing analysis.')
            from worldbox_indirect_slot_probe import emit_indirect_slot_annotations, indirect_slot_report
            emit_indirect_slot_annotations(indirect_slot_report(native))
            sys.exit(0)
        if os.environ.get('WORLDBOX_FILE_HELPER_CALLEE_PROBE') == '1':
            if not native or not native.is_file():
                raise RuntimeError('ARM64 libil2cpp.so not found in the bundle.')
            with native.open('rb') as f:
                observed = hashlib.file_digest(f, 'sha256').hexdigest()
            expected = '1d644b98fec97a35630495c695515861acd2c18209beaae6471a650db65def87'
            if observed != expected:
                raise RuntimeError('ARM64 library hash does not match the observed 0.51.4 sample; refusing analysis.')
            from worldbox_adjacent_thunks import (FILE_HELPER_KIND, FILE_HELPER_TARGETS,
                                                  reference_report)
            from worldbox_static_literal_probe import emit_literal_annotations, literal_report
            report = reference_report(native, thunks=FILE_HELPER_TARGETS,
                                      kind=FILE_HELPER_KIND)
            emit_reference_annotations(report, 'file helper callee',
                                       'file helper callee', FILE_HELPER_KIND)
            emit_literal_annotations(literal_report(native))
            sys.exit(0)
        if os.environ.get('WORLDBOX_FILE_ADAPTER_CALLEE_PROBE') == '1':
            if not native or not native.is_file():
                raise RuntimeError('ARM64 libil2cpp.so not found in the bundle.')
            with native.open('rb') as f:
                observed = hashlib.file_digest(f, 'sha256').hexdigest()
            expected = '1d644b98fec97a35630495c695515861acd2c18209beaae6471a650db65def87'
            if observed != expected:
                raise RuntimeError('ARM64 library hash does not match the observed 0.51.4 sample; refusing analysis.')
            from worldbox_adjacent_thunks import (FILE_ADAPTER_KIND, FILE_ADAPTER_TARGETS,
                                                  reference_report)
            report = reference_report(native, thunks=FILE_ADAPTER_TARGETS,
                                      kind=FILE_ADAPTER_KIND)
            emit_reference_annotations(report, 'file adapter callee',
                                       'file adapter callee', FILE_ADAPTER_KIND)
            sys.exit(0)
        if os.environ.get('WORLDBOX_BRANCH_DESTINATION_PROBE') == '1':
            if not native or not native.is_file():
                raise RuntimeError('ARM64 libil2cpp.so not found in the bundle.')
            with native.open('rb') as f:
                observed = hashlib.file_digest(f, 'sha256').hexdigest()
            expected = '1d644b98fec97a35630495c695515861acd2c18209beaae6471a650db65def87'
            if observed != expected:
                raise RuntimeError('ARM64 library hash does not match the observed 0.51.4 sample; refusing analysis.')
            from worldbox_adjacent_thunks import BRANCH_DESTINATIONS, reference_report
            report = reference_report(native, thunks=BRANCH_DESTINATIONS,
                                      kind='worldbox-branch-destination-probe')
            emit_reference_annotations(report, 'branch destination',
                                       'branch destination',
                                       'worldbox-branch-destination-probe')
            sys.exit(0)
        if os.environ.get('WORLDBOX_ADJACENT_THUNK_PROBE') == '1':
            if not native or not native.is_file():
                raise RuntimeError('ARM64 libil2cpp.so not found in the bundle.')
            with native.open('rb') as f:
                observed = hashlib.file_digest(f, 'sha256').hexdigest()
            expected = '1d644b98fec97a35630495c695515861acd2c18209beaae6471a650db65def87'
            if observed != expected:
                raise RuntimeError('ARM64 library hash does not match the observed 0.51.4 sample; refusing analysis.')
            from worldbox_adjacent_thunks import reference_report
            report = reference_report(native)
            if report.get('kind') != 'worldbox-adjacent-thunk-probe':
                raise RuntimeError('Unexpected WorldBox adjacent-thunk report.')
            print('WorldBox full adjacent-thunk report: ' + json.dumps(report, separators=(',', ':')))
            summary = {key: report[key] for key in
                       ('targets', 'unwindStatus', 'unwindRanges', 'limitations')}
            summary['rows'] = [{'target': row['target'], 'fdeStart': row['fdeStart'],
                                'fdeSize': row['fdeSize'],
                                'consumerCounts': {
                                    'directTailBranches': row['xrefs']['directTailBranches'],
                                    'pcRelativeAddressPairs': row['xrefs']['pcRelativeAddressPairs'],
                                    'matchingRelocations': row['xrefs']['matchingRelocations'],
                                    'alignedPointerValues': row['xrefs']['alignedPointerValues'],
                                    'tailSamples': len(row['tailSamples']),
                                    'pcRelativeSamples': len(row['pcRelativeSamples'])},
                                'fdeReportCount': len(row['fdeReports']),
                                'fdeReportsTruncated': row['fdeReportsTruncated']}
                               for row in report['rows']]
            print('::warning title=WorldBox adjacent thunk summary::' +
                  json.dumps(summary, separators=(',', ':')).replace('%', '%25'))
            for row in report['rows']:
                print('::warning title=WorldBox adjacent thunk xrefs ' + row['target'] + '::' +
                      json.dumps(row['xrefs'], separators=(',', ':')).replace('%', '%25'))
                consumers = {'target': row['target'], 'fdeStart': row['fdeStart'],
                             'fdeSize': row['fdeSize'], 'tailSamples': row['tailSamples'],
                             'pcRelativeSamples': row['pcRelativeSamples'],
                             'relocationSamples': row['relocationSamples'],
                             'pointerSamples': row['pointerSamples'],
                             'fdeReportEntries': [item.get('entry') for item in row['fdeReports']],
                             'fdeReportsTruncated': row['fdeReportsTruncated']}
                print('::warning title=WorldBox adjacent thunk consumers ' + row['target'] + '::' +
                      json.dumps(consumers, separators=(',', ':')).replace('%', '%25'))
                for fde in row['fdeReports']:
                    if fde.get('status') == 'unavailable':
                        print('::notice title=WorldBox adjacent thunk FDE unavailable ' + fde['entry'] + '::' +
                              json.dumps(fde, separators=(',', ':')).replace('%', '%25'))
                        continue
                    lines = [f"{item['address']} {item['mnemonic']} {item['operands']}".strip().replace('%', '%25')
                             for item in fde['instructions']]
                    selected = lines[:100]
                    parts = [selected[start:start + 50] for start in range(0, len(selected), 50)]
                    for number, part in enumerate(parts, 1):
                        payload = {'entry': fde['entry'], 'size': fde['size'],
                                   'decodedInstructions': fde['decodedInstructions'],
                                   'fullyDecoded': fde['fullyDecoded'],
                                   'chunk': [number, len(parts)],
                                   'instructionsTruncated': len(lines) > len(selected),
                                   'instructions': '|'.join(part)}
                        print('::notice title=WorldBox adjacent thunk FDE instructions ' + fde['entry'] +
                              ' ' + str(number) + '/' + str(len(parts)) + '::' +
                              json.dumps(payload, separators=(',', ':')).replace('%', '%25'))
            sys.exit(0)
        if os.environ.get('WORLDBOX_METADATA_SLOT_PROBE') == '1':
            if not native or not native.is_file():
                raise RuntimeError('ARM64 libil2cpp.so not found in the bundle.')
            with native.open('rb') as f:
                observed = hashlib.file_digest(f, 'sha256').hexdigest()
            expected = '1d644b98fec97a35630495c695515861acd2c18209beaae6471a650db65def87'
            if observed != expected:
                raise RuntimeError('ARM64 library hash does not match the observed 0.51.4 sample; refusing analysis.')
            from worldbox_metadata_slot_probe import slot_reference_report
            report = slot_reference_report(native)
            if report.get('kind') != 'worldbox-metadata-slot-probe':
                raise RuntimeError('Unexpected WorldBox metadata slot report.')
            print('WorldBox full metadata slot report: ' + json.dumps(report, separators=(',', ':')))
            summary = {key: report[key] for key in
                       ('slots', 'unwindStatus', 'unwindRanges', 'slotLoadScan', 'limitations')}
            summary['rows'] = [{'slot': row['slot'],
                                'consumerCounts': {'adrpAddSamples': len(row['adrpAddSamples']),
                                                   'adrpLdrSamples': len(row['adrpLdrSamples']),
                                                   'pcRelativeAddressPairs': row['xrefs']['pcRelativeAddressPairs'],
                                                   'directTailBranches': row['xrefs']['directTailBranches'],
                                                   'matchingRelocations': row['xrefs']['matchingRelocations'],
                                                   'alignedPointerValues': row['xrefs']['alignedPointerValues']},
                                'fdeReportCount': len(row['fdeReports']),
                                'fdeReportsTruncated': row['fdeReportsTruncated']}
                               for row in report['rows']]
            print('::warning title=WorldBox metadata slot summary::' +
                  json.dumps(summary, separators=(',', ':')).replace('%', '%25'))
            for row in report['rows']:
                print('::warning title=WorldBox metadata slot xrefs ' + row['slot'] + '::' +
                      json.dumps(row['xrefs'], separators=(',', ':')).replace('%', '%25'))
                consumers = {'slot': row['slot'], 'adrpAddSamples': row['adrpAddSamples'],
                             'adrpLdrSamples': row['adrpLdrSamples'],
                             'fdeReportEntries': [item.get('entry') for item in row['fdeReports']],
                             'fdeReportsTruncated': row['fdeReportsTruncated']}
                print('::warning title=WorldBox metadata slot consumers ' + row['slot'] + '::' +
                      json.dumps(consumers, separators=(',', ':')).replace('%', '%25'))
                for fde in row['fdeReports']:
                    if fde.get('status') == 'unavailable':
                        print('::notice title=WorldBox metadata slot FDE unavailable ' + fde['entry'] + '::' +
                              json.dumps(fde, separators=(',', ':')).replace('%', '%25'))
                        continue
                    lines = [f"{item['address']} {item['mnemonic']} {item['operands']}".strip().replace('%', '%25')
                             for item in fde['instructions']]
                    selected = lines[:100]
                    parts = [selected[start:start + 50] for start in range(0, len(selected), 50)]
                    for number, part in enumerate(parts, 1):
                        payload = {'entry': fde['entry'], 'size': fde['size'],
                                   'decodedInstructions': fde['decodedInstructions'],
                                   'fullyDecoded': fde['fullyDecoded'],
                                   'chunk': [number, len(parts)],
                                   'instructionsTruncated': len(lines) > len(selected),
                                   'instructions': '|'.join(part)}
                        print('::notice title=WorldBox metadata slot FDE instructions ' + fde['entry'] +
                              ' ' + str(number) + '/' + str(len(parts)) + '::' +
                              json.dumps(payload, separators=(',', ':')).replace('%', '%25'))
            sys.exit(0)
        if os.environ.get('WORLDBOX_NATIVE_PROBE') == '1':
            if not native or not native.is_file():
                raise RuntimeError('ARM64 libil2cpp.so not found in the bundle.')
            with native.open('rb') as f:
                observed = hashlib.file_digest(f, 'sha256').hexdigest()
            expected = '1d644b98fec97a35630495c695515861acd2c18209beaae6471a650db65def87'
            if observed != expected:
                raise RuntimeError('ARM64 library hash does not match the observed 0.51.4 sample; refusing analysis.')
            output = subprocess.run([sys.executable, '.github/scripts/worldbox_native_scan.py', str(native)],
                                    capture_output=True, text=True, timeout=360, check=True)
            data = json.loads(output.stdout)
            if data.get('kind') != 'arm64-static-triage':
                raise RuntimeError('Unexpected ARM64 static analysis result.')
            print('ARM64 full aggregate triage: ' + json.dumps(data, separators=(',', ':')))
            triage_summary = dict(data)
            triage_summary['directPltCalls'] = {name: {'count': info['count']} for name, info in data['directPltCalls'].items()}
            print('::warning title=WorldBox ARM64 static triage::' + json.dumps(triage_summary, separators=(',', ':')))
            flow_output = subprocess.run([sys.executable, '.github/scripts/worldbox_native_flow.py', str(native)],
                                         capture_output=True, text=True, timeout=360, check=True)
            flow = json.loads(flow_output.stdout)
            if flow.get('kind') != 'arm64-static-flow':
                raise RuntimeError('Unexpected ARM64 file-flow analysis result.')
            print('ARM64 full aggregate file flow: ' + json.dumps(flow, separators=(',', ':')))
            flow_summary = dict(flow)
            callers = flow.get('directWrapperCallers', {})
            flow_summary['directWrapperCallers'] = {'counts': callers.get('counts', {}),
                                                    'executableScanTruncated': callers.get('executableScanTruncated')}
            direct_targets = flow.get('directTargetCallers', {})
            flow_summary['directTargetCallers'] = {'counts': direct_targets.get('counts', {}),
                                                   'executableScanTruncated': direct_targets.get('executableScanTruncated')}
            print('::warning title=WorldBox ARM64 file flow::' + json.dumps(flow_summary, separators=(',', ':')))
            for detail in direct_targets.get('examples', []):
                print('::warning title=WorldBox ARM64 internal-target caller::' + json.dumps(detail, separators=(',', ':')))
            xref_output = subprocess.run([sys.executable, '.github/scripts/worldbox_native_xrefs.py', str(native)],
                                         capture_output=True, text=True, timeout=360)
            if xref_output.returncode:
                raise RuntimeError('ARM64 cross-reference tool failed: ' + xref_output.stderr[-800:])
            xref = json.loads(xref_output.stdout)
            if xref.get('kind') != 'arm64-static-xrefs':
                raise RuntimeError('Unexpected ARM64 cross-reference result.')
            # GitHub truncates each annotation at 4096 characters. Keep the full
            # aggregate-only report in the job log and emit bounded annotations.
            from worldbox_native_xrefs import annotation_payloads, inspect as inspect_xrefs
            print('ARM64 full aggregate xrefs: ' + json.dumps(xref, separators=(',', ':')))
            summary, details = annotation_payloads(xref)
            print('::warning title=WorldBox ARM64 indirect references::' + json.dumps(summary, separators=(',', ':')))
            for detail in details:
                print('::warning title=WorldBox ARM64 source input::' + json.dumps(detail, separators=(',', ':')))
            adapter_xrefs = inspect_xrefs(native, target=0x18904e0)
            if adapter_xrefs.get('kind') != 'arm64-static-xrefs':
                raise RuntimeError('Unexpected wide-string file adapter xref result.')
            tail = adapter_xrefs['directTailBranches']
            adapter_summary = {
                'target': adapter_xrefs['target'], 'symbolMatches': adapter_xrefs['symbolMatches'],
                'directTailBranches': {'count': tail['count'], 'sampleSites': tail['sampleSites'][:12]},
                'pcRelativeAddressPairs': {'count': adapter_xrefs['pcRelativeAddressPairs']['count'],
                                           'samples': adapter_xrefs['pcRelativeAddressPairs']['samples'][:12]},
                'matchingRelocations': {'count': adapter_xrefs['matchingRelocations']['count'],
                                        'samples': adapter_xrefs['matchingRelocations']['samples'][:12],
                                        'unsupportedSections': adapter_xrefs['matchingRelocations']['unsupportedRelocationSections'][:8]},
                'alignedPointerValues': {'count': adapter_xrefs['alignedPointerValues']['count'],
                                         'samples': adapter_xrefs['alignedPointerValues']['samples'][:12]},
                'execTruncated': adapter_xrefs['execTruncated'], 'dataTruncated': adapter_xrefs['dataTruncated'],
                'tailTracesReported': len(tail['traces']),
                'directCallsFromFlow': direct_targets.get('counts', {}).get('0x18904e0'),
                'directCallerSites': [detail.get('site') for detail in direct_targets.get('examples', [])
                                      if detail.get('target') == '0x18904e0'][:8],
            }
            print('::warning title=WorldBox wide-string file adapter xrefs::' +
                  json.dumps(adapter_summary, separators=(',', ':')).replace('%', '%25'))
            for trace in tail['traces'][:4]:
                compact_trace = {key: trace.get(key) for key in ('site', 'function', 'size', 'workLimitReached', 'status')}
                compact_trace['call'] = trace.get('call')
                print('::warning title=WorldBox wide-string file adapter tail caller::' +
                      json.dumps(compact_trace, separators=(',', ':')).replace('%', '%25'))
            sys.exit(0)
        if os.environ.get('WORLDBOX_REA_PROBE') == '1':
            rea = os.environ['WORLDBOX_REA_ENTRY']
            base = Path(td) / 'base.apk'
            def invoke_rea(*args):
                result = subprocess.run(['node', rea, *map(str, args), '--json'], capture_output=True, text=True, timeout=360)
                if result.returncode:
                    message = (result.stderr or result.stdout)[-1200:]
                    message = message.replace('%', '%25').replace('\r', '%0D').replace('\n', '%0A')
                    print('::warning title=REA analysis::' + message)
                    return None
                try:
                    return json.loads(result.stdout)
                except json.JSONDecodeError:
                    raise RuntimeError('REA returned non-JSON output')
            def strings(value):
                if isinstance(value, str):
                    yield value
                elif isinstance(value, list):
                    for item in value:
                        yield from strings(item)
                elif isinstance(value, dict):
                    for item in value.values():
                        yield from strings(item)
            success = 0
            for term in ('Purchasing',):
                data = invoke_rea('search-android-classes', base, term)
                if data is None:
                    continue
                success += 1
                found = sorted({value for value in strings(data) if term.lower() in value.lower() and len(value) < 250})
                print('::notice title=REA Android class search::' + term + ': ' + ('; '.join(found[:15]) or 'no matching class names reported'))
            if not success:
                raise RuntimeError('All REA Android class searches failed.')
            detail = invoke_rea('inspect-android-method', base, 'com.unity.purchasing.common.UnityPurchasing', 'SerialiseProducts')
            if detail:
                def texts(value, depth=0):
                    if depth > 12:
                        return
                    if isinstance(value, str):
                        yield value
                        if len(value) < 2_000_000 and value.lstrip().startswith(('{', '[')):
                            try:
                                yield from texts(json.loads(value), depth + 1)
                            except (json.JSONDecodeError, RecursionError):
                                pass
                    elif isinstance(value, dict):
                        for part in value.values():
                            yield from texts(part, depth + 1)
                    elif isinstance(value, list):
                        for part in value:
                            yield from texts(part, depth + 1)
                snippets = set()
                for value in texts(detail):
                    if 'SerialiseProducts' in value and ('\n' in value or 'UnitySendMessage' in value) and len(value) < 5000:
                        clean = value.strip().replace('%', '%25').replace('\r', '%0D').replace('\n', '%0A')
                        snippets.add(clean[:1000])
                for snippet in sorted(snippets)[:3]:
                    print('::notice title=REA SerialiseProducts::' + snippet)
            for class_name in ('com.unity.purchasing.common.UnityPurchasing', 'com.unity.purchasing.common.ProductDescription'):
                data = invoke_rea('inspect-android-class', base, class_name)
                if data is None:
                    continue
                def objects(value, depth=0):
                    if depth > 12:
                        return
                    if isinstance(value, dict):
                        yield value
                        for item in value.values():
                            yield from objects(item, depth + 1)
                    elif isinstance(value, list):
                        for item in value:
                            yield from objects(item, depth + 1)
                    elif isinstance(value, str) and len(value) < 2_000_000 and value.lstrip().startswith(('{', '[')):
                        try:
                            yield from objects(json.loads(value), depth + 1)
                        except (json.JSONDecodeError, RecursionError):
                            pass
                seen = set()
                for obj in objects(data):
                    if obj.get('full_name') == class_name and class_name.endswith('ProductDescription') and isinstance(obj.get('fields'), list):
                        for field in obj['fields']:
                            if isinstance(field, dict):
                                print('::notice title=REA product field::' + json.dumps(field, ensure_ascii=True, separators=(',', ':'))[:900].replace('%', '%25'))
                    if obj.get('full_name') == class_name and isinstance(obj.get('methods'), list):
                        for method in obj['methods']:
                            if not isinstance(method, dict):
                                continue
                            name = str(method.get('name', ''))
                            if name and (class_name.endswith('UnityPurchasing') or re.search(r'purchase|billing|product', name, re.I)):
                                summary = json.dumps(method, ensure_ascii=True, separators=(',', ':'))[:900]
                                if summary not in seen:
                                    seen.add(summary)
                                    print('::notice title=REA method inventory::' + class_name + ': ' + summary.replace('%', '%25'))
                snippets = []
                for value in strings(data):
                    if len(value) > 1000 and ('class ' in value or 'UnitySendMessage' in value):
                        lines = value.splitlines()
                        for i, line in enumerate(lines):
                            if re.search(r'purchase|billing|product|UnitySendMessage|native', line, re.I):
                                snippets.append(' | '.join(x.strip() for x in lines[max(0, i-1):i+2])[:500])
                for snippet in list(dict.fromkeys(snippets))[:30]:
                    print('::notice title=REA purchasing bridge::' + class_name + ': ' + snippet.replace('%', '%25').replace('\r', '%0D').replace('\n', '%0A'))
                print('::notice title=REA class analysis::' + class_name + ': inspected; matching source snippets ' + str(len(snippets)))
            sys.exit(0)
        if os.environ.get('WORLDBOX_RUNTIME_PROBE') == '1':
            import time
            def adb(*args, check=True, timeout=180):
                result = subprocess.run(['adb', *args], capture_output=True, text=True, timeout=timeout)
                if check and result.returncode:
                    raise RuntimeError('ADB operation failed: ' + (result.stderr or result.stdout)[-1000:])
                return result.stdout.strip()
            abi = adb('shell', 'getprop', 'ro.product.cpu.abilist')
            bridge = adb('shell', 'getprop', 'ro.dalvik.vm.native.bridge')
            print('::notice title=WorldBox emulator::Supported ABIs: ' + abi + '; native bridge: ' + bridge)
            if 'arm64-v8a' not in abi:
                raise RuntimeError('This emulator does not advertise arm64-v8a; the WorldBox bundle has no x86 split.')
            metadata_scan = os.environ.get('WORLDBOX_METADATA_SCAN') == '1'
            memory_metadata_extractor = os.environ.get('WORLDBOX_MEMORY_METADATA_EXTRACTOR') == '1'
            proc_only_scan = os.environ.get('WORLDBOX_PROC_ONLY_SCAN') == '1'
            if metadata_scan or memory_metadata_extractor or proc_only_scan:
                adb('root')
                adb('wait-for-device')
                if adb('shell', 'id', '-u') != '0':
                    raise RuntimeError('Emulator adbd is not running as root.')
            if metadata_scan or memory_metadata_extractor:
                server = os.environ.get('WORLDBOX_FRIDA_SERVER')
                if not server or not Path(server).is_file():
                    raise RuntimeError('Missing Frida server binary for emulator runtime scan.')
                adb('push', server, '/data/local/tmp/worldbox-frida-server')
                adb('shell', 'chmod', '755', '/data/local/tmp/worldbox-frida-server')
                adb('shell', 'nohup /data/local/tmp/worldbox-frida-server </dev/null >/data/local/tmp/worldbox-frida.log 2>&1 &')
                time.sleep(8)
                if memory_metadata_extractor:
                    smoke_pid = adb('shell', 'sleep 180 >/dev/null 2>&1 & echo $!', check=False).strip()
                    if smoke_pid.isdigit():
                        try:
                            smoke = subprocess.run([sys.executable, '.github/scripts/worldbox_runtime_scan.py',
                                                    smoke_pid, '--smoke'], capture_output=True, text=True, timeout=90)
                            arch = None
                            prefix = '::notice title=Frida smoke test::'
                            for line in smoke.stdout.splitlines():
                                if line.startswith(prefix):
                                    try:
                                        arch = json.loads(line[len(prefix):]).get('arch')
                                    except json.JSONDecodeError:
                                        pass
                            if smoke.returncode == 0 and arch:
                                print('::notice title=Frida smoke test::' +
                                      json.dumps({'attached': True, 'processArch': arch}, separators=(',', ':')))
                            else:
                                print('::warning title=Frida smoke test::' +
                                      json.dumps({'attached': False, 'exitCode': smoke.returncode}, separators=(',', ':')))
                        except subprocess.TimeoutExpired:
                            print('::warning title=Frida smoke test::{"attached":false,"timedOut":true}')
                        finally:
                            adb('shell', 'kill', smoke_pid, check=False)
                    else:
                        print('::warning title=Frida smoke test::Could not start disposable comparison process.')
            base = Path(td) / 'base.apk'
            arm64 = Path(td) / 'split_config.arm64_v8a.apk'
            if not base.is_file() or not arm64.is_file():
                raise RuntimeError('Expected base and ARM64 split APKs are missing.')
            print('::notice title=WorldBox emulator::Installing original WorldBox bundle')
            adb('install-multiple', '-r', str(base), str(arm64))
            adb('shell', 'monkey', '-p', 'com.mkarpenko.worldbox', '-c', 'android.intent.category.LAUNCHER', '1')
            time.sleep(60)
            pid = adb('shell', 'pidof', 'com.mkarpenko.worldbox', check=False)
            if not pid:
                failure = adb('logcat', '-d', '-s', 'AndroidRuntime:E', 'linker:E', 'Unity:E', check=False)[-2000:]
                raise RuntimeError('Game process did not remain running: ' + failure)
            print('::notice title=WorldBox emulator::Game process remained running after 60 seconds (PID ' + pid + ')')
            if metadata_scan:
                game_pid = pid.split()[0]
                def restart_game(reason):
                    print('::notice title=WorldBox emulator::Restarting game before ' + reason, flush=True)
                    adb('shell', 'am', 'force-stop', 'com.mkarpenko.worldbox', check=False)
                    adb('shell', 'monkey', '-p', 'com.mkarpenko.worldbox', '-c', 'android.intent.category.LAUNCHER', '1')
                    time.sleep(60)
                    refreshed = adb('shell', 'pidof', 'com.mkarpenko.worldbox', check=False)
                    if not refreshed:
                        raise RuntimeError('Game did not remain running after restart for ' + reason)
                    return refreshed.split()[0]
                enforcement = adb('shell', 'getenforce', check=False)
                print('::notice title=Emulator security::SELinux before probe: ' + enforcement)
                smoke_pid = adb('shell', 'sleep 180 >/dev/null 2>&1 & echo $!', check=False).strip()
                if smoke_pid.isdigit():
                    subprocess.run([sys.executable, '.github/scripts/worldbox_runtime_scan.py', smoke_pid, '--smoke'], timeout=90)
                    adb('shell', 'kill', smoke_pid, check=False)
                else:
                    print('::warning title=Frida smoke test::Could not start a disposable comparison process.')
                probe = subprocess.run([sys.executable, '.github/scripts/worldbox_runtime_scan.py', game_pid], timeout=240)
                if probe.returncode and enforcement.lower() == 'enforcing':
                    # Only on the disposable CI emulator; never changes a user's device.
                    adb('shell', 'setenforce', '0', check=False)
                    after = adb('shell', 'getenforce', check=False)
                    print('::warning title=Emulator security::SELinux after temporary CI-only change: ' + after)
                    if after.lower() == 'permissive':
                        game_pid = restart_game('permissive Frida retry')
                        probe = subprocess.run([sys.executable, '.github/scripts/worldbox_runtime_scan.py', game_pid], timeout=240)
                if probe.returncode:
                    # A failed Frida attach may have killed or altered the old target.
                    game_pid = restart_game('read-only /proc fallback')
                    helper = os.environ.get('WORLDBOX_PROC_SCANNER')
                    if not helper or not Path(helper).is_file():
                        raise RuntimeError('Frida failed and the /proc fallback binary is missing.')
                    # Attach only to the freshly installed game in the disposable emulator.
                    adb('push', helper, '/data/local/tmp/worldbox-proc-scan')
                    adb('shell', 'chmod', '755', '/data/local/tmp/worldbox-proc-scan')
                    result = json.loads(adb('shell', '/data/local/tmp/worldbox-proc-scan', game_pid, '--resident-and-swapped', timeout=360))
                    if result.get('kind') != 'result':
                        raise RuntimeError('Unexpected /proc scanner response.')
                    print('::warning title=WorldBox proc metadata scan::' + json.dumps(result, separators=(',', ':')))
                    if result['candidates'] == 0:
                        print('::warning title=WorldBox metadata::No plausible header found; the scan may be incomplete.')
            if proc_only_scan:
                helper = os.environ.get('WORLDBOX_PROC_SCANNER')
                if not helper or not Path(helper).is_file():
                    raise RuntimeError('The /proc scanner binary is missing for proc-only scan.')
                game_pid = pid.split()[0]
                adb('push', helper, '/data/local/tmp/worldbox-proc-scan')
                adb('shell', 'chmod', '755', '/data/local/tmp/worldbox-proc-scan')
                scan_command = ['shell', '/data/local/tmp/worldbox-proc-scan', game_pid]
                if os.environ.get('WORLDBOX_PROC_ONLY_ALL') != '1':
                    scan_command.append('--resident-and-swapped')
                result = json.loads(adb(*scan_command, timeout=360))
                if result.get('kind') != 'result':
                    raise RuntimeError('Unexpected /proc scanner response.')
                print('::warning title=WorldBox proc-only memory scan::' +
                      json.dumps(result, separators=(',', ':')).replace('%', '%25'))
            if memory_metadata_extractor:
                if not native or not metadata or not base_apk:
                    raise RuntimeError('Hash-gated base APK, ARM64 library, and metadata are required for the memory-extractor probe.')
                output_root = Path(td) / 'memory-metadata-extractor-out'
                command = [sys.executable, '.github/scripts/worldbox_memory_metadata_extractor_probe.py',
                           '--archive', os.environ.get('WORLDBOX_EXTRACTOR_ARCHIVE', ''),
                           '--source-dir', os.environ.get('WORLDBOX_EXTRACTOR_SOURCE_DIR', ''),
                           '--base-apk', str(base_apk), '--native', str(native), '--metadata', str(metadata),
                           '--output-dir', str(output_root), '--timeout', '180']
                if os.environ.get('WORLDBOX_MEMORY_METADATA_ATTACH_RUNNING') == '1':
                    command.append('--attach-running')
                result = subprocess.run(command, capture_output=True, text=True, timeout=240)
                if result.returncode:
                    raise RuntimeError('Memory metadata extractor wrapper failed: ' + (result.stderr or result.stdout)[-1200:])
                report = json.loads(result.stdout)
                if report.get('kind') != 'worldbox-memory-metadata-extractor-probe':
                    raise RuntimeError('Unexpected memory metadata extractor report.')
                print('::warning title=WorldBox Frida metadata extractor::' +
                      json.dumps(report, separators=(',', ':')).replace('%', '%25'))
            sys.exit(0)
        if not native or not metadata:
            raise RuntimeError('Missing ARM64 native library or Unity metadata.')
        print('::notice title=WorldBox SHA-256::ARM64 library ' + hashlib.file_digest(native.open('rb'), 'sha256').hexdigest())
        header = metadata.read_bytes()
        raw_string_leads = count_string_leads(header)
        print('::notice title=WorldBox raw metadata string leads::' + json.dumps(raw_string_leads, separators=(',', ':')))
        button_method_labels = ('button_premium', 'power_button', 'button_util',
                                'localized_text_price', 'click_premium', 'click_close', 'click_hide')
        button_method_offsets = {
            label: occurrence_offsets(header, METADATA_NEEDLES[label]) for label in button_method_labels
        }
        print('::notice title=WorldBox Premium button metadata offsets::' +
              json.dumps(button_method_offsets, separators=(',', ':')))
        button_method_contexts = {
            label: printable_run_contexts(header, METADATA_NEEDLES[label])
            for label in ('click_premium', 'click_close', 'click_hide')
        }
        print('::notice title=WorldBox Premium button method contexts::' +
              json.dumps(button_method_contexts, separators=(',', ':')))
        premium_offsets = {
            label: occurrence_offsets(header, METADATA_NEEDLES[label])
            for label in ('premium_elements_checker', 'premium_window', 'premium_unlock_animation')
        }
        print('::notice title=WorldBox raw metadata marker offsets::' + json.dumps(premium_offsets, separators=(',', ':')))
        premium_labels = ('premium_elements_checker', 'premium_window', 'premium_unlock_animation')
        candidate_bases = candidate_string_heap_bases(
            header, tuple(METADATA_NEEDLES[label] for label in premium_labels))
        print('::notice title=WorldBox metadata exploratory base heuristic::' + json.dumps(candidate_bases, separators=(',', ':')))
        premium_contexts = {
            label: printable_run_contexts(header, METADATA_NEEDLES[label])
            for label in ('premium_elements_checker', 'premium_window', 'premium_unlock_animation')
        }
        print('::notice title=WorldBox metadata printable contexts::' + json.dumps(premium_contexts, separators=(',', ':')))
        premium_nearby = {
            label: nearby_null_identifiers(header, METADATA_NEEDLES[label])
            for label in ('premium_elements_checker', 'premium_window', 'premium_unlock_animation')
        }
        print('::notice title=WorldBox metadata nearby identifiers::' + json.dumps(premium_nearby, separators=(',', ':')))
        magic = b'\xaf\x1b\xb1\xfa'
        print('::notice title=WorldBox metadata::Header ' + header[:32].hex() + ' magic offset ' + str(header.find(magic)))
        sample = header[:min(len(header), 1024 * 1024)]
        counts = collections.Counter(sample)
        entropy = -sum((n / len(sample)) * math.log2(n / len(sample)) for n in counts.values())
        key = bytes(a ^ b for a, b in zip(header[:4], magic))
        decoded_version = int.from_bytes(bytes(header[4+i] ^ key[i] for i in range(4)), 'little')
        print(f'::notice title=WorldBox metadata::First MiB entropy {entropy:.4f}; four-byte XOR candidate version {decoded_version}')
        for lib in [native, unity]:
            if not lib:
                continue
            data = lib.read_bytes()
            needles = [b'global-metadata.dat', b'il2cpp_init', b'AES_decrypt', b'AES_cbc_encrypt',
                       b'EVP_DecryptInit', b'metadata.dat', b'clickPremium', b'clickClose',
                       b'clickHide', b'ResetState', b'ButtonPremium', b'PremiumWindow',
                       b'PremiumUnlockAnimation']
            found = ', '.join(f'{needle.decode()}={data.find(needle)}' for needle in needles)
            print(f'::notice title=WorldBox native markers::{lib.name}: {found}')
            native_leads = count_string_leads(data)
            selected_labels = ('button_premium', 'power_button', 'button_util',
                               'localized_text_price', 'click_premium', 'click_close',
                               'click_hide')
            selected = {label: {**native_leads[label],
                                'asciiOffsets': occurrence_offsets(data, METADATA_NEEDLES[label], limit=4)}
                        for label in selected_labels}
            print('::warning title=WorldBox Premium button native strings::' +
                  json.dumps({'library': lib.name, 'markers': selected}, separators=(',', ':')))
            symbols = subprocess.run(['readelf', '-Ws', str(lib)], capture_output=True, text=True, check=True).stdout.splitlines()
            matches = [line.strip() for line in symbols if re.search(r'il2cpp_init|MetadataLoader|AES_decrypt|EVP_Decrypt|metadata', line, re.I)]
            for match in matches[:20]:
                print('::notice title=WorldBox native symbol::' + match.replace('%', '%25')[:800])

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
            if 'Metadata file not found or encrypted' in result.stdout:
                print('::warning title=WorldBox metadata::Il2CppDumper could not read the metadata; no premium patch was tested.')
                sys.exit(0)
            raise RuntimeError('IL2CPP dump failed: ' + result.stdout[-1500:] + ' ' + result.stderr[-500:])
        lines = (output / 'dump.cs').read_text(errors='replace').splitlines()
        matches = [i for i, line in enumerate(lines) if re.search(r'premium|purchased|purchase|buyproduct', line, re.I)]
        print(f'::notice title=WorldBox scan::{len(matches)} premium/purchase symbol matches')
        for i in matches[:70]:
            context = ' | '.join(lines[max(0, i-1):i+1]).strip().replace('%', '%25').replace('\r', '%0D').replace('\n', '%0A')
            print('::notice title=WorldBox symbol::' + context[:800])
except Exception as exc:
    detail = re.sub(r'https?://\S+', '[URL]', str(exc))[-2000:]
    detail = detail.replace('%', '%25').replace('\r', '%0D').replace('\n', '%0A')
    print('::error title=WorldBox inspection::' + detail)
    sys.exit(1)

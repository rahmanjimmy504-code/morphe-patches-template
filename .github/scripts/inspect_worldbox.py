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
        unity = None
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
                    relevant = [n for n in apk.namelist() if n.endswith('libil2cpp.so') or n.endswith('global-metadata.dat') or n == 'lib/arm64-v8a/libunity.so']
                    for entry in relevant:
                        info = apk.getinfo(entry)
                        print(f'::notice title=WorldBox file::{name}: {entry} ({info.file_size} bytes)')
                        if entry == 'lib/arm64-v8a/libil2cpp.so':
                            native = Path(td) / 'libil2cpp.so'
                            with apk.open(entry) as src, native.open('wb') as dst:
                                shutil.copyfileobj(src, dst)
                        elif entry == 'lib/arm64-v8a/libunity.so':
                            unity = Path(td) / 'libunity.so'
                            with apk.open(entry) as src, unity.open('wb') as dst:
                                shutil.copyfileobj(src, dst)
                        elif entry.endswith('global-metadata.dat'):
                            metadata = Path(td) / 'global-metadata.dat'
                            with apk.open(entry) as src, metadata.open('wb') as dst:
                                shutil.copyfileobj(src, dst)
        if os.environ.get('WORLDBOX_GHIDRA_PROBE') == '1':
            if not native or not native.is_file():
                raise RuntimeError('ARM64 libil2cpp.so not found in the bundle.')
            with native.open('rb') as f:
                observed = hashlib.file_digest(f, 'sha256').hexdigest()
            if observed != '1d644b98fec97a35630495c695515861acd2c18209beaae6471a650db65def87':
                raise RuntimeError('ARM64 library hash does not match the observed 0.51.4 sample; refusing analysis.')
            tool = os.environ.get('GHIDRA_HEADLESS', '')
            callee_mode = os.environ.get('WORLDBOX_GHIDRA_CALLEE_PROBE') == '1'
            probe_script = 'worldbox_ghidra_callees.py' if callee_mode else 'worldbox_ghidra_probe.py'
            result = subprocess.run([sys.executable, '.github/scripts/' + probe_script,
                                     '--headless', tool, '--binary', str(native)],
                                    capture_output=True, text=True, timeout=1000)
            if result.returncode:
                raise RuntimeError('Bounded Ghidra probe failed: ' + result.stderr[-1200:])
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
            print('::warning title=WorldBox ARM64 file flow::' + json.dumps(flow_summary, separators=(',', ':')))
            xref_output = subprocess.run([sys.executable, '.github/scripts/worldbox_native_xrefs.py', str(native)],
                                         capture_output=True, text=True, timeout=360)
            if xref_output.returncode:
                raise RuntimeError('ARM64 cross-reference tool failed: ' + xref_output.stderr[-800:])
            xref = json.loads(xref_output.stdout)
            if xref.get('kind') != 'arm64-static-xrefs':
                raise RuntimeError('Unexpected ARM64 cross-reference result.')
            # GitHub truncates each annotation at 4096 characters. Keep the full
            # aggregate-only report in the job log and emit bounded annotations.
            from worldbox_native_xrefs import annotation_payloads
            print('ARM64 full aggregate xrefs: ' + json.dumps(xref, separators=(',', ':')))
            summary, details = annotation_payloads(xref)
            print('::warning title=WorldBox ARM64 indirect references::' + json.dumps(summary, separators=(',', ':')))
            for detail in details:
                print('::warning title=WorldBox ARM64 source input::' + json.dumps(detail, separators=(',', ':')))
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
            if os.environ.get('WORLDBOX_METADATA_SCAN') == '1':
                server = os.environ.get('WORLDBOX_FRIDA_SERVER')
                if not server or not Path(server).is_file():
                    raise RuntimeError('Missing Frida server binary for emulator runtime scan.')
                adb('root')
                adb('wait-for-device')
                if adb('shell', 'id', '-u') != '0':
                    raise RuntimeError('Emulator adbd is not running as root.')
                adb('push', server, '/data/local/tmp/worldbox-frida-server')
                adb('shell', 'chmod', '755', '/data/local/tmp/worldbox-frida-server')
                adb('shell', 'nohup /data/local/tmp/worldbox-frida-server </dev/null >/data/local/tmp/worldbox-frida.log 2>&1 &')
                time.sleep(8)
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
            if os.environ.get('WORLDBOX_METADATA_SCAN') == '1':
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
            sys.exit(0)
        if not native or not metadata:
            raise RuntimeError('Missing ARM64 native library or Unity metadata.')
        print('::notice title=WorldBox SHA-256::ARM64 library ' + hashlib.file_digest(native.open('rb'), 'sha256').hexdigest())
        header = metadata.read_bytes()
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
            needles = [b'global-metadata.dat', b'il2cpp_init', b'AES_decrypt', b'AES_cbc_encrypt', b'EVP_DecryptInit', b'metadata.dat']
            found = ', '.join(f'{needle.decode()}={data.find(needle)}' for needle in needles)
            print(f'::notice title=WorldBox native markers::{lib.name}: {found}')
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

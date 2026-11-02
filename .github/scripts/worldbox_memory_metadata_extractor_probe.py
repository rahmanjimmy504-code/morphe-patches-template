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


def _sanitize_lines(lines, limit=12):
    selected = []
    for line in lines:
        if re.search(r'hexdump|your hex|^[\s|+\-0-9a-f]{8,}$', line, re.I):
            continue
        line = re.sub(r'0x[0-9a-fA-F]+', '<address>', line)
        line = re.sub(r'/(?:tmp|home/runner)/[^\s]+', '<temp-path>', line)
        line = re.sub(r'\s+', ' ', line).strip()
        if line and len(line) <= 240:
            selected.append(line)
        if len(selected) >= limit:
            break
    return selected


def diagnostic_lines(text):
    relevant = [line for line in text.splitlines()
        if re.search(r'metadata|il2cpp|dump|error|failed|success|detected|size|pattern', line, re.I)]
    return _sanitize_lines(relevant)


def _adb_result(adb, args, timeout=10):
    try:
        result = subprocess.run([adb, *args], capture_output=True, text=True,
                                errors='replace', timeout=timeout)
        stdout = result.stdout[-32_000:] if 'logcat' in args else result.stdout[:32_000]
        return result.returncode, stdout, result.stderr[:2_000]
    except subprocess.TimeoutExpired:
        return 124, '', 'command timed out'
    except OSError as exc:
        return 127, '', type(exc).__name__


def _adb_text(adb, args, timeout=10):
    code, stdout, _ = _adb_result(adb, args, timeout)
    return stdout if code == 0 else ''


def summarize_crash_tombstone(text):
    """Keep only architecture, signal class, and bounded backtrace module names."""
    summary = {}
    for line in text.splitlines():
        match = re.match(r"\s*ABI:\s*['\"]?([^'\"\s]+)", line)
        if match:
            summary['abi'] = match.group(1)[:32]
            break
    for line in text.splitlines():
        if 'signal' in line and 'SIG' in line:
            match = re.search(r'signal\s+(\d+)\s+\((SIG[A-Z0-9]+)\)(?:,\s*code\s+(\d+))?', line)
            if match:
                summary['signal'] = {'number': int(match.group(1)), 'name': match.group(2),
                                     'code': int(match.group(3)) if match.group(3) else None}
            break
    frames = []
    for line in text.splitlines():
        match = re.match(r'\s*#\d+\s+pc\s+[0-9a-fA-F]+\s+([^\s(]+)', line)
        if match:
            module_path = match.group(1)
            frames.append(module_path.rsplit('/', 1)[-1][:100])
        if len(frames) >= 8:
            break
    if frames:
        summary['backtraceModules'] = frames
    return summary


def collect_crash_tombstone(adb='adb'):
    names = _adb_text(adb, ['shell', 'ls', '-1t', '/data/tombstones']).splitlines()[:5]
    for name in names:
        if not re.fullmatch(r'tombstone_\d+', name.strip()):
            continue
        code, text, _ = _adb_result(adb, ['shell', 'cat', f'/data/tombstones/{name.strip()}'])
        if code == 0 and PACKAGE in text:
            summary = summarize_crash_tombstone(text)
            if summary:
                return summary
    return None


def collect_runtime_diagnostics(adb='adb'):
    """Collect a small, filtered snapshot before force-stopping a failed spawn."""
    details = {}
    state_code, state_out, state_err = _adb_result(adb, ['get-state'])
    details['adbState'] = (state_out.strip()[:32] or 'unknown') if state_code == 0 else 'unavailable'
    if state_code:
        details['adbStateError'] = _sanitize_lines([state_err], 1)
    pid_code, pid_text, pid_error = _adb_result(adb, ['shell', 'pidof', PACKAGE])
    details['gamePidProbeExitCode'] = pid_code
    if pid_code and pid_error:
        details['gamePidProbeError'] = _sanitize_lines([pid_error], 1)
    pids = pid_text.strip().split()
    if pids and pids[0].isdigit():
        pid = pids[0]
        details['spawnedProcessPid'] = int(pid)
        status = _adb_text(adb, ['shell', 'cat', f'/proc/{pid}/status'])
        details['processStatus'] = [line.strip() for line in status.splitlines()
            if line.startswith(('Name:', 'State:', 'TracerPid:'))][:3]
        executable = _adb_text(adb, ['shell', 'readlink', f'/proc/{pid}/exe']).strip()
        details['processExecutable'] = executable[:160] if executable else None
        maps = _adb_text(adb, ['shell', 'grep', '-E',
                               'libndk_translation\\.so|libil2cpp\\.so|libunity\\.so',
                               f'/proc/{pid}/maps'])
        details['nativeBridgeMapped'] = 'libndk_translation.so' in maps
        details['targetLibrariesMapped'] = [line.split()[-1].rsplit('/', 1)[-1]
            for line in maps.splitlines()
            if line.split() and re.search(r'lib(il2cpp|unity)\.so', line.split()[-1])][:4]
    else:
        details['spawnedProcessPid'] = None

    server_code, server_pids, server_error = _adb_result(adb, ['shell', 'pidof', 'worldbox-frida-server'])
    details['fridaServerPidProbeExitCode'] = server_code
    details['fridaServerPid'] = server_pids.strip()[:64] if server_code == 0 and server_pids.strip() else None
    if server_code and server_error:
        details['fridaServerPidProbeError'] = _sanitize_lines([server_error], 1)
    server_log_code, server_log, server_log_error = _adb_result(
        adb, ['shell', 'cat', '/data/local/tmp/worldbox-frida.log'])
    details['fridaServerLogReadable'] = server_log_code == 0
    if server_log_code and server_log_error:
        details['fridaServerLogError'] = _sanitize_lines([server_log_error], 1)
    details['fridaServerLines'] = _sanitize_lines(
        [line for line in server_log.splitlines()
         if re.search(r'error|failed|attach|ptrace|process|transport|agent', line, re.I)], 8)
    logcat_code, logcat, logcat_error = _adb_result(adb, ['shell', 'logcat', '-d', '-t', '400'])
    details['logcatReadable'] = logcat_code == 0
    if logcat_code and logcat_error:
        details['logcatReadError'] = _sanitize_lines([logcat_error], 1)
    relevant = [line for line in logcat.splitlines()
        if re.search(r'frida|mkarpenko\.worldbox|libndk_translation|AndroidRuntime|debuggerd|Fatal signal|avc: denied', line, re.I)]
    details['logcatMatchCount'] = len(relevant)
    details['filteredLogcatLines'] = _sanitize_lines(relevant, 12)
    details['targetCrashTombstone'] = collect_crash_tombstone(adb)
    return details


def run_attached_extractor(js_script, dump_path, timeout, adb):
    """Run the pinned scan JS against an already-running process, without Frida spawn."""
    import threading
    import frida

    pids = _adb_text(adb, ['shell', 'pidof', PACKAGE]).split()
    if not pids or not pids[0].isdigit():
        raise RuntimeError('WorldBox is not running for attach-to-running probe')
    device = frida.get_usb_device(timeout=20)
    session = device.attach(int(pids[0]))
    script = None
    messages = []
    state = {}
    completed = threading.Event()

    def on_message(message, data):
        if message.get('type') == 'send' and data is not None:
            try:
                Path(dump_path).write_bytes(bytes(data))
                completed.set()
            except OSError as exc:
                state['error'] = f'Dump write failed: {type(exc).__name__}'
                completed.set()
        elif message.get('type') == 'error':
            state['error'] = str(message.get('description', 'Frida script error'))[:240]
            completed.set()
        elif message.get('type') == 'log':
            payload = message.get('payload')
            if isinstance(payload, str) and len(messages) < 12:
                messages.append(payload[:240])

    try:
        settings = (f"const metadataFunctionOffset=ptr(0x0); "
                    f"const fileSize={EXPECTED_METADATA_BYTES}; "
                    "const filePattern='af 1b b1 fa 1? 00 00 00 00';\n")
        source = settings + Path(js_script).read_text(encoding='utf-8')
        script = session.create_script(source)
        script.on('message', on_message)
        script.load()
        if not completed.wait(timeout):
            raise TimeoutError('Timed out waiting for the attached Frida scan')
        if state.get('error'):
            raise RuntimeError(state['error'])
        return '\n'.join(messages)
    finally:
        if script is not None:
            try:
                script.unload()
            except Exception:
                pass
        try:
            session.detach()
        except Exception:
            pass


def run_probe(archive_path, source_dir, base_apk, native, raw_metadata,
              output_dir, timeout=180, adb='adb', attach_running=False):
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
    # Spawn mode owns the process lifecycle; running-process mode intentionally attaches to the live app.
    if not attach_running:
        stop = subprocess.run([adb, 'shell', 'am', 'force-stop', PACKAGE],
                              capture_output=True, text=True, timeout=30)
        if stop.returncode:
            raise RuntimeError('Could not stop the existing WorldBox process before Frida spawn')

    timed_out = False
    combined_log = ''
    runtime_diagnostics = None
    returncode = 125
    try:
        if attach_running:
            combined_log = run_attached_extractor(
                source_dir / f'Il2CppMetadataExtractor-{TOOL_COMMIT}' / 'dump-metadata.js',
                dump_path, timeout, adb)
            returncode = 0
        else:
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
    except TimeoutError as exc:
        timed_out = True
        returncode = 124
        combined_log = str(exc)
    except OSError as exc:
        returncode = 127
        combined_log = f'Extractor launch failed: {type(exc).__name__}'
    except Exception as exc:
        returncode = 1
        combined_log = f'{type(exc).__name__}: {exc}'
    finally:
        if not classify(returncode, dump_path, timed_out)['metadataCandidateValidated']:
            try:
                runtime_diagnostics = collect_runtime_diagnostics(adb)
            except Exception as exc:  # Keep diagnostic failure from hiding the bounded probe result.
                runtime_diagnostics = {'collectionError': type(exc).__name__}
        try:
            subprocess.run([adb, 'shell', 'am', 'force-stop', PACKAGE],
                           capture_output=True, text=True, timeout=30)
        except (OSError, subprocess.TimeoutExpired):
            pass

    report = {
        'kind': 'worldbox-memory-metadata-extractor-probe',
        'tool': REPOSITORY,
        'toolCommit': TOOL_COMMIT,
        'driverMode': 'attach-running' if attach_running else 'spawn-before-attach',
        'toolArchiveSha256': sha256(archive_path),
        'rawMetadataSha256': sha256(raw_metadata),
        'baseApkSha256': sha256(base_apk),
        'arm64Il2CppSha256': sha256(native),
        **classify(returncode, dump_path, timed_out),
        'diagnosticLines': diagnostic_lines(combined_log),
    }
    if runtime_diagnostics is not None:
        report['runtimeDiagnostics'] = runtime_diagnostics
    return report


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
    parser.add_argument('--attach-running', action='store_true',
                        help='Attach to the already-running app instead of using device.spawn')
    args = parser.parse_args()
    print(json.dumps(run_probe(args.archive, args.source_dir, args.base_apk, args.native,
        args.metadata, args.output_dir, args.timeout, args.adb, args.attach_running), separators=(',', ':')))


if __name__ == '__main__':
    main()

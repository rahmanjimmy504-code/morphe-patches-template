#!/usr/bin/env python3
"""Hash-gated, bounded Premium-entitlement lead probe for WorldBox 0.51.4.

Only exact predefined `premium_unlocked` / "Get It Now" / case-variant needles,
aggregate counts, predefined safe labels, ELF/ZIP-relative locations, resource
IDs, name hashes, decoded mnemonics and unwind-bounded function addresses are
emitted. No raw game bytes, unknown strings, metadata content or patch logic
leave the analysis. Static matches are not proof of entitlement behavior.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import sys
import zipfile
from pathlib import Path

from elftools.elf.elffile import ELFFile

import worldbox_native_literal_refs as refs
import worldbox_native_xrefs as xrefs
import worldbox_thunk_callers as thunks
from worldbox_bounded_reference_report import annotation

KIND = 'worldbox-premium-entitlement-probe'
EXPECTED_IL2CPP = '1d644b98fec97a35630495c695515861acd2c18209beaae6471a650db65def87'
EXPECTED_UNITY = '8c04ad3b7d482cab925541cfe9839844c87732f7419aaaa71e170ccff916f082'
EXPECTED_BASE_APK = 'ab7c6bab7d2233c26a9e18426aa58dd60fa0ae0ad9be6fa0b2a6673dd8f89c3f'
EXPECTED_METADATA = '0c843e9807d351f193580e178f4826845534cdcd86563e634ca8a48ad3b7bc88'
NEEDLES = {
    'premium_unlocked': 'premium_unlocked',
    'get_it_now': 'Get It Now',
    'premium_lower': 'premium',
    'premium_capital': 'Premium',
    'premium_upper': 'PREMIUM',
    'get_it_now_lower': 'get it now',
    'get_it_now_snake': 'get_it_now',
}
EXACT_NEEDLES = ('premium_unlocked', 'get_it_now')
ENCODINGS = ('ascii', 'utf16le')
CHUNK_SIZE = 1024 * 1024
MAX_ENTRY_BYTES = 256 * 1024 * 1024
MAX_TOTAL_APK_BYTES = 512 * 1024 * 1024
MAX_METADATA_BYTES = 64 * 1024 * 1024
MAX_DEX_BYTES = 64 * 1024 * 1024
MAX_DEX_INSTRUCTIONS = 2_000_000
MAX_EXAMPLES = 12
MAX_ENTRY_ROWS = 24
MAX_EXACT_NEEDLE_ROWS = 12
MAX_ANNOTATION_ROWS = 4
MAX_DEX_ANNOTATION_ROWS = 3
MAX_RESOURCE_TABLES = 8
MAX_DEX_FILES = 12
MAX_RESOURCE_IDS = 64
MAX_GHIDRA_ADDRESSES = 6
DEFAULT_WATCHED_STUBS = {
    0x3bf8f20: 'stat', 0x3bf9000: 'readlink', 0x3bf9030: 'fstat',
    0x3bf9070: 'read', 0x3bf90c0: 'open', 0x3bf90d0: 'close',
    0x3bf9220: 'brotli-decompress-stream-import',
    0x3bf9700: 'mmap', 0x3bf9710: 'munmap',
    0x3bf9d50: 'dlopen', 0x3bf9d60: 'dlerror',
    0x3bf9d70: 'dlsym', 0x3bf9d80: 'dlclose',
}
OBSERVABLE_STUB_LABELS = frozenset(DEFAULT_WATCHED_STUBS.values())
LIMITATIONS = (
    'Hash-gated exact ASCII/UTF-16LE needle counts in ARM64 native libraries, global-metadata.dat, APK entries, DEX string tables/const-string instructions and resource-table values/keys, plus bounded ADRP+ADD literal-reference and direct-import-call modeling. '
    'Zero counts do not exclude encrypted, encoded, split, constructed, runtime-generated or transformed strings. '
    'Resource-ID constants and class/method/resource-key names are represented only by hashes; unknown strings and raw game bytes are never emitted. '
    'Static matches and Ghidra decompilation candidates are not proof of an entitlement check, purchase flow, metadata loading or a patch.'
)


def sha256_file(path):
    with Path(path).open('rb') as handle:
        return hashlib.file_digest(handle, 'sha256').hexdigest()


def encode_needle(text, encoding):
    return text.encode('utf-16le' if encoding == 'utf16le' else encoding)


def scan_stream(handle, needles=NEEDLES, encodings=ENCODINGS,
                max_bytes=MAX_ENTRY_BYTES, chunk_size=CHUNK_SIZE,
                max_examples=MAX_EXAMPLES, location_fields=None):
    """Count exact predefined needles across chunk boundaries without emitting bytes."""
    patterns = [(label, encoding, encode_needle(text, encoding))
                for label, text in needles.items() for encoding in encodings]
    counts = {label: {encoding: 0 for encoding in encodings} for label in needles}
    examples = []
    example_count = 0
    max_len = max(len(pattern) for _, _, pattern in patterns)
    tail = b''
    file_offset = 0
    scanned = 0
    truncated = False
    while scanned < max_bytes:
        chunk = handle.read(min(chunk_size, max_bytes - scanned))
        if not chunk:
            break
        buffer = tail + chunk
        buffer_start = file_offset - len(tail)
        for label, encoding, pattern in patterns:
            threshold = file_offset - (len(pattern) - 1)
            start = 0
            while True:
                position = buffer.find(pattern, start)
                if position < 0:
                    break
                absolute = buffer_start + position
                if absolute >= threshold:
                    counts[label][encoding] += 1
                    example_count += 1
                    if len(examples) < max_examples:
                        example = {'offset': hex(absolute), 'needle': label,
                                   'encoding': encoding}
                        if location_fields:
                            example.update(location_fields)
                        examples.append(example)
                start = position + 1
        scanned += len(chunk)
        file_offset += len(chunk)
        tail = buffer[-(max_len - 1):] if max_len > 1 else b''
        if scanned >= max_bytes:
            truncated = True
            break
    return {'counts': counts, 'examples': examples,
            'examplesTruncated': example_count > len(examples),
            'bytesScanned': scanned, 'truncated': truncated}


def scan_metadata(path, needles=NEEDLES):
    with Path(path).open('rb') as handle:
        result = scan_stream(handle, needles, max_bytes=MAX_METADATA_BYTES)
    result['kind'] = 'metadata-file'
    result['sha256'] = sha256_file(path)
    return result


def scan_apk_entries(paths, needles=NEEDLES):
    hit_rows = []
    total_counts = {label: {encoding: 0 for encoding in ENCODINGS}
                    for label in needles}
    exact_hits = {label: 0 for label in EXACT_NEEDLES if label in needles}
    scanned = 0
    entries_scanned = 0
    truncated = False
    for apk in paths:
        apk = Path(apk)
        with zipfile.ZipFile(apk) as archive:
            for name in archive.namelist():
                if name.endswith('/'):
                    continue
                remaining = MAX_TOTAL_APK_BYTES - scanned
                if remaining <= 0:
                    truncated = True
                    break
                entries_scanned += 1
                with archive.open(name) as handle:
                    result = scan_stream(handle, needles,
                                         max_bytes=min(MAX_ENTRY_BYTES, remaining),
                                         location_fields={'apk': apk.name,
                                                          'entry': name})
                scanned += result['bytesScanned']
                if result['truncated']:
                    truncated = True
                if not any(count for per_encoding in result['counts'].values()
                           for count in per_encoding.values()):
                    continue
                for label, per_encoding in result['counts'].items():
                    for encoding, count in per_encoding.items():
                        total_counts[label][encoding] += count
                exact_counts = {label: sum(result['counts'][label].values())
                                for label in exact_hits}
                for label, count in exact_counts.items():
                    if count:
                        exact_hits[label] += 1
                exact_sum = sum(exact_counts.values())
                get_it_now_count = exact_counts.get('get_it_now', 0)
                premium_unlocked_count = exact_counts.get('premium_unlocked', 0)
                row = {'apk': apk.name, 'entry': name,
                       'counts': result['counts'],
                       'examples': result['examples'][:2],
                       'examplesTruncated': result['examplesTruncated'] or
                                            len(result['examples']) > 2,
                       'bytesScanned': result['bytesScanned'],
                       'truncated': result['truncated'],
                       'exactNeedleCount': exact_sum,
                       'getItNowCount': get_it_now_count,
                       'premiumUnlockedCount': premium_unlocked_count}
                hit_rows.append(row)
            if truncated:
                break
    # The rare "Get It Now" label is more diagnostic than numerous repeated
    # premium_unlocked hits, so keep its entries ahead of broader case variants.
    hit_rows.sort(key=lambda row: (-row['getItNowCount'],
                                   -row['premiumUnlockedCount'],
                                   -row['exactNeedleCount'],
                                   -sum(count for per in row['counts'].values()
                                        for count in per.values()),
                                   row['apk'], row['entry']))
    exact_rows = [row for row in hit_rows if row['exactNeedleCount']]
    return {'kind': 'apk-entry-scan', 'entriesScanned': entries_scanned,
            'bytesScanned': scanned, 'truncated': truncated,
            'totalCounts': total_counts,
            'exactNeedleHitEntryCount': exact_hits,
            'exactNeedleRows': [
                {'apk': row['apk'], 'entry': row['entry'],
                 'getItNowCount': row['getItNowCount'],
                 'premiumUnlockedCount': row['premiumUnlockedCount'],
                 'counts': {label: row['counts'][label] for label in exact_hits}}
                for row in exact_rows[:MAX_EXACT_NEEDLE_ROWS]],
            'exactNeedleRowsTruncated':
                len(exact_rows) > MAX_EXACT_NEEDLE_ROWS,
            'hitEntryCount': len(hit_rows),
            'rows': hit_rows[:MAX_ENTRY_ROWS],
            'rowsTruncated': len(hit_rows) > MAX_ENTRY_ROWS}


def default_arsc_parser(data):
    from androguard.core.axml import ARSCParser
    return ARSCParser(data)


def resource_matches(data, needles=NEEDLES, parser_factory=None,
                     max_examples=MAX_EXAMPLES, max_ids=MAX_RESOURCE_IDS):
    """Map exact needle-bearing resource values/keys to resource IDs by hashes."""
    try:
        parser = (parser_factory or default_arsc_parser)(data)
        resolved = parser.get_resolved_strings()
        resource_keys = parser.resource_keys
    except Exception as exc:
        return {'status': 'parse-failed', 'reason': type(exc).__name__,
                'counts': {}, 'examples': [], 'resourceIds': [],
                'resourceIdsTruncated': False}
    counts = {label: {'value': 0, 'key': 0} for label in needles}
    examples = []
    example_count = 0
    resource_ids = []
    seen_ids = set()
    ids_truncated = False

    def record(label, source, resource_id, extra):
        nonlocal example_count, ids_truncated
        counts[label][source] += 1
        example_count += 1
        if len(examples) < max_examples:
            row = {'needle': label, 'source': source,
                   'resourceId': hex(resource_id)}
            row.update(extra)
            examples.append(row)
        if resource_id not in seen_ids:
            if len(resource_ids) < max_ids:
                seen_ids.add(resource_id)
                resource_ids.append(resource_id)
            else:
                ids_truncated = True

    for package, locales in resolved.items():
        package_hash = refs.hash_text(package)
        for locale, values in locales.items():
            locale_hash = refs.hash_text(locale)
            for resource_id, value in values.items():
                text = str(value)
                for label, needle in needles.items():
                    if needle in text:
                        record(label, 'value', resource_id,
                               {'packageSha256': package_hash,
                                'localeSha256': locale_hash,
                                'valueSha256': refs.hash_text(text)})
    for package, types in resource_keys.items():
        package_hash = refs.hash_text(package)
        for resource_type, keys in types.items():
            for key, resource_id in keys.items():
                text = str(key)
                for label, needle in needles.items():
                    if needle in text:
                        record(label, 'key', resource_id,
                               {'packageSha256': package_hash,
                                'resourceTypeSha256': refs.hash_text(resource_type),
                                'keySha256': refs.hash_text(text)})
    return {'status': 'parsed', 'counts': counts, 'examples': examples,
            'examplesTruncated': example_count > len(examples),
            'resourceIds': [hex(value) for value in resource_ids],
            'resourceIdsTruncated': ids_truncated}


def dex_report(data, needles=NEEDLES, resource_ids=(), dex_factory=None):
    if len(data) > MAX_DEX_BYTES:
        return {'status': 'too-large', 'raw': None}
    raw = scan_stream(io.BytesIO(data), needles, max_bytes=MAX_DEX_BYTES)
    try:
        dex = (dex_factory or (lambda blob: __import__(
            'androguard.core.dex', fromlist=['DEX']).DEX(blob)))(data)
        strings = dex.get_strings()
        resource_set = {int(value, 0) if isinstance(value, str) else value
                        for value in resource_ids}
        string_matches = []
        methods = []
        method_count = 0
        instructions_scanned = 0
        instructions_truncated = False
        for index, value in enumerate(strings):
            matched = [label for label, needle in needles.items()
                       if needle in str(value)]
            if matched:
                string_matches.append({'stringIndex': index,
                                       'needles': sorted(matched),
                                       'stringLength': len(str(value)),
                                       'valueSha256': refs.hash_text(value)})
        for cls in dex.get_classes():
            class_name = str(cls.get_name())
            for method in cls.get_methods():
                code = method.get_code()
                if code is None:
                    continue
                matched = set()
                constants = set()
                for instruction in code.get_bc().get_instructions():
                    instructions_scanned += 1
                    if instructions_scanned > MAX_DEX_INSTRUCTIONS:
                        instructions_truncated = True
                        break
                    name = instruction.get_name()
                    if name.startswith('const-string'):
                        output = str(instruction.get_output())
                        for label, needle in needles.items():
                            if needle in output:
                                matched.add(label)
                    try:
                        literals = instruction.get_literals()
                    except Exception:
                        literals = []
                    for literal in literals:
                        if isinstance(literal, int) and literal in resource_set:
                            constants.add(literal)
                    if instructions_truncated:
                        break
                if matched or constants:
                    method_count += 1
                    if len(methods) < MAX_EXAMPLES:
                        descriptor = str(method.get_descriptor())
                        methods.append({
                            'needles': sorted(matched),
                            'resourceIds': [hex(value) for value in sorted(constants)],
                            'classSha256': refs.hash_text(class_name),
                            'methodSha256': refs.hash_text(method.get_name()),
                            'descriptorSha256': refs.hash_text(descriptor)})
                if instructions_truncated:
                    break
            if instructions_truncated:
                break
        return {'status': 'parsed', 'raw': raw,
                'stringCount': len(strings),
                'stringTableMatchCount': len(string_matches),
                'stringMatches': string_matches[:MAX_EXAMPLES],
                'stringMatchesTruncated': len(string_matches) > MAX_EXAMPLES,
                'methodMatchCount': method_count,
                'methods': methods,
                'methodsTruncated': method_count > len(methods),
                'instructionsScanned': instructions_scanned,
                'instructionsTruncated': instructions_truncated}
    except Exception as exc:
        return {'status': 'parse-failed', 'reason': type(exc).__name__, 'raw': raw}


def analyze_apks(paths, needles=NEEDLES, resource_parser_factory=None,
                 dex_factory=None):
    resources = []
    resource_ids = []
    tables_seen = 0
    tables_truncated = False
    for apk in paths:
        apk = Path(apk)
        with zipfile.ZipFile(apk) as archive:
            for name in archive.namelist():
                if name != 'resources.arsc':
                    continue
                tables_seen += 1
                if len(resources) >= MAX_RESOURCE_TABLES:
                    tables_truncated = True
                    continue
                data = archive.read(name)
                row = resource_matches(data, needles, resource_parser_factory)
                row.update({'apk': apk.name, 'entry': name,
                            'bytes': len(data),
                            'sha256': hashlib.sha256(data).hexdigest()})
                resources.append(row)
                for value in row['resourceIds']:
                    if value not in resource_ids and len(resource_ids) < MAX_RESOURCE_IDS:
                        resource_ids.append(value)
    dex_files = []
    dex_seen = 0
    dex_truncated = False
    for apk in paths:
        apk = Path(apk)
        with zipfile.ZipFile(apk) as archive:
            for name in sorted(entry for entry in archive.namelist()
                               if entry.lower().endswith('.dex')):
                dex_seen += 1
                if len(dex_files) >= MAX_DEX_FILES:
                    dex_truncated = True
                    continue
                data = archive.read(name)
                dex_files.append({'apk': apk.name, 'dex': name,
                                  'bytes': len(data),
                                  'sha256': hashlib.sha256(data).hexdigest(),
                                  'report': dex_report(data, needles,
                                                       resource_ids, dex_factory)})
    return {'resources': resources, 'resourceIds': resource_ids,
            'resourceIdsTruncated': any(row.get('resourceIdsTruncated')
                                        for row in resources),
            'resourceTablesSeen': tables_seen,
            'resourceTablesTruncated': tables_truncated,
            'dexFiles': dex_files, 'dexFilesSeen': dex_seen,
            'dexFilesTruncated': dex_truncated}


def native_report(path, needles=NEEDLES, watched_stubs=None):
    watched = dict(DEFAULT_WATCHED_STUBS if watched_stubs is None else watched_stubs)
    with Path(path).open('rb') as handle:
        elf = ELFFile(handle)
        if elf.elfclass != 64 or not elf.little_endian or elf['e_machine'] != 'EM_AARCH64':
            raise ValueError('Expected a little-endian ELF64 AArch64 library')
        frames, unwind_status = thunks.unwind_frames(elf)
        imports = xrefs.safe_import_plt(elf)
    starts = [low for low, _ in frames]
    literals = refs.literal_occurrences(path, needles)
    name_refs = refs.adrp_add_reference_sites(path,
                                              literals['referenceAddresses'],
                                              frames, starts)
    calls = refs.function_direct_calls(path, name_refs['functionAddresses'],
                                       watched)
    observed = {hex(address): (imports.get(address)
                               if imports.get(address) in OBSERVABLE_STUB_LABELS
                               else 'other-import')
                for address in watched}
    return {'kind': 'native-literal-model', 'sha256': sha256_file(path),
            'needles': needles, 'watchedStubs': {
                hex(address): label for address, label in watched.items()},
            'observedStubLabels': observed, 'unwindStatus': unwind_status,
            'unwindRanges': len(frames), 'literals': literals,
            'nameReferences': name_refs, 'watchedCalls': calls,
            'ghidraAddresses': name_refs['functionAddresses'][:MAX_GHIDRA_ADDRESSES],
            'ghidraAddressesTruncated':
                len(name_refs['functionAddresses']) > MAX_GHIDRA_ADDRESSES}


def verify_hashes(native, unity, metadata, apk_paths, expected=None):
    expected = dict(expected or {})
    expected.setdefault('libil2cpp.so', EXPECTED_IL2CPP)
    expected.setdefault('libunity.so', EXPECTED_UNITY)
    expected.setdefault('metadata', EXPECTED_METADATA)
    expected.setdefault('base.apk', EXPECTED_BASE_APK)
    gates = {}
    for label, path in (('libil2cpp.so', native), ('libunity.so', unity),
                        ('metadata', metadata)):
        observed = sha256_file(path)
        gates[label] = observed
        if expected.get(label) and observed != expected[label]:
            raise ValueError(label + ' hash mismatch; refusing Premium probe.')
    if apk_paths:
        base = next((Path(path) for path in apk_paths
                     if Path(path).name == 'base.apk'), None)
        if base is None:
            raise ValueError('base.apk not supplied for Premium Android probe.')
        observed = sha256_file(base)
        gates['base.apk'] = observed
        if expected.get('base.apk') and observed != expected['base.apk']:
            raise ValueError('base.apk hash mismatch; refusing Premium probe.')
    return gates


def premium_report(native, unity, metadata, apk_paths=(), needles=NEEDLES,
                   expected_hashes=None, watched_stubs=None,
                   resource_parser_factory=None, dex_factory=None):
    apk_paths = [Path(path) for path in apk_paths]
    gates = verify_hashes(native, unity, metadata, apk_paths, expected_hashes)
    native_reports = {
        'libil2cpp.so': native_report(native, needles, watched_stubs),
        'libunity.so': native_report(unity, needles, watched_stubs),
    }
    metadata_scan = scan_metadata(metadata, needles)
    apk_scan = (scan_apk_entries(apk_paths, needles) if apk_paths else
                {'status': 'not-requested'})
    android = (analyze_apks(apk_paths, needles, resource_parser_factory,
                            dex_factory) if apk_paths else
               {'resources': [], 'resourceIds': [], 'resourceIdsTruncated': False,
                'resourceTablesSeen': 0, 'resourceTablesTruncated': False,
                'dexFiles': [], 'dexFilesSeen': 0, 'dexFilesTruncated': False,
                'status': 'not-requested'})
    # Ghidra decompilation is run against libil2cpp.so only. Unity anchors are
    # reported separately so they are never sent to the wrong binary.
    anchors = native_reports['libil2cpp.so']['ghidraAddresses']
    ghidra_addresses = anchors[:MAX_GHIDRA_ADDRESSES]
    unity_addresses = native_reports['libunity.so']['ghidraAddresses']
    trace_targets = [hex(address) for address in
                     dict(DEFAULT_WATCHED_STUBS if watched_stubs is None
                          else watched_stubs)]
    return {'kind': KIND,
            'mode': 'android' if apk_paths else 'native',
            'hashGates': gates, 'needles': needles,
            'encodings': list(ENCODINGS), 'nativeReports': native_reports,
            'metadataScan': metadata_scan, 'apkEntryScan': apk_scan,
            'androidReports': android,
            'ghidraLibrary': 'libil2cpp.so',
            'ghidraAddresses': ghidra_addresses,
            'ghidraAddressesTruncated': len(anchors) > len(ghidra_addresses),
            'unityGhidraAddresses': unity_addresses[:MAX_GHIDRA_ADDRESSES],
            'traceTargets': trace_targets, 'limitations': LIMITATIONS}


def nonzero_counts(counts):
    result = {}
    for label, per_encoding in counts.items():
        kept = {encoding: count for encoding, count in per_encoding.items() if count}
        if kept:
            result[label] = kept
    return result


def emit_bounded(level, title, payload):
    """Emit a compact workflow annotation that stays below GitHub's 4096 cap."""
    message = annotation(json.dumps(payload, separators=(',', ':')))
    if len(message) > 3800:
        raise ValueError('Premium annotation exceeds the safety bound: ' + title)
    print('::' + level + ' title=' + title + '::' + message)


def compact_dex(dex, detailed=False):
    result = {'apk': dex['apk'], 'dex': dex['dex'],
              'bytes': dex['bytes'], 'sha256': dex['sha256'],
              'status': dex['report']['status']}
    raw = dex['report'].get('raw')
    if raw:
        result['rawCounts'] = nonzero_counts(raw['counts'])
        result['rawExamplesTruncated'] = raw['examplesTruncated']
    if dex['report']['status'] != 'parsed':
        if dex['report'].get('reason'):
            result['reason'] = dex['report']['reason']
        return result
    report = dex['report']
    result.update({key: report[key] for key in
                   ('stringCount', 'stringTableMatchCount',
                    'stringMatchesTruncated', 'methodMatchCount',
                    'methodsTruncated', 'instructionsScanned',
                    'instructionsTruncated')})
    if detailed:
        result['stringMatches'] = report['stringMatches'][:3]
        result['methods'] = report['methods'][:3]
    return result


def emit_premium_annotations(report):
    if report.get('kind') != KIND:
        raise RuntimeError('Unexpected WorldBox Premium entitlement report.')
    print('WorldBox full Premium entitlement report: ' +
          json.dumps(report, separators=(',', ':')))
    summary = {key: report[key] for key in
               ('mode', 'hashGates', 'needles', 'encodings',
                'ghidraLibrary', 'ghidraAddresses',
                'ghidraAddressesTruncated', 'unityGhidraAddresses',
                'traceTargets', 'limitations')}
    emit_bounded('warning', 'WorldBox Premium entitlement summary', summary)
    for name, row in report['nativeReports'].items():
        payload = {'library': name, 'sha256': row['sha256'],
                   'unwindStatus': row['unwindStatus'],
                   'literalResults': row['literals']['results'],
                   'referenceAddresses': row['literals']['referenceAddresses'],
                   'referenceAddressesTruncated': row['literals']['referenceAddressesTruncated'],
                   'nameReferenceCount': row['nameReferences']['count'],
                   'nameReferenceSites': row['nameReferences']['sites'],
                   'watchedCalls': row['watchedCalls']['rows'],
                   'ghidraAddresses': row['ghidraAddresses']}
        emit_bounded('warning', 'WorldBox Premium native model ' + name, payload)
    emit_bounded('warning', 'WorldBox Premium metadata scan',
                 report['metadataScan'])
    if report['apkEntryScan'].get('status') == 'not-requested':
        return
    apk_scan = report['apkEntryScan']
    overview = {key: apk_scan[key] for key in
                ('entriesScanned', 'bytesScanned', 'truncated',
                 'totalCounts', 'exactNeedleHitEntryCount',
                 'exactNeedleRows', 'exactNeedleRowsTruncated',
                 'hitEntryCount', 'rowsTruncated')}
    emit_bounded('warning', 'WorldBox Premium APK entry overview', overview)
    rows = apk_scan['rows']
    chunks = [rows[start:start + MAX_ANNOTATION_ROWS]
              for start in range(0, len(rows), MAX_ANNOTATION_ROWS)] or [[]]
    for number, part in enumerate(chunks, 1):
        payload = {'chunk': [number, len(chunks)], 'rows': [
            {'apk': row['apk'], 'entry': row['entry'],
             'counts': nonzero_counts(row['counts']),
             'examples': row['examples'],
             'examplesTruncated': row['examplesTruncated'],
             'bytesScanned': row['bytesScanned'],
             'exactNeedleCount': row['exactNeedleCount'],
             'getItNowCount': row.get('getItNowCount', 0),
             'premiumUnlockedCount': row.get('premiumUnlockedCount', 0)}
            for row in part]}
        emit_bounded('notice', 'WorldBox Premium APK entry rows ' +
                     str(number) + '/' + str(len(chunks)), payload)
    android = report['androidReports']
    emit_bounded('warning', 'WorldBox Premium resource matches', {
        'resourceIds': android['resourceIds'],
        'resourceIdsTruncated': android['resourceIdsTruncated'],
        'resourceTablesSeen': android.get('resourceTablesSeen'),
        'resourceTablesTruncated': android.get('resourceTablesTruncated'),
        'dexFilesSeen': android.get('dexFilesSeen'),
        'dexFilesTruncated': android.get('dexFilesTruncated'),
        'tables': [{key: row.get(key) for key in
                    ('apk', 'entry', 'bytes', 'sha256', 'status',
                     'reason', 'counts', 'examples',
                     'examplesTruncated')}
                   for row in android['resources']]})
    dex_files = android['dexFiles']
    emit_bounded('warning', 'WorldBox Premium DEX overview', {
        'dexFilesSeen': android.get('dexFilesSeen'),
        'dexFilesTruncated': android.get('dexFilesTruncated'),
        'files': [compact_dex(dex) for dex in dex_files]})
    chunks = [dex_files[start:start + MAX_DEX_ANNOTATION_ROWS]
              for start in range(0, len(dex_files), MAX_DEX_ANNOTATION_ROWS)] or [[]]
    for number, part in enumerate(chunks, 1):
        payload = {'chunk': [number, len(chunks)],
                   'files': [compact_dex(dex, detailed=True) for dex in part]}
        emit_bounded('notice', 'WorldBox Premium DEX details ' +
                     str(number) + '/' + str(len(chunks)), payload)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--native', required=True)
    parser.add_argument('--unity', required=True)
    parser.add_argument('--metadata', required=True)
    parser.add_argument('--apk', action='append', default=[])
    args = parser.parse_args()
    try:
        report = premium_report(args.native, args.unity, args.metadata, args.apk)
    except Exception as exc:
        print(f'Premium entitlement probe failed: {type(exc).__name__}: {exc}',
              file=sys.stderr)
        return 1
    print(json.dumps(report, separators=(',', ':')))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

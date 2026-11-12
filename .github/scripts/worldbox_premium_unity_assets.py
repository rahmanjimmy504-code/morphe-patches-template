#!/usr/bin/env python3
"""Bounded Unity asset model for the exact Premium needle entries.

Uses UnityPy's structural parser and common MonoBehaviour base fields only.
Unknown object names, script labels, type names, payload tokens and method
tokens are represented by SHA-256 hashes; no raw asset bytes, arbitrary game
strings, custom field values or executable code are emitted.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
import struct
import sys
import zipfile
from pathlib import Path

import UnityPy
from UnityPy.files.SerializedFile import SerializedFile

import worldbox_unity_schema as schema
import worldbox_unity_script_refs as refs
import worldbox_unity_scripts as scripts
from worldbox_bounded_reference_report import annotation

KIND = 'worldbox-premium-unity-assets'
EXPECTED_BASE_APK = 'ab7c6bab7d2233c26a9e18426aa58dd60fa0ae0ad9be6fa0b2a6673dd8f89c3f'
SELECTED_ENTRIES = (
    {'label': 'get_it_now_primary',
     'entry': 'assets/bin/Data/13cfff6f881b80049833c82202d4227a'},
    {'label': 'get_it_now_secondary',
     'entry': 'assets/bin/Data/6f7d4abbd6fb14eabaad2266d6de4adf'},
    {'label': 'premium_unlocked_1',
     'entry': 'assets/bin/Data/7c7dd69ec9c748445ac2b5ecff11e69f'},
    {'label': 'premium_unlocked_2',
     'entry': 'assets/bin/Data/abba007fcc231f946bb3ba988fe9ddfb'},
    {'label': 'premium_unlocked_3',
     'entry': 'assets/bin/Data/1a521a104aa73fa45843e973963a7d49'},
    {'label': 'premium_unlocked_4',
     'entry': 'assets/bin/Data/1ec40a398dedbc646b5e9781b279f212'},
    {'label': 'premium_unlocked_5',
     'entry': 'assets/bin/Data/305f73ca61e203b4984f15c4a2a1fb07'},
    {'label': 'premium_unlocked_6',
     'entry': 'assets/bin/Data/3d6d3728b940f884589bdfedcb346773'},
)
NEEDLES = {
    'premium_unlocked': b'premium_unlocked',
    'get_it_now': b'Get It Now',
    'premium_lower': b'premium',
    'premium_capital': b'Premium',
}
SAFE_STRINGS = frozenset({
    'premium_unlocked', 'Premium', 'premium', 'Get It Now', 'premium_menu',
    'CloseButton', 'Canvas', 'clickPremium', 'clickClose', 'clickHide',
    'ResetState', 'PremiumWindow', 'PremiumUnlockAnimation',
    'PremiumElementsChecker', 'TopPremiumButtonMover',
    'WindowPremiumRestoreHelper', 'ButtonPremium', 'PowerButton',
    'ButtonUtil', 'LocalizedTextPrice', 'Button', 'GameObject', 'Transform',
    'RectTransform', 'MonoBehaviour', 'MonoScript', 'CanvasGroup', 'Text',
    'Image', 'bool', 'int', 'string', 'float', 'PPtr<GameObject>',
    'same-file', 'other-file', 'external-basename-match',
    'unresolved-file-id', 'unresolved-external',
    'unresolved-ambiguous-basename',
    *refs.TARGETS.values(),
})
SAFE_VERSION = re.compile(r'[0-9A-Za-z._-]{1,64}\Z', re.ASCII)
MAX_FILE = 32 * 1024 * 1024
MAX_OBJECTS = 200000
MAX_MATCHES = 20000
MAX_SAMPLES = 12
MAX_OBJECT_DETAILS = 4
MAX_CONTEXTS = 2
MAX_PAYLOAD = 8192
MAX_PAYLOAD_STRINGS = 12
MAX_PPTR_CANDIDATES = 8
LIMITATIONS = (
    'Hash-gated UnityPy structural model of eight exact Premium-needle assets. Exact needle offsets are mapped to serialized object extents; common MonoBehaviour base pointers, stored schema availability, GameObject hierarchy/component labels, aligned payload tokens and local PPtr/method-token adjacency are reported. '
    'Unknown strings are emitted only as SHA-256 hashes and lengths; no raw asset bytes, arbitrary identifiers, custom field values, method bodies or decoded IL2CPP metadata leave the probe. '
    'Serialized associations and adjacency patterns are not proof of executed entitlement logic, a purchase handler or a safe patch.'
)


def sha256_file(path):
    with Path(path).open('rb') as handle:
        return hashlib.file_digest(handle, 'sha256').hexdigest()


def hash_text(value):
    return hashlib.sha256(value.encode('utf-8', 'replace')).hexdigest()


def string_descriptor(value):
    if not isinstance(value, str):
        return None
    if value in SAFE_STRINGS:
        return {'safe': value}
    return {'sha256': hash_text(value), 'length': len(value)}


def version_descriptor(value):
    if isinstance(value, str) and SAFE_VERSION.fullmatch(value):
        return {'safe': value}
    return string_descriptor(str(value))


def is_descriptor(value):
    return (isinstance(value, dict) and
            (('safe' in value or 'sha256' in value) and
             set(value) <= {'safe', 'sha256', 'length'}))


def sanitize_value(value):
    """Replace every game-derived string with a safe label or hash descriptor."""
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return string_descriptor(value)
    if is_descriptor(value):
        return value
    if isinstance(value, dict):
        return {key: sanitize_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [sanitize_value(item) for item in value]
    return None


def compact_context(context):
    """Keep bounded hierarchy/component labels; hash every unknown string."""
    if not isinstance(context, dict):
        return {'available': False}
    hierarchy = context.get('hierarchy', [])
    component_types = context.get('componentTypes', [])
    scripts = context.get('componentScripts', [])
    buttons = context.get('buttonPPtrCandidates', [])
    pointer_calls = []
    for button in buttons[:8]:
        for match in button.get('localPPtrMatches', [])[:16]:
            method_tokens = [item.get('candidateMethod')
                             for item in match.get('methodTokens', [])[:8]
                             if item.get('candidateMethod') in
                             ('clickPremium', 'ResetState', 'clickClose', 'clickHide')]
            script_class = match.get('scriptClassName')
            if not method_tokens or script_class not in {'ButtonPremium', 'ButtonUtil'}:
                continue
            pointer_calls.append({
                'buttonIndex': button.get('buttonIndex'),
                'buttonPathId': button.get('buttonPathId'),
                'targetIndex': match.get('index'),
                'targetPathId': match.get('pathId'),
                'targetScriptClass': string_descriptor(script_class),
                'offsets': match.get('offsets', [])[:2],
                'methodTokens': [string_descriptor(item)
                                 for item in method_tokens[:2]]})
    return {
        'available': context.get('available'),
        'name': string_descriptor(context.get('name')),
        'activeSelf': context.get('activeSelf'),
        'activeInHierarchy': context.get('activeInHierarchy'),
        'hierarchy': [string_descriptor(item) for item in hierarchy[:6]],
        'hierarchyTruncated': bool(context.get('hierarchyTruncated') or
                                   len(hierarchy) > 6),
        'componentTypes': [string_descriptor(item)
                           for item in component_types[:12]],
        'componentTypesTruncated': bool(context.get('componentsTruncated') or
                                        len(component_types) > 12),
        'scriptClasses': [string_descriptor(row.get('script', {}).get('className'))
                          for row in scripts[:10]],
        'canvasGroups': context.get('canvasGroups', [])[:4],
        'pointerCalls': pointer_calls[:12],
        'pointerCallsTruncated': len(pointer_calls) > 12,
    }


def bounded_payload(payload, max_chars=3800):
    """Shrink annotation payloads deterministically instead of failing CI."""
    candidate = copy.deepcopy(payload)
    def message():
        return annotation(json.dumps(candidate, separators=(',', ':')))
    if len(message()) <= max_chars:
        return message()
    if 'gameObjectContexts' in candidate:
        candidate.pop('gameObjectContexts')
        candidate['contextsOmitted'] = True
    if len(message()) <= max_chars:
        return message()
    details = candidate.get('objectDetails', [])
    original_count = len(details)
    for count in range(original_count, -1, -1):
        candidate['objectDetails'] = details[:count]
        candidate['objectDetailsOmitted'] = count < original_count
        if len(message()) <= max_chars:
            return message()
    for row in candidate.get('objectDetails', []):
        for key in ('payloadTokens', 'localPPtrCandidates', 'storedSchema',
                    'scriptDescriptor'):
            row.pop(key, None)
        row['nestedDetailsOmitted'] = True
    if len(message()) <= max_chars:
        return message()
    minimal = {'label': candidate.get('label'),
               'entry': candidate.get('entry'),
               'status': candidate.get('status'),
               'reason': candidate.get('reason'),
               'chunk': candidate.get('chunk'),
               'payloadOmitted': True}
    return annotation(json.dumps(minimal, separators=(',', ':')))


def emit_bounded(level, title, payload):
    print('::' + level + ' title=' + title + '::' + bounded_payload(payload))


def emit_chunked(level, title, payload, list_key, chunk_size=4):
    entries = payload.get(list_key, [])
    chunks = [entries[start:start + chunk_size]
              for start in range(0, len(entries), chunk_size)] or [[]]
    for number, part in enumerate(chunks, 1):
        item = dict(payload)
        item[list_key] = part
        item['chunk'] = [number, len(chunks)]
        emit_bounded(level, title + ' ' + str(number) + '/' + str(len(chunks)),
                     item)


def parse_asset(data):
    if len(data) > MAX_FILE:
        raise ValueError('Serialized file exceeds size bound')
    env = UnityPy.load(data)
    files = list(env.files.values())
    if len(files) != 1 or not isinstance(files[0], SerializedFile):
        raise ValueError('Expected one directly serialized Unity file')
    asset = files[0]
    if asset.header.file_size != len(data) or not 0 <= asset.header.data_offset <= len(data):
        raise ValueError('Invalid serialized file bounds')
    if len(asset.objects) > MAX_OBJECTS:
        raise ValueError('Object count exceeds bound')
    return asset


def intervals_for(asset, data):
    intervals = []
    offset = asset.header.data_offset
    for obj in asset.objects.values():
        start, size = obj.byte_start, obj.byte_size
        if start < offset or size < 0 or start + size > len(data):
            raise ValueError('Object extent out of file bounds')
        intervals.append((start, start + size, obj))
    return intervals


def classify(offset, length, data_offset, intervals):
    if offset + length <= data_offset:
        return 'pre-data', None
    matches = [obj for start, end, obj in intervals
               if start <= offset and offset + length <= end]
    if len(matches) == 1:
        return 'object', matches[0]
    return 'ambiguous-object' if matches else 'unmapped-data', None


def needle_matches(data, asset, intervals):
    lower = data.lower()
    results = {}
    object_ids = {}
    for label, needle in NEEDLES.items():
        term = needle.lower()
        count = 0
        samples = []
        position = 0
        while count < MAX_MATCHES:
            found = lower.find(term, position)
            if found < 0:
                break
            region, obj = classify(found, len(term), asset.header.data_offset,
                                   intervals)
            if obj is not None:
                object_ids.setdefault(obj.path_id, set()).add(label)
            if len(samples) < MAX_SAMPLES:
                row = {'offset': hex(found), 'region': region,
                       'needle': label}
                if obj is not None:
                    row.update({'objectPathId': obj.path_id,
                                'objectOffset': hex(obj.byte_start),
                                'objectSize': obj.byte_size,
                                'objectType': string_descriptor(obj.type.name)})
                samples.append(row)
            count += 1
            position = found + 1
        results[label] = {'count': count, 'samples': samples,
                          'samplesTruncated': count > len(samples),
                          'matchLimitReached': count >= MAX_MATCHES}
    return results, object_ids


def compact_schema(node):
    report = schema.schema(node)
    return {'available': report['available'],
            'topLevelCount': report.get('topLevelCount'),
            'fields': report.get('fields', []),
            'fieldsTruncated': report.get('fieldsTruncated'),
            'nodesVisited': report.get('nodesVisited'),
            'nodeLimitReached': report.get('nodeLimitReached')}


def aligned_payload_tokens(payload):
    locations = schema.aligned_serialized_string_locations(
        payload, limit=MAX_PAYLOAD_STRINGS)
    return [{'offset': row['offset'],
             'token': string_descriptor(row['value'])} for row in locations]


def local_pptr_candidates(payload, objects):
    locations = {row['offset']: row['value']
                 for row in schema.aligned_serialized_string_locations(
                     payload, limit=64)}
    samples = []
    truncated = False
    for offset in range(0, len(payload) - 12, 4):
        file_id = struct.unpack_from('<i', payload, offset)[0]
        if file_id != 0:
            continue
        path_id = struct.unpack_from('<q', payload, offset + 4)[0]
        target = objects.get(path_id)
        if target is None:
            continue
        row = {'offset': offset, 'targetPathId': path_id,
               'targetType': string_descriptor(target.type.name)}
        token = locations.get(offset + 16)
        if token is not None:
            row['methodToken'] = string_descriptor(token)
        if len(samples) < MAX_PPTR_CANDIDATES:
            samples.append(row)
        else:
            truncated = True
            break
    return {'count': len(samples), 'samples': samples,
            'truncated': truncated}


def monobehaviour_details(obj, asset, owner, script_asset, basename_unique,
                          script_cache):
    row = {'objectPathId': obj.path_id,
           'objectOffset': hex(obj.byte_start), 'objectSize': obj.byte_size,
           'status': 'parsed'}
    try:
        base = refs.get_typetree_node(114, obj.version)
        values = obj.read_typetree(nodes=base, check_read=False)
        ptr = values['m_Script']
        go = values['m_GameObject']
        file_id, script_id = ptr['m_FileID'], ptr['m_PathID']
        go_file, go_id = go['m_FileID'], go['m_PathID']
        resolution = refs.resolve(file_id, owner, asset.externals,
                                  refs.TARGET_FILE, basename_unique)
        row.update({'scriptFileId': file_id, 'scriptPathId': script_id,
                    'scriptLabel': string_descriptor(refs.TARGETS[script_id])
                    if script_id in refs.TARGETS else None,
                    'scriptResolution': string_descriptor(resolution),
                    'gameObjectFileId': go_file,
                    'gameObjectPathId': go_id})
        descriptor = None
        if resolution in ('same-file', 'external-basename-match'):
            target_asset = asset if resolution == 'same-file' else script_asset
            script_object = (target_asset.objects.get(script_id)
                             if target_asset is not None else None)
            if script_object is not None and script_object.type.name == 'MonoScript':
                descriptor = sanitize_value(schema._script_descriptor(script_object))
        row['scriptDescriptor'] = descriptor
        node = getattr(getattr(obj, 'serialized_type', None), 'node', None)
        row['storedSchema'] = compact_schema(node)
        payload = obj.get_raw_data()
        row['payloadTruncated'] = len(payload) > MAX_PAYLOAD
        bounded = payload[:MAX_PAYLOAD]
        row['payloadTokens'] = aligned_payload_tokens(bounded)
        row['localPPtrCandidates'] = local_pptr_candidates(bounded,
                                                           asset.objects)
        if go_file == 0:
            row['localGameObjectPathId'] = go_id
    except Exception as exc:
        row['status'] = 'parse-failed'
        row['reason'] = type(exc).__name__
    return row


def inspect_asset_bytes(data, owner, asset=None, script_asset=None,
                        basename_unique=True, script_cache=None):
    asset = asset if asset is not None else parse_asset(data)
    intervals = intervals_for(asset, data)
    needles, object_ids = needle_matches(data, asset, intervals)
    by_id = {obj.path_id: obj for obj in asset.objects.values()}
    details = []
    local_go_ids = []
    priority = {'get_it_now': 0, 'premium_unlocked': 1,
                'premium_capital': 2, 'premium_lower': 3}
    ordered_ids = sorted(
        object_ids,
        key=lambda path_id: (min(priority[label] for label in object_ids[path_id]),
                             path_id))
    for path_id in ordered_ids[:MAX_OBJECT_DETAILS]:
        obj = by_id.get(path_id)
        if obj is None:
            continue
        row = {'objectPathId': path_id,
               'needles': sorted(object_ids[path_id]),
               'objectType': string_descriptor(obj.type.name)}
        if obj.type.name == 'MonoBehaviour':
            row.update(monobehaviour_details(obj, asset, owner, script_asset,
                                             basename_unique,
                                             script_cache or {}))
            if row.get('localGameObjectPathId') is not None:
                local_go_ids.append(row['localGameObjectPathId'])
        elif obj.type.name == 'GameObject':
            local_go_ids.append(path_id)
        details.append(row)
    contexts = []
    for path_id in dict.fromkeys(local_go_ids):
        if len(contexts) >= MAX_CONTEXTS:
            break
        try:
            context = schema.game_object_context(
                asset, path_id, owner, script_asset, basename_unique,
                script_cache or {})
            if not context.get('available'):
                continue
            known_context = context.get('name') in {
                'Get It Now', 'premium_unlocked', 'premium_menu'}
            has_pointer_calls = any(
                button.get('localPPtrMatches')
                for button in context.get('buttonPPtrCandidates', []))
            if not known_context and not has_pointer_calls:
                continue
            contexts.append({'gameObjectPathId': path_id,
                             'context': compact_context(context)})
        except Exception as exc:
            contexts.append({'gameObjectPathId': path_id,
                             'context': {'available': False,
                                         'errorType': type(exc).__name__}})
    return {'entry': refs.safe_path(owner),
            'sha256': hashlib.sha256(data).hexdigest(),
            'fileBytes': len(data),
            'unityVersion': version_descriptor(str(asset.unity_version)),
            'formatVersion': asset.header.version,
            'dataOffset': asset.header.data_offset,
            'objectCount': len(asset.objects),
            'needles': needles,
            'objectDetails': details,
            'objectDetailsTruncated': len(object_ids) > len(details),
            'gameObjectContexts': contexts,
            'gameObjectContextsTruncated': len(set(local_go_ids)) > len(contexts),
            'parseErrorCount': sum(1 for row in details
                                   if row.get('status') == 'parse-failed')}


def inspect(path, expected_sha=EXPECTED_BASE_APK):
    sha = sha256_file(path)
    if expected_sha is not None and sha != expected_sha:
        raise ValueError('base.apk hash mismatch; refusing Premium Unity scan.')
    with zipfile.ZipFile(Path(path)) as apk:
        infos = apk.infolist()
        script_infos = [info for info in infos if info.filename == scripts.ENTRY]
        if len(script_infos) != 1 or script_infos[0].file_size > MAX_FILE:
            raise ValueError('Missing, duplicate or oversized MonoScript asset')
        script_data = apk.read(script_infos[0])
        validated = scripts.inspect_bytes(script_data)
        observed = {row['pathId']: row['className']
                    for row in validated['matchedIdentifiers']}
        if (observed != refs.TARGETS or validated['parseErrors'] or
                validated['candidateLimitReached'] or
                validated['oversizedCandidates']):
            raise ValueError('Premium MonoScript identities did not match prior observation')
        script_asset = parse_asset(script_data)
        basename_unique = sum(
            info.filename.rsplit('/', 1)[-1].lower() ==
            scripts.ENTRY.rsplit('/', 1)[-1].lower()
            for info in infos) == 1
        script_cache = {}
        files = []
        for selected in SELECTED_ENTRIES:
            matches = [info for info in infos if info.filename == selected['entry']]
            if len(matches) != 1:
                raise ValueError('Selected Premium asset missing or duplicated')
            info = matches[0]
            if info.file_size > MAX_FILE:
                raise ValueError('Selected Premium asset exceeds size bound')
            data = apk.read(info)
            if len(data) != info.file_size:
                raise ValueError('Short asset read')
            try:
                row = inspect_asset_bytes(data, selected['entry'],
                                          script_asset=script_asset,
                                          basename_unique=basename_unique,
                                          script_cache=script_cache)
                row.update({'label': selected['label'], 'status': 'parsed'})
            except Exception as exc:
                row = {'label': selected['label'],
                       'entry': refs.safe_path(selected['entry']),
                       'status': 'parse-failed',
                       'reason': type(exc).__name__}
            files.append(row)
    return {'kind': KIND, 'baseApkSha256': sha,
            'unityPyVersion': version_descriptor(str(UnityPy.__version__)),
            'scriptIdentityValidated': True,
            'scriptCandidateCount': validated['candidateCount'],
            'scriptParseErrorCount': len(validated['parseErrors']),
            'basenameUnique': basename_unique,
            'selectedEntries': [row['entry'] for row in SELECTED_ENTRIES],
            'files': files, 'limitations': LIMITATIONS}


def emit_annotations(report):
    if report.get('kind') != KIND:
        raise RuntimeError('Unexpected WorldBox Premium Unity asset report.')
    print('WorldBox full Premium Unity asset report: ' +
          json.dumps(report, separators=(',', ':')))
    rows = report['files']
    compact_files = [{
        'label': row.get('label'), 'entry': row.get('entry'),
        'status': row.get('status'), 'reason': row.get('reason'),
        'sha256': row.get('sha256'), 'fileBytes': row.get('fileBytes'),
        'objectCount': row.get('objectCount'),
        'needleCounts': {label: value['count']
                         for label, value in row.get('needles', {}).items()},
        'objectDetailCount': len(row.get('objectDetails', [])),
        'contextCount': len(row.get('gameObjectContexts', [])),
        'detailsTruncated': row.get('objectDetailsTruncated'),
        'contextsTruncated': row.get('gameObjectContextsTruncated'),
        'parseErrorCount': row.get('parseErrorCount')}
        for row in rows]
    emit_bounded('warning', 'WorldBox Premium Unity asset summary', {
        'baseApkSha256': report['baseApkSha256'],
        'unityPyVersion': report['unityPyVersion'],
        'scriptIdentityValidated': report['scriptIdentityValidated'],
        'scriptCandidateCount': report['scriptCandidateCount'],
        'scriptParseErrorCount': report['scriptParseErrorCount'],
        'basenameUnique': report['basenameUnique'],
        'files': compact_files})

    # Keep the exact Get It Now UnityEvent lead in a single high-priority
    # annotation; this one is the most diagnostic result of the asset model.
    primary = next((row for row in rows
                    if row.get('label') == 'get_it_now_primary'), None)
    if primary:
        target_context = next((item for item in primary.get('gameObjectContexts', [])
                               if item.get('context', {}).get('name') ==
                               {'safe': 'Get It Now'}), None)
        target_object = next((item for item in primary.get('objectDetails', [])
                              if item.get('objectType') == {'safe': 'GameObject'} and
                              'get_it_now' in item.get('needles', [])), None)
        emit_bounded('warning', 'WorldBox Premium Unity Get It Now lead', {
            'entry': primary['entry'], 'sha256': primary.get('sha256'),
            'needleCounts': {label: value['count'] for label, value in
                             primary.get('needles', {}).items()},
            'gameObject': target_object,
            'context': target_context,
            'detailsTruncated': primary.get('objectDetailsTruncated'),
            'limitations': 'Serialized component/PPtr/method-token adjacency only; not a fully decoded UnityEvent or proof of runtime entitlement behavior.'})

    unlocked = next((row for row in rows
                     if row.get('label') == 'premium_unlocked_1'), None)
    if unlocked:
        target_object = next((item for item in unlocked.get('objectDetails', [])
                              if item.get('objectType') == {'safe': 'GameObject'} and
                              'premium_unlocked' in item.get('needles', [])), None)
        target_context = next((item for item in unlocked.get('gameObjectContexts', [])
                               if item.get('context', {}).get('name') ==
                               {'safe': 'premium_unlocked'}), None)
        associated = [item for item in unlocked.get('objectDetails', [])
                      if item.get('objectType') == {'safe': 'MonoBehaviour'}]
        emit_bounded('notice', 'WorldBox Premium Unity premium_unlocked lead', {
            'entry': unlocked['entry'], 'sha256': unlocked.get('sha256'),
            'needleCounts': {label: value['count'] for label, value in
                             unlocked.get('needles', {}).items()},
            'gameObject': target_object, 'context': target_context,
            'associatedMonoBehaviours': [{key: item.get(key) for key in
                ('objectPathId', 'objectOffset', 'objectSize', 'scriptPathId',
                 'scriptResolution', 'gameObjectPathId', 'storedSchema')}
                for item in associated],
            'detailsTruncated': unlocked.get('objectDetailsTruncated'),
            'contextsTruncated': unlocked.get('gameObjectContextsTruncated'),
            'limitations': 'Static serialized associations only; no entitlement method or safe patch is established.'})


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('base_apk')
    parser.add_argument('--expected-sha', default=EXPECTED_BASE_APK)
    args = parser.parse_args()
    try:
        report = inspect(args.base_apk, args.expected_sha)
    except Exception as exc:
        print(f'Premium Unity asset probe failed: {type(exc).__name__}: {exc}',
              file=sys.stderr)
        return 1
    print(json.dumps(report, separators=(',', ':')))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

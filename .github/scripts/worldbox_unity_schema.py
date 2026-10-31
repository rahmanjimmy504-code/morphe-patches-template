#!/usr/bin/env python3
"""Inspect stored type-tree schemas of selected Premium component candidates.

Only serialized schema identifiers and common base references are emitted;
no game-specific field values, method bodies, or asset bytes are exported.
"""
import json
from pathlib import Path
import re
import sys
import zipfile
import UnityPy
from UnityPy.files.SerializedFile import SerializedFile
import worldbox_unity_scripts as scripts
import worldbox_unity_script_refs as refs

SPECS = {
    'assets/bin/Data/13cfff6f881b80049833c82202d4227a': {1641: 2449, 1700: 1116},
    'assets/bin/Data/7c7dd69ec9c748445ac2b5ecff11e69f': {1745: 2449, 1109: 1116, 1688: 888},
}
MAX_FILE = 32 * 1024 * 1024
MAX_NODES = 2048
MAX_FIELDS = 48
SAFE_NAME = re.compile(r'[A-Za-z_][A-Za-z0-9_.+\[\]]{0,127}\Z', re.ASCII)
SAFE_TYPE = re.compile(r'[A-Za-z_][A-Za-z0-9_.+<>\[\], *-]{0,127}\Z', re.ASCII)


def schema(root):
    if root is None:
        return {'available': False}
    children = getattr(root, 'm_Children', None) or []
    fields = []
    for node in children[:MAX_FIELDS]:
        name, kind = getattr(node, 'm_Name', None), getattr(node, 'm_Type', None)
        fields.append({'name': name if isinstance(name, str) and SAFE_NAME.fullmatch(name) else None,
                       'type': kind if isinstance(kind, str) and SAFE_TYPE.fullmatch(kind) else None})
    stack, seen = [root], 0
    while stack and seen < MAX_NODES:
        node = stack.pop()
        seen += 1
        stack.extend(getattr(node, 'm_Children', None) or [])
    return {'available': True, 'topLevelCount': len(children), 'fields': fields,
            'fieldsTruncated': len(children) > len(fields),
            'nodesVisited': seen, 'nodeLimitReached': bool(stack)}


def inspect_bytes(data, owner, expected, basename_unique=True):
    if len(data) > MAX_FILE:
        raise ValueError('Serialized file exceeds size bound')
    env = UnityPy.load(data)
    files = list(env.files.values())
    if len(files) != 1 or not isinstance(files[0], SerializedFile):
        raise ValueError('Expected one directly serialized Unity file')
    asset = files[0]
    if asset.header.file_size != len(data) or not 0 <= asset.header.data_offset <= len(data):
        raise ValueError('Invalid serialized file bounds')
    rows = []
    for path_id, expected_script in expected.items():
        obj = asset.objects.get(path_id)
        if obj is None or obj.type.name != 'MonoBehaviour':
            raise ValueError('Selected MonoBehaviour not found')
        if obj.byte_start < asset.header.data_offset or obj.byte_size < 0 or obj.byte_start + obj.byte_size > len(data):
            raise ValueError('Selected MonoBehaviour extent out of bounds')
        base = refs.get_typetree_node(114, obj.version)
        values = obj.read_typetree(nodes=base, check_read=False)
        ptr = values['m_Script']
        file_id, script_id = ptr['m_FileID'], ptr['m_PathID']
        if not isinstance(file_id, int) or script_id != expected_script or script_id not in refs.TARGETS:
            raise ValueError('Selected script pointer does not match prior candidate')
        resolution = refs.resolve(file_id, owner, asset.externals, refs.TARGET_FILE, basename_unique)
        if resolution not in ('same-file', 'external-basename-match'):
            raise ValueError('Selected script pointer does not resolve to expected basename')
        go = values['m_GameObject']
        go_file, go_id = go['m_FileID'], go['m_PathID']
        if not isinstance(go_file, int) or not isinstance(go_id, int):
            raise ValueError('Invalid GameObject pointer')
        node = getattr(obj.serialized_type, 'node', None) if obj.serialized_type is not None else None
        rows.append({'objectPathId': path_id, 'scriptPathId': script_id,
                     'script': refs.TARGETS[script_id], 'scriptResolution': resolution,
                     'gameObjectFileId': go_file, 'gameObjectPathId': go_id,
                     'objectSize': obj.byte_size, 'schema': schema(node)})
    return {'entry': refs.safe_path(owner), 'unityVersion': asset.unity_version, 'objects': rows}


def inspect(path):
    with zipfile.ZipFile(Path(path)) as apk:
        infos = apk.infolist()
        target = [i for i in infos if i.filename == scripts.ENTRY]
        if len(target) != 1 or target[0].file_size > MAX_FILE:
            raise ValueError('Missing, duplicate or oversized MonoScript asset')
        validated = scripts.inspect_bytes(apk.read(target[0]))
        observed = {x['pathId']: x['className'] for x in validated['matchedIdentifiers']}
        if observed != refs.TARGETS or validated['parseErrors'] or validated['candidateLimitReached'] or validated['oversizedCandidates']:
            raise ValueError('Premium script identities did not match prior observation')
        unique = sum(i.filename.rsplit('/', 1)[-1].lower() == scripts.ENTRY.rsplit('/', 1)[-1].lower() for i in infos) == 1
        reports = []
        for name, expected in SPECS.items():
            matches = [i for i in infos if i.filename == name]
            if len(matches) != 1 or matches[0].file_size > MAX_FILE:
                raise ValueError('Selected asset is missing, duplicated or oversized')
            data = apk.read(matches[0])
            if len(data) != matches[0].file_size:
                raise ValueError('Short asset read')
            reports.append(inspect_bytes(data, name, expected, basename_unique=unique))
    return {'kind': 'worldbox-unity-schema-leads', 'unityPyVersion': UnityPy.__version__, 'files': reports}


if __name__ == '__main__':
    print(json.dumps(inspect(Path(sys.argv[1])), separators=(',', ':')))

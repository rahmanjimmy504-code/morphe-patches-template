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
SAFE_OBJECT_NAME = re.compile(r'[A-Za-z0-9 _().+-]{1,128}\Z', re.ASCII)
MAX_HIERARCHY = 8
MAX_COMPONENTS = 32


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


def _path_id(pointer):
    if not isinstance(pointer, dict):
        return None
    path_id = pointer.get('m_PathID')
    return path_id if isinstance(path_id, int) and path_id > 0 else None


def _script_descriptor(script_object):
    try:
        script = script_object.read()
    except Exception:
        return None
    fields = {
        'name': scripts.safe(getattr(script, 'm_Name', None), scripts.NAME),
        'className': scripts.safe(getattr(script, 'm_ClassName', None), scripts.NAME),
        'namespace': '' if getattr(script, 'm_Namespace', None) == '' else
                     scripts.safe(getattr(script, 'm_Namespace', None), scripts.NAMESPACE),
        'assembly': scripts.safe(getattr(script, 'm_AssemblyName', None), scripts.ASSEMBLY),
    }
    return fields if fields['name'] or fields['className'] else None


def _component_script(asset, component, owner, script_asset, basename_unique, cache):
    if owner is None:
        return None
    try:
        base = refs.get_typetree_node(114, component.version)
        values = component.read_typetree(nodes=base, check_read=False)
        pointer = values.get('m_Script')
        script_id = _path_id(pointer)
        file_id = pointer.get('m_FileID') if isinstance(pointer, dict) else None
        if script_id is None or not isinstance(file_id, int):
            return None
        if file_id == 0:
            target_asset = asset
        else:
            resolution = refs.resolve(file_id, owner, asset.externals, refs.TARGET_FILE, basename_unique)
            target_asset = script_asset if resolution == 'external-basename-match' else None
        if target_asset is None:
            return None
        key = (id(target_asset), script_id)
        if key not in cache:
            script_object = target_asset.objects.get(script_id)
            cache[key] = (_script_descriptor(script_object)
                          if script_object is not None and script_object.type.name == 'MonoScript' else None)
        return cache[key]
    except Exception:
        return None


def game_object_context(asset, game_object_path_id, owner=None, script_asset=None,
                        basename_unique=True, script_cache=None):
    """Return bounded hierarchy and script labels for a known local owner."""
    game_object = asset.objects.get(game_object_path_id)
    if game_object is None or game_object.type.name != 'GameObject':
        return {'available': False}
    try:
        values = game_object.read_typetree(check_read=False)
        raw_name = values.get('m_Name')
        name = raw_name if isinstance(raw_name, str) and SAFE_OBJECT_NAME.fullmatch(raw_name) else None
        components = values.get('m_Component', [])
        if not isinstance(components, list):
            components = []
        component_types = []
        component_scripts = []
        transform = None
        script_cache = script_cache if script_cache is not None else {}
        for index, item in enumerate(components[:MAX_COMPONENTS]):
            if not isinstance(item, dict):
                continue
            component_id = _path_id(item.get('component', item))
            component = asset.objects.get(component_id) if component_id is not None else None
            if component is None:
                continue
            type_name = component.type.name
            if isinstance(type_name, str) and SAFE_TYPE.fullmatch(type_name):
                component_types.append(type_name)
            if type_name == 'MonoBehaviour':
                descriptor = _component_script(asset, component, owner, script_asset,
                                               basename_unique, script_cache)
                if descriptor:
                    stored_type_tree = getattr(getattr(component, 'serialized_type', None), 'node', None)
                    component_scripts.append({'index': index, 'script': descriptor,
                                              'storedSchema': schema(stored_type_tree)})
            if type_name in ('Transform', 'RectTransform'):
                transform = component
        hierarchy = [name] if name else []
        seen_transforms = set()
        hierarchy_truncated = False
        for level in range(MAX_HIERARCHY - 1):
            if transform is None:
                break
            transform_id = getattr(transform, 'path_id', None)
            if transform_id in seen_transforms:
                break
            if transform_id is not None:
                seen_transforms.add(transform_id)
            transform_values = transform.read_typetree(check_read=False)
            parent_id = _path_id(transform_values.get('m_Father'))
            parent_transform = asset.objects.get(parent_id) if parent_id is not None else None
            if parent_transform is None:
                break
            parent_transform_id = getattr(parent_transform, 'path_id', parent_id)
            if parent_transform_id in seen_transforms:
                break
            parent_values = parent_transform.read_typetree(check_read=False)
            parent_go_id = _path_id(parent_values.get('m_GameObject'))
            parent_go = asset.objects.get(parent_go_id) if parent_go_id is not None else None
            if parent_go is None or parent_go.type.name != 'GameObject':
                break
            parent_go_values = parent_go.read_typetree(check_read=False)
            parent_name = parent_go_values.get('m_Name')
            if isinstance(parent_name, str) and SAFE_OBJECT_NAME.fullmatch(parent_name):
                hierarchy.append(parent_name)
            transform = parent_transform
            if level == MAX_HIERARCHY - 2:
                hierarchy_truncated = True
        return {'available': True, 'name': name, 'hierarchy': hierarchy,
                'hierarchyTruncated': hierarchy_truncated,
                'componentTypes': component_types[:MAX_COMPONENTS],
                'componentScripts': component_scripts[:MAX_COMPONENTS],
                'componentsTruncated': len(components) > MAX_COMPONENTS}
    except Exception:
        return {'available': False}


def inspect_bytes(data, owner, expected, basename_unique=True, script_asset=None, script_cache=None):
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
                     'ownerContext': game_object_context(asset, go_id, owner, script_asset,
                                                       basename_unique, script_cache)
                                     if go_file == 0 else {'available': False},
                     'objectSize': obj.byte_size, 'schema': schema(node)})
    return {'entry': refs.safe_path(owner), 'unityVersion': asset.unity_version, 'objects': rows}


def inspect(path):
    with zipfile.ZipFile(Path(path)) as apk:
        infos = apk.infolist()
        target = [i for i in infos if i.filename == scripts.ENTRY]
        if len(target) != 1 or target[0].file_size > MAX_FILE:
            raise ValueError('Missing, duplicate or oversized MonoScript asset')
        script_data = apk.read(target[0])
        validated = scripts.inspect_bytes(script_data)
        observed = {x['pathId']: x['className'] for x in validated['matchedIdentifiers']}
        if observed != refs.TARGETS or validated['parseErrors'] or validated['candidateLimitReached'] or validated['oversizedCandidates']:
            raise ValueError('Premium script identities did not match prior observation')
        script_env = UnityPy.load(script_data)
        script_files = list(script_env.files.values())
        if len(script_files) != 1 or not isinstance(script_files[0], SerializedFile):
            raise ValueError('Expected one directly serialized MonoScript asset')
        script_asset = script_files[0]
        unique = sum(i.filename.rsplit('/', 1)[-1].lower() == scripts.ENTRY.rsplit('/', 1)[-1].lower() for i in infos) == 1
        script_cache = {}
        reports = []
        for name, expected in SPECS.items():
            matches = [i for i in infos if i.filename == name]
            if len(matches) != 1 or matches[0].file_size > MAX_FILE:
                raise ValueError('Selected asset is missing, duplicated or oversized')
            data = apk.read(matches[0])
            if len(data) != matches[0].file_size:
                raise ValueError('Short asset read')
            reports.append(inspect_bytes(data, name, expected, basename_unique=unique,
                                         script_asset=script_asset, script_cache=script_cache))
    return {'kind': 'worldbox-unity-schema-leads', 'unityPyVersion': UnityPy.__version__, 'files': reports}


if __name__ == '__main__':
    print(json.dumps(inspect(Path(sys.argv[1])), separators=(',', ':')))

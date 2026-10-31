#!/usr/bin/env python3
"""Read bounded Premium-related MonoScript identifiers, not executable code.

A MonoScript asset records script metadata; an identifier does not prove the
class's behavior or provide IL2CPP method bodies or native addresses.
"""
import hashlib
import json
from pathlib import Path
import re
import sys
import zipfile
import UnityPy
from UnityPy.files.SerializedFile import SerializedFile

ENTRY = 'assets/bin/Data/globalgamemanagers.assets'
MAX_FILE = 32 * 1024 * 1024
MAX_OBJECTS = 200000
MAX_OBJECT_SIZE = 4096
MAX_CANDIDATES = 100
NAME = re.compile(r'[A-Za-z_][A-Za-z0-9_+]{0,127}\Z', re.ASCII)
NAMESPACE = re.compile(r'[A-Za-z_][A-Za-z0-9_.+]{0,127}\Z', re.ASCII)
ASSEMBLY = re.compile(r'[A-Za-z_][A-Za-z0-9_.-]{0,127}\Z', re.ASCII)


def safe(value, pattern):
    return value if isinstance(value, str) and pattern.fullmatch(value) else None


def identifiers(script):
    """Expose only validated identifiers when script/class name contains premium."""
    name = getattr(script, 'm_Name', None)
    cls = getattr(script, 'm_ClassName', None)
    related = any(isinstance(x, str) and 'premium' in x.lower() for x in (name, cls))
    if not related:
        return None
    namespace = getattr(script, 'm_Namespace', None)
    return {'scriptName': safe(name, NAME), 'className': safe(cls, NAME),
            'namespace': '' if namespace == '' else safe(namespace, NAMESPACE),
            'assembly': safe(getattr(script, 'm_AssemblyName', None), ASSEMBLY)}


def inspect_bytes(data):
    if len(data) > MAX_FILE:
        raise ValueError('Serialized file exceeds size bound')
    env = UnityPy.load(data)
    files = list(env.files.values())
    if len(files) != 1 or not isinstance(files[0], SerializedFile):
        raise ValueError('Expected one directly serialized Unity file')
    asset = files[0]
    if asset.header.file_size != len(data) or not 0 <= asset.header.data_offset <= len(data):
        raise ValueError('Invalid serialized file size or data offset')
    objects = list(asset.objects.values())
    if len(objects) > MAX_OBJECTS:
        raise ValueError('Object count exceeds bound')
    candidates = []
    for obj in objects:
        if obj.type.name != 'MonoScript':
            continue
        lo, size = obj.byte_start, obj.byte_size
        if lo < asset.header.data_offset or size < 0 or lo + size > len(data):
            raise ValueError('MonoScript extent out of bounds')
        if b'premium' in data[lo:lo + size].lower():
            candidates.append(obj)
    result = []
    errors = []
    skipped = 0
    for obj in candidates[:MAX_CANDIDATES]:
        if obj.byte_size > MAX_OBJECT_SIZE:
            skipped += 1
            continue
        try:
            info = identifiers(obj.read())
        except Exception as exc:
            errors.append({'pathId': obj.path_id, 'errorType': type(exc).__name__})
            continue
        if info is not None:
            result.append({'pathId': obj.path_id, **info})
    return {'kind': 'worldbox-premium-monoscripts', 'unityVersion': asset.unity_version,
            'fileBytes': len(data), 'objectCount': len(objects), 'candidateCount': len(candidates),
            'candidateLimitReached': len(candidates) > MAX_CANDIDATES,
            'oversizedCandidates': skipped, 'parseErrors': errors,
            'matchedIdentifiers': result}


def inspect(path):
    with Path(path).open('rb') as f:
        sha = hashlib.file_digest(f, 'sha256').hexdigest()
    with zipfile.ZipFile(path) as apk:
        entries = [i for i in apk.infolist() if i.filename == ENTRY]
        if len(entries) != 1 or entries[0].file_size > MAX_FILE:
            raise ValueError('Missing, duplicate or oversized selected asset')
        data = apk.read(entries[0])
        if len(data) != entries[0].file_size:
            raise ValueError('Short asset read')
    return {'baseApkSha256': sha, 'unityPyVersion': UnityPy.__version__, **inspect_bytes(data)}


if __name__ == '__main__':
    print(json.dumps(inspect(Path(sys.argv[1])), separators=(',', ':')))

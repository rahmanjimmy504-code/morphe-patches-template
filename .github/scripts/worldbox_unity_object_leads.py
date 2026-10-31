#!/usr/bin/env python3
"""Map predefined keyword offsets to Unity serialized object extents.

Uses UnityPy's structural parser only; does not execute the game or export
strings, object contents, binaries, or a patched asset. Mapping an offset to an
object is not proof that the byte sequence is a field or an entitlement.
"""
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys
import zipfile
import UnityPy
from UnityPy.files.SerializedFile import SerializedFile

ENTRIES = ('assets/bin/Data/globalgamemanagers', 'assets/bin/Data/globalgamemanagers.assets')
TERMS = {'premium': b'premium', 'purchase': b'purchase', 'product': b'product'}
MAX_SIZE = 32 * 1024 * 1024
MAX_OBJECTS = 200000
MAX_MATCHES = 20000
MAX_SAMPLES = 8


def classify(offset, length, data_offset, intervals):
    if offset + length <= data_offset:
        return ('pre-data', None)
    matches = [obj for start, end, obj in intervals if start <= offset and offset + length <= end]
    if len(matches) == 1:
        return ('object', matches[0])
    return ('ambiguous-object' if matches else 'unmapped-data', None)


def inspect_bytes(data):
    if len(data) > MAX_SIZE:
        raise ValueError('Asset exceeds size bound')
    env = UnityPy.load(data)
    files = list(env.files.values())
    if len(files) != 1 or not isinstance(files[0], SerializedFile):
        raise ValueError('Expected one directly serialized Unity file')
    asset = files[0]
    if asset.header.file_size != len(data) or not (0 <= asset.header.data_offset <= len(data)):
        raise ValueError('Serialized file size or data offset invalid')
    objects = list(asset.objects.values())
    if len(objects) > MAX_OBJECTS:
        raise ValueError('Object count exceeds bound')
    intervals = []
    for obj in objects:
        start, size = obj.byte_start, obj.byte_size
        if start < asset.header.data_offset or size < 0 or start + size > len(data):
            raise ValueError('Object extent out of file bounds')
        intervals.append((start, start + size, obj))
    lower = data.lower()
    categories = {}
    for category, term in TERMS.items():
        offset = 0
        total = 0
        groups = Counter()
        examples = []
        while True:
            offset = lower.find(term, offset)
            if offset < 0:
                break
            if total == MAX_MATCHES:
                break
            region, obj = classify(offset, len(term), asset.header.data_offset, intervals)
            type_name = obj.type.name if obj is not None else None
            key = region + (':' + type_name if type_name else '')
            groups[key] += 1
            if len(examples) < MAX_SAMPLES:
                sample = {'offset': offset, 'region': region}
                if obj is not None:
                    sample.update({'class': type_name, 'pathId': obj.path_id,
                                   'objectOffset': obj.byte_start, 'objectSize': obj.byte_size})
                examples.append(sample)
            total += 1
            offset += 1
        categories[category] = {'count': total, 'matchLimitReached': offset >= 0,
                                'groups': dict(sorted(groups.items())), 'samples': examples,
                                'samplesTruncated': total > len(examples)}
    return {'formatVersion': asset.header.version, 'unityVersion': asset.unity_version,
            'fileBytes': len(data), 'dataOffset': asset.header.data_offset,
            'objectCount': len(objects), 'categories': categories}


def inspect(path):
    with Path(path).open('rb') as f:
        sha = hashlib.file_digest(f, 'sha256').hexdigest()
    reports = []
    with zipfile.ZipFile(path) as apk:
        for name in ENTRIES:
            infos = [i for i in apk.infolist() if i.filename == name]
            if len(infos) != 1:
                raise ValueError('Expected exactly one selected APK entry')
            info = infos[0]
            if info.file_size > MAX_SIZE:
                raise ValueError('Selected APK entry exceeds size bound')
            data = apk.read(info)
            if len(data) != info.file_size:
                raise ValueError('Short APK entry read')
            reports.append({'entry': name, **inspect_bytes(data)})
    return {'kind': 'worldbox-unity-object-leads', 'baseApkSha256': sha,
            'unityPyVersion': UnityPy.__version__, 'entries': reports}


if __name__ == '__main__':
    print(json.dumps(inspect(Path(sys.argv[1])), separators=(',', ':')))

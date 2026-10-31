#!/usr/bin/env python3
"""Find bounded serialized MonoBehaviour pointers to known Premium MonoScripts.

Uses only Unity's common MonoBehaviour base fields. External basename matching
is a clue, not identity proof. Does not decode user fields or execute code.
"""
from collections import Counter
import importlib
import json
from pathlib import Path
import re
import sys
import zipfile
import UnityPy
from UnityPy.files.SerializedFile import SerializedFile
import worldbox_unity_scripts as scripts

TARGETS = {77: 'WindowPremiumRestoreHelper', 640: 'TopPremiumButtonMover',
           888: 'PremiumUnlockAnimation', 1116: 'ButtonPremium',
           1559: 'PremiumElementsChecker', 2449: 'PremiumWindow'}
TARGET_FILE = scripts.ENTRY
MAX_FILE = 32 * 1024 * 1024
MAX_TOTAL = 128 * 1024 * 1024
MAX_FILES = 128
MAX_OBJECTS = 200000
MAX_BEHAVIOURS = 100000
MAX_SAMPLES = 24
get_typetree_node = importlib.import_module('UnityPy.files.ObjectReader').get_typetree_node


def selected(name):
    lower = name.lower()
    if not lower.startswith('assets/bin/data/'):
        return False
    base = lower.rsplit('/', 1)[-1]
    return base == 'globalgamemanagers' or base.endswith('.assets') or re.fullmatch(r'level[0-9]+', base) is not None


def safe_path(name):
    return name if re.fullmatch(r'[A-Za-z0-9_./-]{1,240}', name, re.ASCII) else '<redacted>'


def resolve(file_id, owner, externals, target_name, basename_unique):
    if file_id == 0:
        return 'same-file' if owner == target_name else 'other-file'
    if file_id < 0 or file_id > len(externals):
        return 'unresolved-file-id'
    path = externals[file_id - 1].path.replace('\\', '/')
    base = path.rsplit('/', 1)[-1].lower()
    if base == target_name.rsplit('/', 1)[-1].lower():
        return 'external-basename-match' if basename_unique else 'unresolved-ambiguous-basename'
    # CAB paths can resolve through Unity's archive registry; no resolver here.
    if base.startswith('cab-') or not base:
        return 'unresolved-external'
    return 'other-file'


def inspect_bytes(data, owner, targets=TARGETS, basename_unique=True, max_size=MAX_FILE):
    if len(data) > max_size:
        raise ValueError('Serialized file exceeds size bound')
    env = UnityPy.load(data)
    files = list(env.files.values())
    if len(files) != 1 or not isinstance(files[0], SerializedFile):
        raise ValueError('Expected one directly serialized Unity file')
    asset = files[0]
    if asset.header.file_size != len(data) or not 0 <= asset.header.data_offset <= len(data):
        raise ValueError('Invalid serialized file bounds')
    objects = list(asset.objects.values())
    if len(objects) > MAX_OBJECTS:
        raise ValueError('Too many serialized objects')
    behaviours = [obj for obj in objects if obj.type.name == 'MonoBehaviour']
    errors = Counter()
    counts = Counter()
    matches = []
    for obj in behaviours[:MAX_BEHAVIOURS]:
        if obj.byte_start < asset.header.data_offset or obj.byte_size < 0 or obj.byte_start + obj.byte_size > len(data):
            errors['invalid-extent'] += 1
            continue
        try:
            # Passing explicit base type prevents generation of game-specific fields.
            base = get_typetree_node(114, obj.version)
            values = obj.read_typetree(nodes=base, check_read=False)
            ptr = values['m_Script']
            file_id, path_id = ptr['m_FileID'], ptr['m_PathID']
            if not isinstance(file_id, int) or not isinstance(path_id, int):
                raise ValueError('Invalid script pointer')
        except Exception as exc:
            errors[type(exc).__name__] += 1
            continue
        if path_id not in targets:
            continue
        resolution = resolve(file_id, owner, asset.externals, TARGET_FILE, basename_unique)
        counts[resolution] += 1
        if len(matches) < MAX_SAMPLES:
            matches.append({'objectPathId': obj.path_id, 'scriptPathId': path_id,
                            'script': targets[path_id], 'fileId': file_id, 'resolution': resolution})
    return {'entry': safe_path(owner), 'bytes': len(data), 'unityVersion': asset.unity_version,
            'objectCount': len(objects), 'monoBehaviourCount': len(behaviours),
            'behaviourLimitReached': len(behaviours) > MAX_BEHAVIOURS,
            'parseErrors': dict(errors), 'candidateCounts': dict(counts),
            'samplesTruncated': sum(counts.values()) > len(matches), 'samples': matches}


def inspect(path):
    reports, skipped = [], []
    with zipfile.ZipFile(Path(path)) as apk:
        infos = [i for i in apk.infolist() if selected(i.filename) and not i.is_dir()]
        targets = [i for i in infos if i.filename == TARGET_FILE]
        if len(targets) != 1 or targets[0].file_size > MAX_FILE:
            raise ValueError('Missing, duplicate or oversized script asset')
        target_data = apk.read(targets[0])
        validated = scripts.inspect_bytes(target_data)
        observed = {x['pathId']: x['className'] for x in validated['matchedIdentifiers']}
        if observed != TARGETS or validated['parseErrors'] or validated['candidateLimitReached'] or validated['oversizedCandidates']:
            raise ValueError('Premium script identities did not match prior observation')
        basename_unique = sum(i.filename.rsplit('/', 1)[-1].lower() == TARGET_FILE.rsplit('/', 1)[-1].lower() for i in infos) == 1
        total_bytes = 0
        for info in sorted(infos, key=lambda i: i.filename)[:MAX_FILES]:
            if info.file_size > MAX_FILE or total_bytes + info.file_size > MAX_TOTAL:
                skipped.append({'entry': safe_path(info.filename), 'reason': 'size-limit'})
                continue
            data = apk.read(info)
            if len(data) != info.file_size: raise ValueError('Short ZIP entry')
            total_bytes += len(data)
            try:
                reports.append(inspect_bytes(data, info.filename, basename_unique=basename_unique))
            except Exception as exc:
                skipped.append({'entry': safe_path(info.filename), 'reason': type(exc).__name__})
        return {'kind': 'worldbox-unity-script-references', 'unityPyVersion': UnityPy.__version__,
                'eligibleFiles': len(infos), 'filesAnalyzed': len(reports),
                'fileLimitReached': len(infos) > MAX_FILES, 'bytesRead': total_bytes,
                'basenameUnique': basename_unique, 'skipped': skipped, 'files': reports}


if __name__ == '__main__':
    print(json.dumps(inspect(Path(sys.argv[1])), separators=(',', ':')))

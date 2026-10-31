#!/usr/bin/env python3
"""Bounded search for one MonoScript pointer in serialized APK entries.

64-bit little-endian path-ID prefilter is not itself evidence of a pointer.
All prefilter hits are rechecked as MonoBehaviour base fields where budget
permits; external CAB references remain explicitly unresolved.
"""
from collections import Counter
import json
from pathlib import Path
import struct
import sys
import zipfile
import worldbox_bundle_inventory as inventory
import worldbox_unity_scripts as scripts
import worldbox_unity_script_refs as refs

TARGET_ID = 1559
TARGET_NAME = 'PremiumElementsChecker'
NEEDLE = struct.pack('<q', TARGET_ID)
MAX_FILE = 64 * 1024 * 1024
MAX_TOTAL = 1024 * 1024 * 1024
MAX_ENTRIES = 15000
MAX_PARSE = 500
MAX_SAMPLES = 24


def needs_parser(data):
    version = struct.unpack_from('>I', data, 8)[0]
    # Older and big-endian serialized files do not match our 64-bit LE filter.
    return version < 14 or len(data) <= 16 or data[16] != 0 or NEEDLE in data


def inspect(path):
    with zipfile.ZipFile(Path(path)) as apk:
        selected = [i for i in apk.infolist() if not i.is_dir() and i.filename.lower().startswith('assets/bin/data/')]
        all_infos = apk.infolist()
        target_infos = [i for i in all_infos if i.filename == scripts.ENTRY]
        if len(target_infos) != 1 or target_infos[0].file_size > scripts.MAX_FILE:
            raise ValueError('Missing, duplicate or oversized script asset')
        verified = scripts.inspect_bytes(apk.read(target_infos[0]))
        observed = {x['pathId']: x['className'] for x in verified['matchedIdentifiers']}
        if observed != refs.TARGETS or verified['parseErrors'] or verified['candidateLimitReached'] or verified['oversizedCandidates']:
            raise ValueError('Premium script identities did not match prior observation')
        unique = sum(i.filename.rsplit('/', 1)[-1].lower() == scripts.ENTRY.rsplit('/', 1)[-1].lower() for i in all_infos) == 1
        totals = Counter()
        errors = Counter()
        results = []
        # Smaller serialized files first so a byte cap does not hide them behind
        # one large resource. Every omitted file/byte is counted, not guessed.
        ordered = sorted(selected, key=lambda item: (item.file_size, item.filename))
        for info in ordered[:MAX_ENTRIES]:
            if info.flag_bits & 1:
                errors['encrypted'] += 1
                continue
            try:
                with apk.open(info) as f:
                    head = f.read(min(inventory.HEADER, info.file_size))
                if len(head) != min(inventory.HEADER, info.file_size):
                    raise ValueError('short header')
            except Exception as exc:
                errors['header-' + type(exc).__name__] += 1
                continue
            if inventory.classify(head, info.file_size, info.filename) != 'serialized-file-candidate':
                continue
            totals['serializedCandidates'] += 1
            totals['serializedBytes'] += info.file_size
            if info.file_size > MAX_FILE or totals['bytesScanned'] + info.file_size > MAX_TOTAL:
                totals['sizeBudgetSkipped'] += 1
                totals['sizeBudgetSkippedBytes'] += info.file_size
                continue
            try:
                data = apk.read(info)
                if len(data) != info.file_size:
                    raise ValueError('short entry')
            except Exception as exc:
                errors['read-' + type(exc).__name__] += 1
                continue
            totals['filesScanned'] += 1
            totals['bytesScanned'] += len(data)
            # Legacy and big-endian files bypass the little-endian prefilter.
            if not needs_parser(data):
                continue
            totals['rawCandidateFiles'] += 1
            if totals['filesParsed'] >= MAX_PARSE:
                totals['parseBudgetSkipped'] += 1
                continue
            totals['filesParsed'] += 1
            try:
                report = refs.inspect_bytes(data, info.filename, targets={TARGET_ID: TARGET_NAME}, basename_unique=unique, max_size=MAX_FILE)
            except Exception as exc:
                errors['parse-' + type(exc).__name__] += 1
                continue
            totals['monoBehavioursParsed'] += min(report['monoBehaviourCount'], refs.MAX_BEHAVIOURS)
            if report['behaviourLimitReached']:
                totals['behaviourLimitFiles'] += 1
            for kind, count in report['parseErrors'].items():
                errors['base-field-' + kind] += count
            for kind, count in report['candidateCounts'].items():
                totals['references-' + kind] += count
            if report['samplesTruncated']:
                totals['sampleTruncatedFiles'] += 1
            if report['samples']:
                totals['filesWithReferences'] += 1
            if report['samples'] and len(results) < MAX_SAMPLES:
                results.append({'entry': report['entry'], 'candidateCounts': report['candidateCounts'],
                                'samplesTruncated': report['samplesTruncated'], 'samples': report['samples']})
        return {'kind': 'worldbox-guid-script-references', 'target': TARGET_NAME, 'pathId': TARGET_ID,
                'assetsEntries': len(selected), 'entryLimitReached': len(selected) > MAX_ENTRIES,
                'basenameUnique': unique, 'totals': dict(totals), 'errors': dict(errors),
                'resultFiles': results, 'resultSampleLimit': MAX_SAMPLES,
                'resultFilesTruncated': totals['filesWithReferences'] > len(results)}


if __name__ == '__main__':
    print(json.dumps(inspect(Path(sys.argv[1])), separators=(',', ':')))

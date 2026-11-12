#!/usr/bin/env python3
"""Bounded, hash-gated string-neighborhood model for WorldBox metadata.

The probe examines a fixed window around the observed plaintext
`premium_unlocked` offset. It emits aggregate counts, safe predefined labels,
offsets and SHA-256 hashes for nearby tokens; unknown strings and raw metadata
bytes are never emitted. It does not claim to parse IL2CPP metadata.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import struct
import sys
from pathlib import Path

from worldbox_bounded_reference_report import annotation
from worldbox_metadata_string_counts import candidate_string_heap_bases

KIND = 'worldbox-metadata-string-neighborhood'
EXPECTED_METADATA = '0c843e9807d351f193580e178f4826845534cdcd86563e634ca8a48ad3b7bc88'
ANCHOR_TEXT = b'premium_unlocked'
EXPECTED_ANCHOR = 0x7456f1
WINDOW_RADIUS = 64 * 1024
MAX_TOKENS = 2048
MAX_SAMPLES = 12
MIN_TOKEN_LENGTH = 4
MAX_TOKEN_LENGTH = 128
IDENTIFIER = re.compile(rb'[A-Za-z_][A-Za-z0-9_.$`<>+-]{3,127}\Z', re.ASCII)
PRINTABLE = re.compile(rb'[ -~]{4,128}\Z', re.ASCII)
SAFE_IDENTIFIERS = frozenset({
    'premium_unlocked', 'Premium', 'premium', 'Get It Now',
    'PremiumWindow', 'PremiumUnlockAnimation', 'PremiumElementsChecker',
    'TopPremiumButtonMover', 'WindowPremiumRestoreHelper', 'ButtonPremium',
    'PowerButton', 'ButtonUtil', 'LocalizedTextPrice', 'clickPremium',
    'clickClose', 'clickHide', 'ResetState', 'premium_menu', 'CloseButton',
})
HEAP_TEXTS = tuple(sorted(SAFE_IDENTIFIERS))
LIMITATIONS = (
    'Bounded NUL-delimited printable-token, length-prefix, aligned-u32 and recurring-relative-offset model around one exact verified anchor in the hash-gated global-metadata.dat. '
    'Unknown strings are emitted only as SHA-256 hashes and lengths; no raw metadata bytes, arbitrary identifiers, decoded IL2CPP tables or entitlement logic leave the probe. '
    'Candidate string-heap bases and length prefixes are structural clues in opaque bytes, not proof of an IL2CPP string-literal table or a Premium check.'
)


def sha256_file(path):
    with Path(path).open('rb') as handle:
        return hashlib.file_digest(handle, 'sha256').hexdigest()


def hash_text(value):
    return hashlib.sha256(value.encode('utf-8', 'replace')).hexdigest()


def token_descriptor(value):
    """Expose predefined strings verbatim; hash every other observed token."""
    if value in SAFE_IDENTIFIERS:
        return {'safe': value}
    return {'sha256': hash_text(value), 'length': len(value)}


def emit_bounded(level, title, payload):
    message = annotation(json.dumps(payload, separators=(',', ':')))
    if len(message) > 3800:
        raise ValueError('Metadata neighborhood annotation exceeds the safety bound: ' + title)
    print('::' + level + ' title=' + title + '::' + message)


def u32_at(data, offset):
    if offset < 0 or offset + 4 > len(data):
        return None
    return struct.unpack_from('<I', data, offset)[0]


def printable_tokens(data, window_start, anchor_offset, max_tokens=MAX_TOKENS):
    tokens = []
    cursor = 0
    truncated = False
    while cursor < len(data):
        end = data.find(b'\0', cursor)
        if end < 0:
            end = len(data)
        raw = data[cursor:end]
        if (MIN_TOKEN_LENGTH <= len(raw) <= MAX_TOKEN_LENGTH and
                PRINTABLE.fullmatch(raw) and any(chr(byte).isalpha() for byte in raw)):
            absolute = window_start + cursor
            value = raw.decode('ascii')
            needle_labels = sorted(label for label, text in
                                   {'premium_unlocked': 'premium_unlocked',
                                    'get_it_now': 'Get It Now',
                                    'premium_lower': 'premium',
                                    'premium_capital': 'Premium'}.items()
                                   if text in value)
            row = {'offset': hex(absolute),
                   'deltaFromAnchor': hex(absolute - anchor_offset),
                   'length': len(raw),
                   'kind': ('identifier' if IDENTIFIER.fullmatch(raw)
                            else 'printable-phrase'),
                   'aligned': absolute % 4 == 0,
                   'needles': needle_labels,
                   'token': token_descriptor(value)}
            if len(tokens) < max_tokens:
                tokens.append(row)
            else:
                truncated = True
        cursor = end + 1
        if end >= len(data):
            break
    tokens.sort(key=lambda row: (abs(int(row['deltaFromAnchor'], 16)),
                                 int(row['offset'], 16)))
    return tokens, truncated


def length_prefix_candidates(data, tokens, max_samples=MAX_SAMPLES):
    count = 0
    samples = []
    for token in tokens:
        offset = int(token['offset'], 16)
        length = token['length']
        for back in (4, 8):
            prefix_offset = offset - back
            value = u32_at(data, prefix_offset)
            if value is None or value not in (length, length + 1):
                continue
            count += 1
            if len(samples) < max_samples:
                samples.append({'prefixOffset': hex(prefix_offset),
                                'prefixValue': value,
                                'tokenOffset': token['offset'],
                                'tokenLength': length,
                                'prefixAligned': prefix_offset % 4 == 0,
                                'includesNul': value == length + 1,
                                'token': token['token']})
    return {'count': count, 'samples': samples,
            'samplesTruncated': count > len(samples)}


def aligned_u32_model(data, window_start, anchor_offset, tokens):
    token_offsets = {int(row['offset'], 16) for row in tokens}
    token_lengths = {row['length'] for row in tokens}
    begin = (-window_start) % 4
    end = len(data)
    counts = {'anchorAbsoluteValue': 0, 'anchorWindowRelativeValue': 0,
              'pointsToNearbyToken': 0, 'matchesNearbyTokenLength': 0}
    samples = []
    relative_anchor = anchor_offset - window_start
    words_scanned = 0
    for local_offset in range(begin, end - 3, 4):
        words_scanned += 1
        value = struct.unpack_from('<I', data, local_offset)[0]
        absolute_offset = window_start + local_offset
        if value == anchor_offset:
            counts['anchorAbsoluteValue'] += 1
        if value == relative_anchor:
            counts['anchorWindowRelativeValue'] += 1
        if window_start + value in token_offsets:
            counts['pointsToNearbyToken'] += 1
        if value in token_lengths:
            counts['matchesNearbyTokenLength'] += 1
        if (value in (anchor_offset, relative_anchor) or
                window_start + value in token_offsets) and len(samples) < MAX_SAMPLES:
            samples.append({'wordOffset': hex(absolute_offset),
                            'value': hex(value),
                            'pointsToNearbyToken': window_start + value in token_offsets})
    return {'counts': counts, 'samples': samples,
            'samplesTruncated': sum(counts.values()) > len(samples),
            'wordsScanned': words_scanned}


def anchor_facts(data, expected_anchor=EXPECTED_ANCHOR):
    offsets = []
    start = 0
    while True:
        position = data.find(ANCHOR_TEXT, start)
        if position < 0:
            break
        offsets.append(position)
        start = position + 1
    if expected_anchor not in offsets:
        raise ValueError('Expected premium_unlocked anchor offset not found; refusing analysis.')
    anchor_end = expected_anchor + len(ANCHOR_TEXT)
    return {'anchorCount': len(offsets),
            'anchorOffsets': [hex(value) for value in offsets[:MAX_SAMPLES]],
            'anchorOffsetsTruncated': len(offsets) > MAX_SAMPLES,
            'expectedAnchor': hex(expected_anchor),
            'precedingU32': u32_at(data, expected_anchor - 4),
            'followingU32': u32_at(data, anchor_end),
            'anchorLength': len(ANCHOR_TEXT),
            'anchorLengthPrefix': u32_at(data, expected_anchor - 4) == len(ANCHOR_TEXT),
            'anchorNulTerminated': anchor_end < len(data) and data[anchor_end] == 0}


def neighborhood_report(path, expected_sha=EXPECTED_METADATA,
                        expected_anchor=EXPECTED_ANCHOR,
                        radius=WINDOW_RADIUS):
    sha = sha256_file(path)
    if expected_sha is not None and sha != expected_sha:
        raise ValueError('global-metadata.dat hash mismatch; refusing neighborhood scan.')
    data = Path(path).read_bytes()
    anchor = anchor_facts(data, expected_anchor)
    start = max(0, expected_anchor - radius)
    end = min(len(data), expected_anchor + len(ANCHOR_TEXT) + radius)
    window = data[start:end]
    tokens, tokens_truncated = printable_tokens(window, start, expected_anchor)
    prefixes = length_prefix_candidates(data, tokens)
    u32_model = aligned_u32_model(data, start, expected_anchor, tokens)
    heap = candidate_string_heap_bases(window, HEAP_TEXTS, min_support=2)
    return {'kind': KIND, 'sha256': sha, 'fileBytes': len(data),
            'anchor': anchor, 'window': {'start': hex(start), 'end': hex(end),
                                         'bytes': len(window), 'radius': radius},
            'tokens': {'count': len(tokens), 'truncated': tokens_truncated,
                       'safeKnownCount': sum(1 for row in tokens
                                             if 'safe' in row['token']),
                       'samples': tokens[:MAX_SAMPLES],
                       'samplesTruncated': len(tokens) > MAX_SAMPLES},
            'lengthPrefixes': prefixes, 'alignedU32': u32_model,
            'candidateStringHeapBases': heap, 'limitations': LIMITATIONS}


def emit_neighborhood_annotations(report):
    if report.get('kind') != KIND:
        raise RuntimeError('Unexpected WorldBox metadata neighborhood report.')
    print('WorldBox full metadata string-neighborhood report: ' +
          json.dumps(report, separators=(',', ':')))
    tokens = report['tokens']
    emit_bounded('warning', 'WorldBox metadata string neighborhood', {
        'sha256': report['sha256'], 'fileBytes': report['fileBytes'],
        'anchor': report['anchor'], 'window': report['window'],
        'tokenCount': tokens['count'], 'tokensTruncated': tokens['truncated'],
        'safeKnownCount': tokens['safeKnownCount'],
        'tokenSamples': tokens['samples'],
        'tokenSamplesTruncated': tokens['samplesTruncated'],
        'candidateStringHeapBases': report['candidateStringHeapBases'],
        'limitations': report['limitations']})
    emit_bounded('notice', 'WorldBox metadata string neighborhood structure', {
        'lengthPrefixes': report['lengthPrefixes'],
        'alignedU32': report['alignedU32']})


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('metadata')
    parser.add_argument('--expected-sha', default=EXPECTED_METADATA)
    args = parser.parse_args()
    try:
        report = neighborhood_report(args.metadata, args.expected_sha)
    except Exception as exc:
        print(f'Metadata neighborhood probe failed: {type(exc).__name__}: {exc}',
              file=sys.stderr)
        return 1
    print(json.dumps(report, separators=(',', ':')))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

#!/usr/bin/env python3
"""Compact, safe annotation emitters for bounded ARM64 target/FDE reports.

Only aggregate counts, safe addresses, section names and decoded mnemonics or
operands are surfaced. These helpers never emit unknown strings or game bytes.
"""
from __future__ import annotations

import json


def annotation(message):
    """Escape characters that GitHub Actions treats specially in commands."""
    return (message.replace('%', '%25')
                   .replace('\r', '%0D')
                   .replace('\n', '%0A'))


def compact_ghidra_row(row):
    return {'entry': row.get('entry'), 'anchorSites': row.get('anchorSites', []),
            'fdeBytes': row.get('fdeBytes'), 'decompiled': row.get('decompiled'),
            'status': row.get('status'), 'directCallCount': row.get('directCallCount'),
            'operationCounts': row.get('operationCounts', {}),
            'calls': [{'site': call.get('site'), 'target': call.get('target'),
                       'verifiedDirect': call.get('verifiedDirect'),
                       'importCategory': call.get('importCategory')}
                      for call in row.get('calls', [])[:10]],
            'tracedTargetArguments': [{key: item.get(key) for key in
                ('site', 'target', 'argumentIndex', 'stringCategories', 'rootKinds',
                 'inputRegisters', 'nodes', 'limited')}
                for item in row.get('tracedTargetArguments', [])[:12]],
            'returnGraphs': [{'roots': graph.get('rootKinds', []),
                              'strings': graph.get('stringCategories', []),
                              'operations': sorted(graph.get('operationCounts', {})),
                              'nodes': graph.get('nodes'),
                              'limited': bool(graph.get('nodeLimitReached') or graph.get('depthLimitReached'))}
                             for graph in row.get('returnGraphs', [])],
            'stringCategories': row.get('stringCategories', []),
            'truncated': row.get('truncated')}


def emit_fde_instructions(fde, label):
    if fde.get('status') == 'unavailable':
        print('::notice title=WorldBox ' + label + ' FDE unavailable ' + fde['entry'] + '::' +
              annotation(json.dumps(fde, separators=(',', ':'))))
        return
    lines = [f"{item['address']} {item['mnemonic']} {item['operands']}".strip().replace('%', '%25')
             for item in fde.get('instructions', [])]
    selected = lines[:100]
    parts = [selected[start:start + 50] for start in range(0, len(selected), 50)]
    for number, part in enumerate(parts, 1):
        payload = {'entry': fde['entry'], 'size': fde['size'],
                   'decodedInstructions': fde['decodedInstructions'],
                   'fullyDecoded': fde['fullyDecoded'],
                   'chunk': [number, len(parts)],
                   'instructionsTruncated': len(lines) > len(selected),
                   'instructions': '|'.join(part)}
        print('::notice title=WorldBox ' + label + ' FDE instructions ' + fde['entry'] +
              ' ' + str(number) + '/' + str(len(parts)) + '::' +
              annotation(json.dumps(payload, separators=(',', ':'))))


def emit_reference_annotations(report, label, full_label, expected_kind):
    if report.get('kind') != expected_kind:
        raise RuntimeError('Unexpected WorldBox ' + full_label + ' report.')
    print('WorldBox full ' + full_label + ' report: ' +
          json.dumps(report, separators=(',', ':')))
    summary = {key: report[key] for key in
               ('targets', 'unwindStatus', 'unwindRanges', 'limitations')}
    summary['rows'] = [{'target': row['target'], 'fdeStart': row['fdeStart'],
                        'fdeSize': row['fdeSize'],
                        'consumerCounts': {
                            'directTailBranches': row['xrefs']['directTailBranches'],
                            'pcRelativeAddressPairs': row['xrefs']['pcRelativeAddressPairs'],
                            'matchingRelocations': row['xrefs']['matchingRelocations'],
                            'alignedPointerValues': row['xrefs']['alignedPointerValues'],
                            'tailSamples': len(row['tailSamples']),
                            'pcRelativeSamples': len(row['pcRelativeSamples'])},
                        'fdeReportCount': len(row['fdeReports']),
                        'fdeReportsTruncated': row['fdeReportsTruncated']}
                       for row in report['rows']]
    print('::warning title=WorldBox ' + label + ' summary::' +
          annotation(json.dumps(summary, separators=(',', ':'))))
    emitted_fdes = set()
    for row in report['rows']:
        print('::warning title=WorldBox ' + label + ' xrefs ' + row['target'] + '::' +
              annotation(json.dumps(row['xrefs'], separators=(',', ':'))))
        consumers = {'target': row['target'], 'fdeStart': row['fdeStart'],
                     'fdeSize': row['fdeSize'], 'tailSamples': row['tailSamples'],
                     'pcRelativeSamples': row['pcRelativeSamples'],
                     'relocationSamples': row['relocationSamples'],
                     'pointerSamples': row['pointerSamples'],
                     'fdeReportEntries': [item.get('entry') for item in row['fdeReports']],
                     'fdeReportsTruncated': row['fdeReportsTruncated']}
        print('::warning title=WorldBox ' + label + ' consumers ' + row['target'] + '::' +
              annotation(json.dumps(consumers, separators=(',', ':'))))
        for fde in row['fdeReports']:
            key = (fde.get('entry'), fde.get('size'), fde.get('status'))
            if key in emitted_fdes:
                continue
            emitted_fdes.add(key)
            emit_fde_instructions(fde, label)


def emit_ghidra_annotations(report, label, addresses, targets, native_report=None):
    if report.get('kind') != 'ghidra-callees-probe':
        raise RuntimeError('Unexpected WorldBox ' + label + ' Ghidra report.')
    anchors = {site for row in report.get('functions', [])
               for site in row.get('anchorSites', [])}
    missing = sorted(set(addresses) - anchors)
    if missing:
        raise RuntimeError('WorldBox ' + label + ' Ghidra report omitted requested anchors: ' +
                           ', '.join(missing))
    print('WorldBox full ' + label + ' Ghidra report: ' +
          json.dumps(report, separators=(',', ':')))
    summary = {'addresses': addresses, 'traceTargets': targets,
               'functionCount': len(report.get('functions', [])),
               'limitations': report.get('limitations')}
    print('::warning title=WorldBox ' + label + ' Ghidra summary::' +
          annotation(json.dumps(summary, separators=(',', ':'))))
    for row in report.get('functions', []):
        print('::warning title=WorldBox ' + label + ' Ghidra::' +
              annotation(json.dumps(compact_ghidra_row(row), separators=(',', ':'))))
    if not native_report:
        return
    emitted = set()
    for native_row in native_report.get('rows', []):
        for fde in native_row.get('fdeReports', []):
            key = (fde.get('entry'), fde.get('size'), fde.get('status'))
            if key in emitted:
                continue
            emitted.add(key)
            emit_fde_instructions(fde, label)


def emit_ghidra_failure(label, diagnostic):
    payload = {'status': 'failed', 'diagnostic': diagnostic}
    print('::notice title=WorldBox ' + label + ' Ghidra::' +
          annotation(json.dumps(payload, separators=(',', ':'))))

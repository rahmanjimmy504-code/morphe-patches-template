#!/usr/bin/env python3
"""Bounded classification of hash-gated native imports and their callers.

Only predefined system API labels, safe addresses, aggregate counts, section
names, FDE-relative addresses and decoded ARM64 mnemonics/operands are emitted.
No game bytes or unknown literal strings leave the analysis. Direct BL/tail
matches are static candidates, not executed control flow.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from elftools.elf.sections import SymbolTableSection

import worldbox_native_flow as flow
import worldbox_native_scan as triage
import worldbox_native_xrefs as xrefs
import worldbox_thunk_callers as thunks
from worldbox_bounded_reference_report import annotation, emit_fde_instructions

KIND = 'worldbox-native-import-probe'
EXPECTED_IL2CPP = '1d644b98fec97a35630495c695515861acd2c18209beaae6471a650db65def87'
EXPECTED_UNITY = '8c04ad3b7d482cab925541cfe9839844c87732f7419aaaa71e170ccff916f082'
MAX_SECTION = 96 * 1024 * 1024
MAX_SAMPLES = 12
MAX_FDE_REPORTS = 3
MAX_TOTAL_FDE_REPORTS = 12
MAX_FDE_SIZE = 32 * 1024
MAX_GHIDRA_ADDRESSES = 6
MAX_TRACE_TARGETS = 16
MAX_STUB_SAMPLES = 128

IMPORT_CATEGORIES = {
    'crypto-openssl-aes': frozenset({
        'AES_decrypt', 'AES_encrypt', 'AES_cbc_encrypt', 'AES_set_decrypt_key',
        'AES_set_encrypt_key',
    }),
    'crypto-openssl-evp': frozenset({
        'EVP_DecryptInit', 'EVP_DecryptInit_ex', 'EVP_DecryptUpdate', 'EVP_DecryptFinal_ex',
        'EVP_EncryptInit', 'EVP_EncryptInit_ex', 'EVP_EncryptUpdate', 'EVP_EncryptFinal_ex',
        'EVP_CIPHER_CTX_new', 'EVP_CIPHER_CTX_free', 'EVP_aes_128_cbc', 'EVP_aes_256_cbc',
    }),
    'crypto-openssl-hash': frozenset({
        'MD5', 'SHA1', 'SHA256', 'SHA256_Init', 'SHA256_Update', 'SHA256_Final',
    }),
    'crypto-mbedtls': frozenset({
        'mbedtls_aes_init', 'mbedtls_aes_setkey_dec', 'mbedtls_aes_crypt_cbc',
        'mbedtls_md_init', 'mbedtls_md_update', 'mbedtls_md_finish',
    }),
    'crypto-other': frozenset({
        'RC4', 'sodium_init', 'crypto_secretbox_open_easy', 'crypto_stream_xor',
    }),
    'compression-zlib': frozenset({
        'inflateInit_', 'inflateInit2_', 'inflate', 'inflateEnd', 'uncompress',
        'zlibVersion', 'deflateInit_', 'deflate', 'deflateEnd',
    }),
    'compression-lz4': frozenset({
        'LZ4_decompress_safe', 'LZ4_decompress_safe_partial', 'LZ4_decompress_fast',
        'LZ4_createStreamDecode', 'LZ4_decompress_safe_continue',
    }),
    'compression-zstd': frozenset({
        'ZSTD_decompress', 'ZSTD_decompressStream', 'ZSTD_getFrameContentSize',
        'ZSTD_isError', 'ZSTD_createDStream', 'ZSTD_freeDStream',
    }),
    'compression-brotli': frozenset({
        'BrotliDecoderDecompress', 'BrotliDecoderCreateInstance', 'BrotliDecoderDecompressStream',
        'BrotliDecoderDestroyInstance',
    }),
    'compression-lzma': frozenset({
        'lzma_stream_decoder', 'lzma_code', 'lzma_end', 'lzma_stream_buffer_decode',
    }),
    'asset-android': frozenset({
        'AAssetManager_open', 'AAsset_read', 'AAsset_close', 'AAsset_getLength',
        'AAsset_getRemainingLength', 'AAsset_seek', 'AAssetManager_fromJava',
        'AAssetDir_openDir', 'AAssetDir_getNextFileName', 'AAssetDir_close',
    }),
    'file-io': frozenset({
        'open', 'open64', '__open_2', 'openat', '__openat_2', 'fopen', 'fopen64',
        'read', 'pread', 'pread64', 'close', 'lseek', 'lseek64', 'fstat', 'fstat64',
        'stat', 'mmap', 'mmap64', 'munmap', 'mprotect', 'access', 'readlink',
    }),
    'dynamic-loader': frozenset({'dlopen', 'android_dlopen_ext', 'dlsym', 'dlclose', 'dlerror'}),
}
SYMBOL_TO_CATEGORY = {name: label for label, names in IMPORT_CATEGORIES.items() for name in names}

KNOWN_DEPENDENCIES = {
    'libcrypto.so': 'crypto-openssl',
    'libssl.so': 'crypto-openssl',
    'libz.so': 'compression-zlib',
    'liblz4.so': 'compression-lz4',
    'libzstd.so': 'compression-zstd',
    'libbrotli': 'compression-brotli',
    'libbrotlidec': 'compression-brotli',
    'liblzma.so': 'compression-lzma',
    'libandroid.so': 'asset-android',
    'libdl.so': 'dynamic-loader',
    'libc.so': 'system-libc',
    'libm.so': 'system-libm',
    'liblog.so': 'system-log',
}

KNOWN_ANCHORS = (
    '0x1890260', '0x18eb7a4', '0x18edbb8', '0x18eb1a0',
    '0x18ebcb4', '0x18ebe74', '0x18ebfac',
    '0x3bf8dd0', '0x3bf8de0',
    '0x3bf90c0', '0x3bf9030', '0x3bf9700', '0x3bf9710',
)
LIMITATIONS = (
    'This is a bounded static classification of predefined dynamic imports and direct BL/tail candidates in hash-gated ARM64 libraries. '
    'It does not emit unknown symbol names or game bytes, model indirect calls, packed relocations, runtime-generated references, or executed control flow. '
    'Ghidra decompilation is restricted to bounded libil2cpp.so caller FDEs; libunity.so matches are classified only.'
)


def sha256_file(path):
    with Path(path).open('rb') as handle:
        return hashlib.file_digest(handle, 'sha256').hexdigest()


def known_dependency_labels(names):
    labels = set()
    for name in names:
        for prefix, label in KNOWN_DEPENDENCIES.items():
            if name.startswith(prefix):
                labels.add(label)
    return sorted(labels)


def fde_reports(path, entries, max_reports=MAX_FDE_REPORTS):
    unique = sorted(set(entries))
    reports = []
    for entry in unique[:max_reports]:
        try:
            result = flow.disassemble_fde(path, entry, max_size=MAX_FDE_SIZE)
        except ValueError as exc:
            reports.append({'entry': hex(entry), 'status': 'unavailable', 'reason': str(exc)})
        else:
            reports.append(result)
    return reports, len(unique) > max_reports


def library_report(path, library, expected_hash):
    sha = sha256_file(path)
    if expected_hash is not None and sha != expected_hash:
        raise ValueError(library + ' hash mismatch; refusing import classification.')
    with Path(path).open('rb') as handle:
        elf = ELFFile(handle)
        if elf.elfclass != 64 or not elf.little_endian or elf['e_machine'] != 'EM_AARCH64':
            raise ValueError('Expected a little-endian ELF64 AArch64 library')
        dynsym = elf.get_section_by_name('.dynsym')
        if not isinstance(dynsym, SymbolTableSection):
            raise ValueError('ELF has no dynamic symbol table')
        category_symbol_counts = {label: 0 for label in IMPORT_CATEGORIES}
        matched_names = set()
        dynamic_symbol_count = undefined_symbol_count = 0
        for symbol in dynsym.iter_symbols():
            dynamic_symbol_count += 1
            if symbol['st_shndx'] != 'SHN_UNDEF':
                continue
            undefined_symbol_count += 1
            label = SYMBOL_TO_CATEGORY.get(symbol.name)
            if label:
                category_symbol_counts[label] += 1
                matched_names.add(symbol.name)
        reloc_symbols = {}
        for section in elf.iter_sections():
            if not isinstance(section, RelocationSection) or '.plt' not in section.name:
                continue
            symbols = elf.get_section(section['sh_link'])
            if not isinstance(symbols, SymbolTableSection):
                continue
            for relocation in section.iter_relocations():
                index = relocation['r_info_sym']
                if index >= symbols.num_symbols():
                    continue
                name = symbols.get_symbol(index).name
                if name in SYMBOL_TO_CATEGORY:
                    reloc_symbols[relocation['r_offset']] = name
        reloc_labels = {offset: SYMBOL_TO_CATEGORY[name]
                        for offset, name in reloc_symbols.items()}
        plt, plt_stub_count = triage.plt_targets(elf, reloc_labels)
        plt_names, _ = triage.plt_targets(elf, reloc_symbols)
        plt_symbol_map = {}
        for address in sorted(set(plt) & set(plt_names)):
            name = plt_names[address]
            label = SYMBOL_TO_CATEGORY.get(name)
            if label:
                plt_symbol_map[hex(address)] = {'symbol': name, 'category': label}
        plt_by_category = {label: [] for label in IMPORT_CATEGORIES}
        for address, label in sorted(plt.items()):
            if label in plt_by_category:
                plt_by_category[label].append(hex(address))
        plt_stubs_truncated = {}
        for label, values in list(plt_by_category.items()):
            unique = sorted(set(values), key=lambda item: int(item, 16))
            plt_by_category[label] = unique[:MAX_STUB_SAMPLES]
            plt_stubs_truncated[label] = len(unique) > MAX_STUB_SAMPLES
        plt_by_category = {label: values for label, values in plt_by_category.items() if values}
        plt_stubs_truncated = {label: value for label, value in plt_stubs_truncated.items()
                               if label in plt_by_category}
        dependency_names = []
        dynamic = elf.get_section_by_name('.dynamic')
        if dynamic is not None and hasattr(dynamic, 'iter_tags'):
            string_table = elf.get_section(dynamic['sh_link'])
            getter = getattr(string_table, 'get_string', None)
            for tag in dynamic.iter_tags():
                if tag.entry.d_tag != 'DT_NEEDED':
                    continue
                name = getattr(tag, 'needed', None)
                if name is None and getter:
                    offset = getattr(tag.entry, 'd_val', None)
                    if isinstance(offset, int):
                        name = getter(offset)
                if isinstance(name, bytes):
                    name = name.decode('latin1', 'replace')
                if isinstance(name, str):
                    dependency_names.append(name)
        dependency_labels = known_dependency_labels(dependency_names)
        frames, unwind_status = thunks.unwind_frames(elf)
        starts = [low for low, _ in frames]
        state = {label: {'callCount': 0, 'samples': [], 'fdeStarts': set()}
                 for label in IMPORT_CATEGORIES}
        exec_sections = [section for section in elf.iter_sections()
                         if section['sh_flags'] & 4 and section['sh_type'] != 'SHT_NOBITS']
        total = scanned = 0
        for section in exec_sections:
            total += section['sh_size']
            budget = max(0, MAX_SECTION - scanned) & ~3
            if not budget:
                continue
            data = section.data()[:budget]
            scanned += len(data)
            for pc, word in triage.instructions(data, section['sh_addr']):
                candidates = (('bl', triage.direct_branch(word, pc)),
                              ('tail', xrefs.direct_tail(word, pc)))
                for kind, target in candidates:
                    label = plt.get(target) if target is not None else None
                    if not label:
                        continue
                    row = state[label]
                    row['callCount'] += 1
                    frame = flow.frame_for_site(frames, starts, pc)
                    function, size = (frame[0], frame[1] - frame[0]) if frame else (None, None)
                    if function is not None and size is not None and size <= flow.MAX_FUNCTION:
                        row['fdeStarts'].add(function)
                    if len(row['samples']) < MAX_SAMPLES:
                        row['samples'].append({
                            'site': hex(pc), 'kind': kind, 'target': hex(target),
                            'function': hex(function) if function is not None else None,
                            'size': size,
                        })
                    break
        rows = []
        category_rows = []
        for label in sorted(IMPORT_CATEGORIES):
            row = state[label]
            symbol_count = category_symbol_counts[label]
            stubs = plt_by_category.get(label, [])
            if not (symbol_count or row['callCount'] or stubs):
                continue
            fde_rows, fde_truncated = fde_reports(path, row['fdeStarts'])
            fde_entries = [item.get('entry') for item in fde_rows]
            detailed = {
                'library': library, 'category': label,
                'symbolCount': symbol_count,
                'pltStubCount': len(stubs), 'pltStubs': stubs,
                'directCallCount': row['callCount'],
                'callSamples': row['samples'],
                'fdeReports': fde_rows,
                'fdeReportEntries': fde_entries,
                'fdeReportsTruncated': fde_truncated,
            }
            rows.append(detailed)
            category_rows.append({key: detailed[key] for key in
                                  ('category', 'symbolCount', 'pltStubCount',
                                   'directCallCount', 'fdeReportsTruncated')})
        return {
            'summary': {
                'library': library, 'sha256': sha,
                'dynamicSymbolCount': dynamic_symbol_count,
                'undefinedSymbolCount': undefined_symbol_count,
                'categorySymbolCounts': category_symbol_counts,
                'matchedSymbolNames': sorted(matched_names),
                'dynamicDependencyLabels': dependency_labels,
                'pltStubCount': plt_stub_count,
                'pltByCategory': plt_by_category,
                'pltSymbolMap': plt_symbol_map,
                'pltStubsTruncated': plt_stubs_truncated,
                'executableBytes': total, 'executableScanned': scanned,
                'execTruncated': scanned < total,
                'unwindStatus': unwind_status, 'unwindRanges': len(frames),
                'categoryRows': category_rows,
            },
            'rows': rows,
        }


def import_report(native, unity, expected_il2cpp=EXPECTED_IL2CPP,
                  expected_unity=EXPECTED_UNITY):
    first = library_report(native, 'libil2cpp.so', expected_il2cpp)
    second = library_report(unity, 'libunity.so', expected_unity)
    rows = first['rows'] + second['rows']
    remaining = MAX_TOTAL_FDE_REPORTS
    for row in rows:
        if remaining <= 0:
            row['fdeReports'] = []
            row['fdeReportEntries'] = []
            row['fdeReportsTruncated'] = True
            continue
        if len(row['fdeReports']) > remaining:
            row['fdeReports'] = row['fdeReports'][:remaining]
            row['fdeReportEntries'] = [item.get('entry') for item in row['fdeReports']]
            row['fdeReportsTruncated'] = True
            remaining = 0
        else:
            remaining -= len(row['fdeReports'])
    il2cpp_rows = [row for row in rows if row['library'] == 'libil2cpp.so']
    address_values = [item.get('entry') for row in il2cpp_rows
                      for item in row['fdeReports']
                      if item.get('status') != 'unavailable' and item.get('entry')]
    all_addresses = sorted(set(address_values), key=lambda item: int(item, 16))
    ghidra_addresses = all_addresses[:MAX_GHIDRA_ADDRESSES]
    stub_values = sorted({address for row in il2cpp_rows for address in row['pltStubs']},
                         key=lambda item: int(item, 16))
    trace_targets = stub_values[:MAX_TRACE_TARGETS]
    for anchor in KNOWN_ANCHORS:
        if anchor not in trace_targets and len(trace_targets) < MAX_TRACE_TARGETS:
            trace_targets.append(anchor)
    trace_targets = sorted(trace_targets, key=lambda item: int(item, 16))
    return {
        'kind': KIND,
        'libraries': [first['summary'], second['summary']],
        'rows': rows,
        'ghidraLibrary': 'libil2cpp.so',
        'ghidraAddresses': ghidra_addresses,
        'ghidraAddressesTruncated': len(all_addresses) > len(ghidra_addresses),
        'traceTargets': trace_targets,
        'traceTargetsTruncated': len(stub_values) > MAX_TRACE_TARGETS,
        'limitations': LIMITATIONS,
    }


def emit_import_annotations(report):
    if report.get('kind') != KIND:
        raise RuntimeError('Unexpected WorldBox native import report.')
    print('WorldBox full native import report: ' +
          json.dumps(report, separators=(',', ':')))
    summary = {key: report[key] for key in
               ('ghidraLibrary', 'ghidraAddresses',
                'ghidraAddressesTruncated', 'traceTargets',
                'traceTargetsTruncated', 'limitations')}
    summary['libraryNames'] = [library['library'] for library in report['libraries']]
    print('::warning title=WorldBox native import summary::' +
          annotation(json.dumps(summary, separators=(',', ':'))))
    for library in report['libraries']:
        compact = {key: library[key] for key in
                   ('library', 'sha256', 'dynamicSymbolCount',
                    'undefinedSymbolCount', 'categorySymbolCounts',
                    'matchedSymbolNames', 'dynamicDependencyLabels',
                    'pltStubCount', 'pltStubsTruncated',
                    'executableBytes', 'executableScanned',
                    'execTruncated', 'unwindStatus', 'unwindRanges')}
        print('::warning title=WorldBox native import library ' + library['library'] + '::' +
              annotation(json.dumps(compact, separators=(',', ':'))))
        print('::warning title=WorldBox native import categories ' + library['library'] + '::' +
              annotation(json.dumps({'library': library['library'],
                                     'categoryRows': library['categoryRows']},
                                    separators=(',', ':'))))
        print('::warning title=WorldBox native import symbols ' + library['library'] + '::' +
              annotation(json.dumps({'library': library['library'],
                                     'pltSymbolMap': library['pltSymbolMap']},
                                    separators=(',', ':'))))
        for category, stubs in library['pltByCategory'].items():
            payload = {'library': library['library'], 'category': category,
                       'pltStubs': stubs,
                       'pltStubsTruncated': library['pltStubsTruncated'].get(category, False)}
            print('::warning title=WorldBox native import stubs ' +
                  library['library'] + ' ' + category + '::' +
                  annotation(json.dumps(payload, separators=(',', ':'))))
    emitted = set()
    for row in report['rows']:
        consumers = {key: row[key] for key in
                     ('library', 'category', 'symbolCount', 'pltStubCount',
                      'directCallCount', 'callSamples', 'fdeReportEntries',
                      'fdeReportsTruncated')}
        print('::warning title=WorldBox native import consumers ' +
              row['library'] + ' ' + row['category'] + '::' +
              annotation(json.dumps(consumers, separators=(',', ':'))))
        for fde in row['fdeReports']:
            key = (fde.get('entry'), fde.get('size'), fde.get('status'))
            if key in emitted:
                continue
            emitted.add(key)
            emit_fde_instructions(fde, 'native import')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('native')
    parser.add_argument('unity')
    parser.add_argument('--expected-il2cpp', default=EXPECTED_IL2CPP)
    parser.add_argument('--expected-unity', default=EXPECTED_UNITY)
    args = parser.parse_args()
    print(json.dumps(import_report(args.native, args.unity,
                                   args.expected_il2cpp, args.expected_unity),
                     separators=(',', ':')))


if __name__ == '__main__':
    main()

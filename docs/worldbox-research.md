# WorldBox 0.51.4 research

This is an investigation, **not a working Morphe patch**. No premium-unlock patch or release has been produced.

## Target

- WorldBox Android 0.51.4, version code 725, package `com.mkarpenko.worldbox`.
- The APKMirror bundle contains a base APK and ARM64/ARMv7 splits. The analysis workflow downloads the bundle temporarily and does not publish the APK or native libraries.
- The ARM64 `libil2cpp.so` observed in the bundle has SHA-256 `1d644b98fec97a35630495c695515861acd2c18209beaae6471a650db65def87`. Bundle size and this library hash identify the observed file; they do not verify its publisher's signature.

## Observations

- The Android emulator in [this run](https://github.com/rahmanjimmy504-code/morphe-patches-template/actions/runs/41097940887) supported ARM64 translation, installed the original base and ARM64 split, and still had a game process after 60 seconds. The test did **not** establish that gameplay, premium, or a patched build worked.
- Standard Il2CppDumper could not read `global-metadata.dat`; its header is not the standard IL2CPP magic, and the first MiB has approximately 7.9998 bits/byte of entropy. This is consistent with protected data but does not by itself establish its encryption scheme.
- [REA](https://github.com/morluto/rea) with JADX identified `com.unity.purchasing.common.UnityPurchasing` and Google Billing classes. REA observed that `OnProductsRetrieved` forwards serialized products through a bridge. This does **not** identify or bypass the actual premium entitlement check.
- REA's IL2CPP metadata reader does not decrypt protected metadata. Native runtime analysis or a verified metadata-unpacking method is still needed to locate and validate a version-specific entitlement check.

The branch's experimental inspection workflow warns when the static IL2CPP dumper cannot read the metadata; that warning is not a passing patch test. It is a research diagnostic, not a release or a compatibility test for a patch. Its runtime emulator probe is disabled unless the repository variable `WORLDBOX_RUNTIME_PROBE` is set to `1`.

## Experimental runtime scan

The read-only scanner in `docs/worldbox/scan-metadata.js` was adapted from the research in [PR #1](https://github.com/rahmanjimmy504-code/morphe-patches-template/pull/1). It uses the Frida 17 pointer API and sends only aggregate candidate counts, versions and scan coverage; it does not save or transmit process-memory bytes. A candidate is only a heuristic and must not be treated as verified metadata. A zero count also does not prove the metadata is absent, especially if the scan is truncated or reads fail.

The branch-only runtime workflow installs the original ARM64 base and split APKs on a disposable Android emulator and attaches to the exact game PID. It does not publish the APK or any metadata. It can be enabled with the `WORLDBOX_RUNTIME_PROBE` repository variable or by including `[worldbox-runtime]` in a commit message that changes one of the workflow's watched paths. This is a research workflow, not a premium patch.

Local synthetic checks: `node tests/worldbox-metadata-scanner.test.cjs` and `bash -n docs/worldbox/triage-static.sh`. These checks do not prove the scanner works against WorldBox.

A real Frida 17.25.0 attachment to a synthetic local Linux process containing a mock header also completed successfully. This validates the API path on that host, not Android or WorldBox.

## Frida attachment investigation

The initial emulator runtime scan failed with `unexpectedly timed out trying to sync up with agent`; it did not produce a metadata result. The experimental workflow now tests Frida against a separate disposable emulator process, records the emulator's SELinux mode, and retries WorldBox with permissive SELinux **only inside the disposable CI emulator**. If Frida still fails, it attempts a read-only `/proc/PID/mem` scan via a small x86-64 Android helper. The helper temporarily pauses the target with `ptrace`, resumes it afterwards, and emits aggregate counts only; it does not export memory bytes. Neither a successful attachment nor a heuristic header match proves that Premium can be unlocked.

Synthetic local checks: `python3 tests/test_worldbox_proc_scan.py`, `node tests/worldbox-metadata-scanner.test.cjs`, and `python3 tests/test_worldbox_triage.py`. The `/proc` check attaches only to a synthetic child and verifies that it resumes. These tests do not establish Android or WorldBox compatibility.

The subsequent CI comparison successfully attached Frida to a simple x86-64 emulator process. WorldBox attachment timed out waiting for a process stop; by the fallback attempt, that process was gone, so the `/proc` scan did not run. The workflow now restarts WorldBox before retrying or using the fallback; this does not establish why the game disappeared.

In the next emulator run, the simple Frida smoke test passed, but the WorldBox Frida attempt timed out and its retry could not connect to the server. The restarted game was scanned by the Android `/proc` helper and it reported zero plausible headers. A zero is inconclusive; the detailed aggregate was hidden by GitHub Actions notice limits in that run. The workflow now surfaces it as a warning.

CI run [41106734649](https://github.com/rahmanjimmy504-code/morphe-patches-template/actions/runs/41106734649) reported: Frida attached successfully to the simple smoke process; attachment to WorldBox timed out both before and after temporarily setting the emulator to permissive SELinux. The restarted game's `/proc` scan reported 0 candidates, 2,147,483,648 scanned bytes, 151 ranges, 0 read errors, and `truncated: true`. Thus it did not cover all readable mappings. The green job indicates the diagnostic completed, not that metadata was recovered or a patch was validated. A next investigation would need to cover later mappings or prioritize likely metadata-containing regions, while preserving strict limits and aggregate-only output.

### Expanded bounded scan

The `/proc` helper now scans two disjoint groups, each capped at 2 GiB of requested reads: (1) writable, anonymous or Android anonymous-style mappings of at most 128 MiB, in ascending address order; (2) all other readable mappings, in descending address order, including the high end of any partially scanned range. This prioritization is only a heuristic; metadata may be elsewhere. Each group reports eligible virtual bytes, attempted and actually read bytes, ranges, read errors, candidate counts, and header-validation counts. `truncated` identifies unattempted readable bytes; read errors or short reads can limit coverage even when it is false. Candidate validation itself is bounded and emits no addresses, paths or memory bytes. The game may change while scanned because attaching one thread does not freeze every thread, and the mappings are a snapshot, not proof of a consistent whole-process inspection.

The synthetic Linux tests exercise both mapping groups, truncated budgets, selecting the high end of a range, a chunk-boundary header, candidate counts and resuming the child. They do not establish the result on Android or identify an entitlement check.

The expanded diagnostic ran on Android in [run 41108167630](https://github.com/rahmanjimmy504-code/morphe-patches-template/actions/runs/41108167630). The priority group attempted and read 2,147,483,648 of 4,954,796,032 eligible bytes across 183 ranges, with no read errors. The later-address group attempted 2,147,483,648 of 17,197,826,048 eligible bytes across 1,550 ranges; it read 2,146,390,016 bytes and reported 2 read errors. Neither group saw the magic needed to initiate header validation; both reported zero candidates, and the overall scan was truncated. Frida still timed out on the game both before and after the emulator-only SELinux change. These results do not prove the protected metadata was absent or locate a Premium entitlement check.

### Resident-page experiment

The helper also supports a `--resident` mode, first used in the following CI probe. It samples Linux `/proc/PID/pagemap` present bits, coalesces present pages, then applies the same two 2 GiB scan budgets. It reports mapped, resident-eligible, nonresident, swapped (a subset of nonresident), and unknown page-map bytes for each group; `selectedTruncated` means some selected or unknown pages were not covered, while `truncated` also reflects deliberately skipped nonresident pages. Earlier results used the name `residentTruncated`. Read errors and validation limits are reported separately. Pagemap examination is bounded, does not emit addresses or page contents, and failure to open it is an error rather than an empty successful scan.

Present bits describe only a changing snapshot: skipped nonresident pages could contain relevant data, other threads can change memory, and header bytes across a skipped page boundary can be missed. The result is therefore not a complete scan or proof of absence. Local tests use synthetic sparse, resident, swapped, unknown, and chunk-boundary fixtures and verify resumption; they do not establish Android compatibility or identify Premium logic.

In [run 41109434497](https://github.com/rahmanjimmy504-code/morphe-patches-template/actions/runs/41109434497), the resident scan read all 1,330,049,024 bytes marked present in its pagemap snapshot (zero pagemap unknown bytes and zero memory read errors) and found no header candidates. It deliberately did not scan nonresident pages; 114,589,696 of those bytes were marked swapped. Frida again timed out on WorldBox. The workflow now uses `--resident-and-swapped` to include swapped pages in a new bounded snapshot. `nonresidentBytes` includes swapped bytes, and `eligibleBytes` includes present plus swapped bytes in this mode. The two snapshots are separate and can change as the game runs.

The subsequent combined scan in [run 41110457414](https://github.com/rahmanjimmy504-code/morphe-patches-template/actions/runs/41110457414) selected 1,440,358,400 bytes reported present or swapped (including 82,321,408 swapped bytes), attempted all of them, and read 1,440,354,304 bytes. One 4,096-byte read failed; no pagemap bytes were unknown. It found zero header candidates. Other nonresident pages were not selected, and the process can change while scanning, so this is not a complete or conclusive memory search. Frida again timed out on the game. The green workflow result means diagnostics ran, not that a patch was found or tested.

## ARM64 static initialization triage

`.github/scripts/worldbox_native_scan.py` inspects an ELF64 AArch64 library without executing it. The branch workflow verifies the previously observed ARM64 library SHA-256 before running it on the original 0.51.4 bundle; the library stays in runner temporary storage. The scanner reports selected import/export names, relative virtual call-site addresses, recognized ARM64 PLT stubs, and bounded initialization-window statistics. It does not print native code or metadata and is not a patch.

The scanner identifies common ARM64 PLT stubs by matching their GOT relocations, sweeps executable sections for direct `BL` instructions, and explores short windows from up to 64 initialization entries to a maximum depth of two and 256 windows. This is a heuristic, not a proven call graph: linear decoding can mistake data or unreachable instructions for code, and the analysis can miss indirect calls, alternate PLT formats, encrypted/packed code, control-flow paths and initializers outside the limits. A selected import or call is not proof of metadata decryption or Premium logic. Unrecognized stubs are reported as unresolved rather than guessed.

Run synthetic tests with `python tests/test_worldbox_native.py` after installing `pyelftools==0.32` and `capstone==5.0.6`. The native CI job is enabled by `[worldbox-native]` in a commit touching a watched workflow path. The synthetic ARM64 ELF tests cover relocation-based initialization, a matched PLT import, a two-level direct trace, unknown stubs, and non-ARM64 rejection; they do not validate the findings against WorldBox.

The first real ARM64 pass in [run 41112952048](https://github.com/rahmanjimmy504-code/morphe-patches-template/actions/runs/41112952048) recognized all 9 watched PLT relocations and swept 39,080,228 executable bytes. It found 24 initialization entries, and its bounded heuristic traversal reached 152 code windows. One `read` site at ELF-relative virtual address `0x18eae2c` was within a depth-one window from initializer `0x18f4220`; an `open` site was 84 bytes earlier at `0x18eadd8`. Proximity and the heuristic path are not proof that the calls share a function, access metadata, execute on this path, or affect Premium.

The analyzer now also reports bounded windows of nearby file-related import calls and only predefined categories for simple PC-relative references to `/proc/`, metadata names, or Unity asset paths. These are spatial clues, not function boundaries or proof of purpose, and the reference pattern can miss or misclassify pointers. Raw code and strings remain unreported.

The follow-up [run 41113353858](https://github.com/rahmanjimmy504-code/morphe-patches-template/actions/runs/41113353858) resolved all 13 selected import PLT stubs. It again found the initializer-adjacent `open`/`read` sites above and a nearby `open`/`fstat`/`mmap`/`munmap` cluster around `0x18ebdf0`–`0x18ebfb0`; neither selected window produced a recognized metadata-name or Unity-assets-path reference. A different cluster around `0x193d920`–`0x193da9c` included a detected `/proc/`-path reference. These are not verified function boundaries, execution paths or file arguments. A missing category is inconclusive, and the `/proc/` reference does not prove every neighboring call uses it. No metadata loader, decryption algorithm or Premium entitlement check was established. Future work should inspect control flow and file arguments at the first two clusters, ideally on an ARM64 runtime, before attempting a patch.

## Targeted file-argument investigation

`.github/scripts/worldbox_native_flow.py` examines the previously observed file-access sites in the hash-verified ARM64 library. It uses `.eh_frame` unwind ranges where available, verifies each direct call against the resolved PLT entry, and applies a bounded control-flow/register/stack-value heuristic to the containing ranges. It emits only relative site addresses and coarse argument categories, not game instructions, file paths or other raw bytes. `return-from-open@…` is a possible modeled provenance, not proof that an actual execution links those calls. The heuristic does not fully model ARM64 instructions, indirect control flow, memory aliases, called functions or dynamic strings, and unwind ranges themselves may be incomplete or misleading. Missing unwind information is reported as inconclusive.

Synthetic tests cover unwind-backed call confirmation, missing unwind ranges, branch joins, call-clobbered registers, and a stack spill/reload. These tests do not validate WorldBox-specific file arguments or establish a decryption or entitlement check.

The file-argument analysis in [run 41114087635](https://github.com/rahmanjimmy504-code/morphe-patches-template/actions/runs/41114087635) parsed 209,468 unwind ranges and matched all six targeted calls. The formerly adjacent `open` at `0x18eadd8` and `read` at `0x18eae2c` fall in distinct FDE ranges; the open argument was classified only as another static string, while the read file descriptor was an entry argument to its own function. In the other cluster, `open`, `fstat`/`mmap`, and `munmap` were also in separate FDE ranges; the modeled open path came from an entry argument and the `mmap` file-descriptor source was unknown. These are heuristic static results, not proof that runtime paths or arguments match.

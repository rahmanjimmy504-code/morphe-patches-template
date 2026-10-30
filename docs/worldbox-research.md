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

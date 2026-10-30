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

The branch's experimental inspection workflow deliberately reports the static IL2CPP dump failure. It is a research diagnostic, not a release or a compatibility test for a patch. Its runtime emulator probe is disabled unless the repository variable `WORLDBOX_RUNTIME_PROBE` is set to `1`.

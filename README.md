# WorldBox 0.51.4 Patch Research

An independent project investigating a Premium unlock patch for WorldBox Android 0.51.4 using [Morphe](https://github.com/MorpheApp/morphe-patcher). This project is not affiliated with WorldBox or Morphe.

## Status: research only

**There is no working Premium unlock patch or patched APK in this repository.** The entitlement check has not been identified or validated, and no usable WorldBox patch has been released. Adding this repository to Morphe Manager or building the current project will not unlock Premium.

The intended target is package `com.mkarpenko.worldbox`, version **0.51.4** (version code **725**). The investigated APKMirror download is an APKM containing a base APK and ARM64/ARMv7 splits; the native analysis so far focused on ARM64. Applying, rebuilding, and installing a patched APKM with Morphe has not been verified.

## Findings and next steps

The observed IL2CPP metadata does not have the standard header and existing metadata tools could not read it. Unity purchasing callbacks and several Premium-related script names were observed, but neither identifies the entitlement check or proves a patch target. See [WorldBox research](docs/worldbox-research.md) for the evidence, test results and limitations.

Before publishing a patch, the project needs a verified version-specific entitlement target, a Morphe implementation that handles the relevant package files safely, and tests showing that the patched build installs, runs, and unlocks Premium without breaking normal functionality. Avoid treating a successful analysis workflow as a patch test.

## Patch list

<!-- PATCHES_START EXPANDED -->

No WorldBox patches are available yet.

<!-- PATCHES_END -->

## Development

The research scripts and experimental GitHub Actions workflow are described in [the research notes](docs/worldbox-research.md). Synthetic tests exercise parts of the analysis tooling; they do not establish WorldBox compatibility.

Once a real patch is implemented, build the bundle with `./gradlew buildAndroid`; the output is written under `patches/build/libs/`. This requires the Java, Android and Morphe/GitHub Packages dependencies described in the [Morphe development documentation](https://github.com/MorpheApp/morphe-documentation/blob/main/docs/morphe-development/README.md). The existing semantic-release workflow generates release metadata and patch lists; generated `patches-list.json`, `patches-bundle.json`, and `CHANGELOG.md` should not be edited manually.

Do not commit APKs, game binaries, receipts, purchase tokens, signing keys, or other private data to this repository. The research workflow downloads its sample into temporary runner storage.

## License

This repository is licensed under the [GNU General Public License v3.0](LICENSE); see also [NOTICE](NOTICE).

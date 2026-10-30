# WorldBox 0.51.4 (com.mkarpenko.worldbox, vc 725) — IL2CPP metadata research

Status: research note, last updated **2026-10-30**.
Scope: free / open-source tooling that can *analyse or recover* the protected
`global-metadata.dat` of WorldBox on Android, plus reproducible steps for a
GitHub Actions emulator.

> **Nothing in this document claims that WorldBox 0.51.4's metadata has been
> decrypted.** No tool below has been proven to work on this build. The table in
> [§6](#6-what-is-actually-verified-for-this-build) separates what is verified
> from what is merely plausible. Everything else is a hypothesis with a test
> attached.

Related files in this repo:

| File | Purpose |
| --- | --- |
| `docs/worldbox/triage-static.sh` | Classifies the protection (aggregate report, no game data) |
| `docs/worldbox/dump-metadata.js` | Frida script: finds the *decrypted* metadata in process memory, read-only |
| `.github/workflows/worldbox-metadata-dump.yml` | Manual `workflow_dispatch` CI for both of the above |

---

## 1. Target facts

| Fact | Value | Source |
| --- | --- | --- |
| Package | `com.mkarpenko.worldbox` | — |
| Version / versionCode | 0.51.4 / **725** | [APKMirror listing](https://www.apkmirror.com/apk/mako-mako/worldbox-sandbox-god-simulator/worldbox-sandbox-god-sim-0-51-4-release/worldbox-sandbox-god-sim-0-51-4-android-apk-download/) |
| ABIs in the bundle | `arm64-v8a` + `armeabi-v7a` | same listing |
| minSdk / targetSdk | 23 / 35 | same listing |
| Bundle size | ≈ 181.5 MB (190,320,343 bytes) | same listing |
| Published | 2026-05-25 | same listing |
| Engine | Unity, IL2CPP backend (`libil2cpp.so` + `assets/bin/Data/Managed/Metadata/global-metadata.dat`) | project knowledge; confirm with the triage script |

Two consequences that matter:

1. **The metadata file is architecture-independent.** One
   `global-metadata.dat` is shared by the arm64 and armv7 builds. If the two
   `libil2cpp.so` files look different (they always do), that is expected; if you
   ever find *two* metadata files with different hashes, you are looking at a
   split/repacked bundle and should stop and re-extract.
2. **The metadata is the useful half of the pair.** `libil2cpp.so` holds code,
   `global-metadata.dat` holds every type name, method name, field name and
   string literal. Il2CppDumper needs both to produce `dump.cs` + `script.json`.
   A decrypted metadata file alone already gives you the type/method layout and
   string literals; the binary alone gives you very little.

### What the existing notes established

| Observation | Meaning | Verified here? |
| --- | --- | --- |
| `global-metadata.dat` lacks the standard magic `0xFAB11BAF` | The on-disk file is not a vanilla metadata file | reported by you; re-check with `triage-static.sh` |
| Il2CppDumper says the file "may be encrypted" | Il2CppDumper refuses the header; it does **not** attempt decryption by design | reported by you; matches upstream docs ("Deobfuscating … beyond the scope of this program") |
| REA's IL2CPP metadata reader does not decrypt it | REA (`morluto/rea`, MIT) parses metadata, it is not a decryption tool | reported by you; consistent with REA's advertised behaviour |
| `libil2cpp.so` (arm64) has stripped/obfuscated symbols | Possibly *normal* `strip`; only a problem if **dynamic** exports are gone | **not** verified — `triage-static.sh` distinguishes the two |
| Game process survived 60 s on a GH Actions emulator | The app boots under translation; static analysis and data-level memory reads are realistic there | reported by you |

---

## 2. The four failure modes (do not conflate them)

"Il2CppDumper says the metadata may be encrypted" is *one* symptom that covers
at least four very different situations. Which one you have decides which tool
can help. `docs/worldbox/triage-static.sh` produces the numbers needed to tell
them apart.

| # | Situation | Fingerprint in the triage report | Realistic tool |
| --- | --- | --- | --- |
| A | Metadata is fine, wrong version for the dumper | Magic **present**, version plausible but older/newer than the tool supports | Newer dumper (AndnixSH CLI, Cpp2IL, Il2CppInspector) |
| B | Header/envelope obfuscated, **tables still plaintext** | Magic missing, but block entropy 4–6 b/B and `mscorlib` / `System.Private.CoreLib` occurrences > 0 | Structural recovery: dumper forks with magic/structure recovery, Il2CppInspector loader plugins, or a small script |
| C | **Whole file really encrypted** | Magic missing, every 64 KiB block ≈ 8.0 b/B, zero identifier hits | Runtime memory dump (only sane option) |
| D | Metadata normal but **`libil2cpp.so` is packed** | Fingerprints `libjiagu`, `libDexHelper`, high `.text` entropy, tiny code | Runtime dump of *both* the binary and the metadata |

A useful prior: a full custom cipher (case C) is mostly seen in titles that
integrated a commercial hardening product (FairGuard, Bangcle, NetEase Yidun,
AppSealing, …). There is no public evidence that WorldBox ships one, which makes
case **B** or **A** more likely — but that is a prior, not evidence, and nothing
in this repo assumes it. Run the triage before choosing a path.

---

## 3. Static tools

All links are the official upstream repositories. Licences were read from the
GitHub API on 2026-10-30, not from memory.

| Tool | Official link | Licence | Requirements | Android ARM64 | Root / modified APK | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| **Il2CppDumper** (Perfare) | <https://github.com/Perfare/Il2CppDumper> | **MIT** | .NET 6+ / builds from source; releases up to `v6.7.46` (2024-07) | Yes (ELF/ELF64); Unity 5.3 – 2022.2 | No / No | The reference tool. Pattern-finds `Il2CppCodeRegistration`. Explicitly refuses obfuscated metadata. Accepts *memory-dumped* `libil2cpp.so`. |
| **Il2CppDumper GUI + CLI** (AndnixSH fork) | <https://github.com/AndnixSH/Il2CppDumper> | **MIT** | .NET 10 Desktop Runtime (GUI, Windows); CLI builds/runs on Linux/macOS | Yes | No / No | Claims metadata 16–39 and 104–111, Unity 5.3 – 6000.7, `--fast`, `--code-registration` overrides. Third-party fork: treat extra "auto-recovery" claims as unverified. |
| **Cpp2IL** (Samboy) | <https://github.com/SamboyCoding/Cpp2IL> | **MIT** | .NET; pre-releases only (`2022.1.0-pre-release.*`) | Yes | No / No | Independent parser (`LibCpp2IL`), useful as a second opinion when Il2CppDumper disagrees. Also needs valid metadata. |
| **Il2CppInspector** (djkaty) | <https://github.com/djkaty/Il2CppInspector> | **AGPL-3.0** | .NET; Windows GUI + CLI; last release `2021.1`, repo dormant since 2022 | Yes | No / No | The only free tool with **loader plugins** for obfuscated metadata, and it accepts **Linux process maps + `.bin`** (GameGuardian-style dumps) plus memory-dumped ELFs. AGPL matters if you plan to redistribute derived code. |
| **REA** (`morluto/rea`) | <https://github.com/morluto/rea> | **MIT** | Node.js ≥ 20, `npx rea-agents` | Static metadata reader | No / No | Already tried: reads IL2CPP metadata, does **not** decrypt. Keep it for the `libil2cpp.so` side (pseudo-code via Ghidra). |
| **Ghidra** | <https://github.com/NationalSecurityAgency/ghidra> | **Apache-2.0** | Java 21 | Yes | No / No | Consumes Il2CppDumper's `ghidra.py` / `script.json`; also the tool you use to reverse the decryption routine in case C. |
| **Rizin / radare2** | <https://github.com/rizinorg/rizin> · <https://github.com/radareorg/radare2> | **LGPL-3.0** | CLI | Yes | No / No | Scriptable alternative to Ghidra; good for entropy maps and section triage over SSH/CI. |
| **apktool** | <https://github.com/iBotPeaches/Apktool> | **Apache-2.0** | Java | n/a | No / repackages | Only needed for the frida-gadget route. |
| **uber-apk-signer** | <https://github.com/patrickfav/uber-apk-signer> | **Apache-2.0** | Java | n/a | n/a | Re-signs a repacked APK (v1/v2/v3). |

Non-free but relevant: **IDA Free** (freeware), **Binary Ninja** (paid), **GameGuardian** (paid, Android; its memory-map dumps are the input format Il2CppInspector documents).

---

## 4. Runtime tools

Runtime tools do not need the cipher: they read the metadata *after* the engine
decrypted it. This is the only class of tool with a realistic chance if the
triage says case C.

| Tool | Official link | Licence | Requirements | Android ARM64 | Root / modified APK | What you get |
| --- | --- | --- | --- | --- | --- | --- |
| **Frida** | <https://frida.re> · <https://github.com/frida/frida> | wxWindows Library Licence (LGPL-style) | `frida-server` as root **or** `frida-gadget` inside a repacked APK; host client `frida-tools` | Yes | Root **or** repack | The plumbing; everything below builds on it. |
| **frida-il2cpp-bridge** | <https://github.com/vfsfitvnm/frida-il2cpp-bridge> | **MIT** | Frida in the target process; Unity 5.3 – 6000.3; `npm exec frida-il2cpp-bridge -- dump` | Yes | Root or gadget | Full `dump.cs` **without** `global-metadata.dat` at all (it walks the runtime's own structures). Needs working `il2cpp_*` exports/detection. |
| **Zygisk-Il2CppDumper** (Perfare) | <https://github.com/Perfare/Zygisk-Il2CppDumper> | **MIT** | Magisk 24+ with Zygisk; module built per package (`game.h`); GitHub Actions build workflow included | Yes | **Root required** (Magisk), no repack | `dump.cs` written to `/data/data/<pkg>/files/`. Resolves the il2cpp API via `xdl`, so renamed/removed exports break it. |
| **Frida memory scan** (this repo, `docs/worldbox/dump-metadata.js`) | — | GPL-3.0 (repo) | Frida server/gadget + root (server) | Yes; also works on x86_64 emulator with ARM translation | Root or gadget | Raw decrypted `global-metadata.dat`, which is what static tools want. **Read-only; no hooks**, so it survives stripped/renamed exports. |
| **Il2CppMetadataExtractor** (CameroonD) | <https://github.com/CameroonD/Il2CppMetadataExtractor> | **MIT** | Frida; you must find the metadata-loader offset yourself (README explains how) | Yes | Root or gadget | Decrypted metadata, but more manual than the scan above. |
| **global-metadata_dump** (350030173) | <https://github.com/350030173/global-metadata_dump> | **no licence file** | Frida | Yes | Root | Automated metadata dump, but *no licence* = all rights reserved by default. Do not vendor it into this GPL repo. |
| **frida-il2cppDumper** (IIIIIMMMyyy) | <https://github.com/IIIIIMMMyyy/frida-il2cppDumper> | **no licence file** | Frida | Yes | Root | Claims support for 易盾-protected metadata. Same licence problem; reference only. |
| **objection** | <https://github.com/sensepost/objection> | **GPL-3.0** | Python; `objection patchapk` | Yes | **No root** — repacks APK with gadget | Automates the no-root gadget route (breaks the signature; fine for an offline game, unacceptable if you want to keep the Play install). |

Explicitly **not** recommended: uploading the APK to random web "IL2CPP dumper"
services. That republishes a commercial game binary to a third party, which is
both a licence problem and irreversible.

---

## 5. Android/emulator constraints that shape the plan

These are the constraints that make the naive "run Frida on a GitHub emulator"
plan fail, and they are the reason the workflow in this repo only *reads memory*.

1. **ARM64 system images cannot boot on x86_64 hosts for API ≥ 28.**
   QEMU2 aborts with `Avd's CPU Architecture 'arm64' is not supported by the
   QEMU2 emulator on x86_64 host`. GitHub-hosted `ubuntu-24.04-arm` runners have
   no `/dev/kvm`, so a native ARM64 emulator is not an option either. Practical
   consequence: the emulator you already got working is an **x86_64 image with
   ARM translation** (API 30 `google_apis` is the classic choice, and it also
   gives you `adb root`).
2. **Frida's x86_64 agent cannot hook ARM code running under translation.**
   `Interceptor.attach` on `il2cpp_init` fails, and `Process.enumerateModules()`
   may not list `libil2cpp.so` even though `/proc/<pid>/maps` shows it
   ([frida#3497](https://github.com/frida/frida/issues/3497),
   [frida-il2cpp-bridge#264](https://github.com/vfsfitvnm/frida-il2cpp-bridge/issues/264)).
   Frida's `--realm=emulated` exists, but the il2cpp bridge is not reliable there.
3. **…but reading that memory works fine.** The metadata is *data*, not code.
   `Memory.readByteArray` on the mapped region works with the x86_64 agent. This
   is the single most useful fact for CI-based analysis.
4. **`global-metadata.dat` is 20–80 MB.** Do not dump the whole address space;
   scan for the header and cut at the end of the containing mapping.

---

## 6. What is actually verified for this build

Keep this section honest when you report progress.

| Statement | Status |
| --- | --- |
| WorldBox 0.51.4 = versionCode 725, arm64-v8a + armeabi-v7a, minSdk 23, targetSdk 35, ≈181.5 MB bundle | **Verified** (APKMirror listing) |
| `global-metadata.dat` in this build does not start with `0xFAB11BAF` | **Reported by you**, reproducible with `triage-static.sh` |
| Il2CppDumper reports the metadata "may be encrypted" on this build | **Reported by you**; this is Il2CppDumper's documented refusal path, not a diagnosis of the cipher |
| REA's metadata reader does not decrypt it | **Reported by you**; consistent with REA being a reader, not a decryptor |
| arm64 `libil2cpp.so` symbols are "stripped or obfuscated" | **Unverified as harmful** — Android always strips `.symtab`; what matters is the **dynamic** export table. Check with the triage script before concluding anything |
| The game process runs ≥ 60 s on GH Actions under ARM translation | **Reported by you** |
| Any tool in §3/§4 can decrypt **this** metadata | **Not verified** — no such claim is made here |
| The memory-scan approach works on **this** build | **Not verified** — it is the highest-probability approach, and the workflow will produce evidence either way |
| Which Unity version / metadata version this build uses | **Unknown** — the triage report prints the version field if the header is readable |

---

## 7. Recommendation (most practical first)

### Step 0 — classify, 20 minutes, free, no root

Run `docs/worldbox/triage-static.sh` on your APK (or use the `static` job of the
workflow). Do not skip this: it decides whether you need any of the runtime
machinery at all, and it costs nothing.

* Blocks at 4–6 b/B with readable identifiers → **case B**, recover statically.
* Flat ≈ 8 b/B, zero identifiers → **case C**, go to Step 2.
* Plausible magic + plausible version but the dumper complains → **case A**, use
  a newer dumper (AndnixSH CLI, Cpp2IL) before anything else.
* Packer fingerprints / tiny `.text` → **case D**, runtime dump of both files.

### Step 1 — if case A or B: static recovery

```bash
# case A/B first attempts, cheapest first
Il2CppDumper libil2cpp.so global-metadata.dat out/         # upstream, MIT
Il2CppDumper libil2cpp.so global-metadata.dat out/ --fast  # AndnixSH CLI
Cpp2IL --game-path . --exe-name libil2cpp                    # second opinion
```

If the tables are plaintext but the header is scrambled, upstream Il2CppDumper
will keep refusing; that is expected. Options: Il2CppInspector **loader plugins**
(the only free, documented plugin API for metadata deobfuscation), or a ~100-line
script that locates the string table yourself (the string table is a dense block
of NUL-terminated identifiers; find it, then locate the type table by stride
scanning). Only worth it if step 0 really said "plaintext".

### Step 2 — if case C/D: dump the decrypted metadata from memory

**Preferred environment: the GH Actions emulator you already have running**
(x86_64 API 30 `google_apis`, `adb root`, ARM translation). It is slow but free,
reproducible and needs no Magisk. Use the read-only scanner in
§8.2. This sidesteps constraint §5.2 entirely.

**Preferred environment #2 (if you own one): a real ARM64 phone.**
Then a *hook-based* dump also works, and those give you more than the raw file:
`frida-il2cpp-bridge` (`dump` produces `dump.cs` with no metadata file at all),
or `Zygisk-Il2CppDumper` (Magisk + Zygisk, `dump.cs` in the app's files dir).
Both need `il2cpp_*` exports; check the triage report first.

**Last resort: break the cipher statically.** Hook-free, but real work:
find the string `global-metadata.dat` (or the asset-read call) in
`libil2cpp.so`, walk back to `MetadataLoader::LoadMetadataFile`, read the
decryption loop, reimplement it in Python, and validate by checking the output
magic. The methodology is documented in
[katyscode's "Finding loaders for obfuscated global-metadata.dat"](https://katyscode.wordpress.com/2021/02/23/il2cpp-finding-obfuscated-global-metadata/).

### What I would not do first

* Building a Magisk-patched emulator image (heavy, and Zygisk modules still need
  the ARM exports inside the translated process).
* Trying arm64 system images on x86_64 runners (QEMU refuses at API ≥ 28).
* Uploading the APK to an online dumper.
* Chasing `--ignore-magic`-style flags in random forks before knowing whether the
  tables are even plaintext.

---

## 8. Reproducible steps

Everything below uses **your own APK copy** and produces **no game data in git**.
The workflow expects the file via the repository secret `WORLDBOX_APK_URL`.

### 8.1 Static triage (local or CI, ~2 min)

```bash
# local: point it at the .apk / .apks / extracted split directory
bash docs/worldbox/triage-static.sh ~/Downloads/worldbox-0.51.4.apk report.md
less report.md
```

In CI: run the `static` job of
`.github/workflows/worldbox-metadata-dump.yml`
(Actions → *WorldBox IL2CPP triage* → *Run workflow*).

Read the report like this:

| Report says | Conclusion | Next |
| --- | --- | --- |
| `Standard IL2CPP magic` = NO, `Blocks below 6.0` ≈ all, identifiers > 0 | Header scrambled, tables plaintext (B) | Step 1 |
| Magic NO, every block ≈ 8.0, identifiers = 0 | Real cipher (C) | 8.2 |
| Magic YES, version implausible for the tool | Wrong tool version (A) | Step 1 with AndnixSH CLI / Cpp2IL |
| Packer fingerprints > 0, `Dynsym FUNC defined` ≈ 0 | Packed / exports gone (D) | 8.2, and expect every export-based tool to fail |
| No `global-metadata.dat` at all | Split bundle or embedded metadata | re-extract all splits |

### 8.2 Runtime memory scan on the GitHub Actions emulator

What the workflow does, step by step — you can replay it locally with the same
commands against a local emulator:

```bash
# 1. emulator: x86_64 API 30 google_apis  (adb root works, libndk_translation present)
#    create it with Android Studio / avdmanager as usual; on CI see the workflow.

adb root && adb wait-for-device
adb shell setenforce 0 || true                 # userdebug image; allows /proc/<pid>/mem if Frida is unavailable

# 2. frida-server must match the EMULATOR abi (x86_64), not the game's abi
FRIDA=17.25.0
curl -LO "https://github.com/frida/frida/releases/download/$FRIDA/frida-server-$FRIDA-android-x86_64.xz"
xz -d frida-server-$FRIDA-android-x86_64.xz
adb push frida-server-$FRIDA-android-x86_64 /data/local/tmp/frida-server
adb shell chmod 755 /data/local/tmp/frida-server
adb shell "nohup /data/local/tmp/frida-server -D >/dev/null 2>&1 &"
sleep 8 && frida-ps -U | head          # sanity: the server is reachable

# 3. install + launch, then give the engine time to decrypt
adb install -r -g worldbox-0.51.4.apk
adb shell monkey -p com.mkarpenko.worldbox -c android.intent.category.LAUNCHER 1
sleep 60
adb shell pidof com.mkarpenko.worldbox
adb shell "cat /proc/$(adb shell pidof com.mkarpenko.worldbox | tr -d '\r')/maps" | grep libil2cpp

# 4. read-only scan for the decrypted header (no hooks -> works across translation)
frida -U -F -l docs/worldbox/dump-metadata.js -q
adb pull /data/local/tmp/wb-meta ./wb-meta

# 5. validate the dump
python3 - <<'PY'
import glob, struct
for p in glob.glob('wb-meta/*.dat'):
    b = open(p, 'rb').read()
    print(p, len(b), hex(struct.unpack_from('<I', b, 0)[0]), struct.unpack_from('<i', b, 4)[0])
PY
```

Expected results and what to do with them:

| Outcome | Meaning | Action |
| --- | --- | --- |
| `candidate*.dat` starts with `0xFAB11BAF`, plausible version | Success — this is decrypted metadata | Run Il2CppDumper with the **matching** `libil2cpp.so` (§8.3) |
| Scan runs, nothing found, game alive | Metadata not decrypted yet, or not contiguous | Re-run with the world loaded; raise `attempts`; or dump the whole candidate region via `/proc/<pid>/mem` |
| `frida-ps` empty / attach refused | Server not running as root, or SELinux | `adb root`, `setenforce 0`, restart `frida-server` |
| `frida -F` attaches but the script cannot read ranges | Wrong process (the emulator's launcher) | Use `-n` with the process name from `frida-ps -Uai` |
| Process dies within seconds | Translation/ABI mismatch, or the game needs more RAM | `-memory 4096`, longer `wait_seconds` |
| Everything works but the header is still not `0xFAB11BAF` | The runtime keeps metadata encrypted per-page | Case D-extra: reverse the loader (§7 last resort) |

Fallback without Frida (only if attach keeps failing): with `adb root` +
`setenforce 0`, dump the candidate regions straight out of `/proc/<pid>/mem`.

```bash
PID=$(adb shell pidof com.mkarpenko.worldbox | tr -d '\r')
adb shell "cat /proc/$PID/maps" > maps.txt
# pick anonymous rw regions of 8-64 MB that look like a dedicated allocation, then:
adb shell "dd if=/proc/$PID/mem of=/data/local/tmp/r0.bin bs=4096 skip=$((0xSTART/4096)) count=$((SIZE/4096))"
adb pull /data/local/tmp/r0.bin
grep -abo $'\xaf\x1b\xb1\xfa' r0.bin | head
```

This is slower and clumsier than the Frida scan; treat it as a backup.

### 8.3 Pairing and validation

```bash
unzip -o worldbox-0.51.4.apk 'lib/arm64-v8a/libil2cpp.so' \
      'assets/bin/Data/Managed/Metadata/global-metadata.dat'

Il2CppDumper lib/arm64-v8a/libil2cpp.so wb-meta/global-metadata.candidate0_0.dat out/
```

Success criteria (do not skip them):

1. Il2CppDumper exits without "metadata file supplied is not valid".
2. `out/dump.cs` contains recognizable namespaces (e.g. a `WorldBox`-ish set) —
   check a couple against strings you already know from the game.
3. `out/script.json` addresses fall inside the `.text` range of the *arm64*
   `libil2cpp.so` (`readelf -S`), not into `.data`/beyond the file.
4. Re-running with the armeabi-v7a binary against the **same** metadata should
   also work — metadata is architecture-independent, so both pairs must parse.

If (3) fails, you paired a memory-dumped binary with an on-disk metadata file (or
vice versa). Dump both from the same process at the same time.

### 8.4 If the target has to be a real ARM64 device

```bash
# root + frida-server arm64, then either:
frida -U -f com.mkarpenko.worldbox -l docs/worldbox/dump-metadata.js --no-pause   # raw file
npm exec frida-il2cpp-bridge -- dump --out-dir out                                # dump.cs, no metadata needed

# or Magisk route:
# fork Perfare/Zygisk-Il2CppDumper, set GamePackageName in module/src/main/cpp/game.h,
# run its Build workflow, install the module zip, launch the game,
# pull /data/data/com.mkarpenko.worldbox/files/dump.cs
```

No-root alternative: `objection patchapk --source worldbox-0.51.4.apk` (injects
`frida-gadget`, re-signs, repackages) — the gadget then runs in the same ARM
context as `libil2cpp.so`, so hooks work. This is the one path that works on a
stock, non-rooted ARM64 phone. It changes the APK signature, so keep a separate
install and never publish the patched package.

---

## 9. Handling rules (game files must not be published)

* Never commit the APK, `libil2cpp.so`, `global-metadata.dat`, `dump.cs` or
  `script.json` from a commercial title into this (or any public) repository.
* CI artifacts: on **public** repositories, artifacts are downloadable by any
  signed-in GitHub user. The workflow therefore uploads only aggregate reports by
  default, and the payload upload is opt-in (`upload_payload`) for private repos.
* Prefer publishing **derived knowledge** only: offsets, hashes of *your* dump,
  type names you need for a patch, and the tooling itself.
* Short-lived signed URLs for `WORLDBOX_APK_URL`; rotate them after a run.
* This repo is GPL-3.0: don't vendor code from repositories without a licence
  (two of the dumpers in §4 have none), and note that Il2CppInspector is AGPL-3.0.

Relation to Morphe patches: the Morphe patcher APIs documented upstream operate
on dex/smali (`Document`, `smali`) and resources. Nothing in those docs covers
rewriting `lib/**/*.so`. So IL2CPP work here is **patch-development research**,
not something a Morphe patch can currently ship — verify before promising a
WorldBox patch to users.

---

## 10. Open questions / next experiments

1. What is the metadata version field, and is the header merely scrambled?
   (`triage-static.sh` — decides between case A/B and C.)
2. Does the arm64 `libil2cpp.so` still export `il2cpp_init`,
   `il2cpp_class_from_name`, …? (If yes, the whole export-based family is usable;
   if no, only memory scanning is.)
3. Does the app on the CI emulator map `libil2cpp.so` from `/data/app/...`, and
   is `ro.dalvik.vm.native.bridge` = `libndk_translation.so`?
4. Does the memory scan find `0xFAB11BAF` after 60 s, or only after a world is
   running?
5. If it finds nothing: is the metadata region readable but still encrypted
   (case C + lazy decryption), or is the scan simply looking at the wrong ranges?

Each of these is a small, cheap experiment; run them in that order and record the
answers at the top of this file rather than in chat.

---

## 11. Sources checked (2026-10-30)

* APKMirror — WorldBox 0.51.4 (725) listing, ABIs, SDK levels, size.
* GitHub REST API — repository licence, description, last push and release tags
  for every tool in §3/§4 (Il2CppDumper MIT, Zygisk-Il2CppDumper MIT,
  Il2CppInspector AGPL-3.0, Cpp2IL MIT, frida-il2cpp-bridge MIT, REA MIT,
  Ghidra Apache-2.0, rizin/radare2 LGPL-3.0, apktool Apache-2.0,
  uber-apk-signer Apache-2.0, objection GPL-3.0, Magisk GPL-3.0,
  android-emulator-runner Apache-2.0).
* Upstream READMEs — Il2CppDumper feature list; Zygisk-Il2CppDumper usage;
  frida-il2cpp-bridge compatibility (Unity 5.3.0 – 6000.3.x, Android tested);
  Il2CppInspector obfuscation/loader-plugin and memory-map support;
  Cpp2IL status; Android emulator KVM guidance.
* QEMU2/Android emulator: `arm64` guest refused on `x86_64` host for API ≥ 28.
* frida#3497 and frida-il2cpp-bridge#264 — x86_64 agent versus translated ARM
  code; memory reads still work.
* katyscode — IL2CPP structural overview and "Finding loaders for obfuscated
  global-metadata.dat" methodology.

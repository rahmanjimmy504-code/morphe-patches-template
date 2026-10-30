#!/usr/bin/env bash
# Static triage for a Unity IL2CPP Android package.
#
# Purpose: collect static indicators before spending time on
# a dumper. These indicators do not establish the protection scheme. It prints a redacted, aggregate-only report: hashes, sizes, header
# bytes, entropy, string COUNTS and ELF/symbol statistics. It never prints the
# game's type names, string literals or disassembly, so the report is safe to
# attach to an issue or a CI artifact.
#
# Usage:
#   ./triage-static.sh <app.apk|app.apks|extracted-dir> [report.md]
#
# Requirements: bash, unzip, python3, readelf (binutils), strings, sha256sum.
# No root, no network, no modified APK. The input is only read, never written.

set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "usage: $0 <app.apk|app.apks|extracted-dir> [report.md]" >&2
  exit 2
fi

INPUT="$1"
REPORT="${2:-worldbox-triage-report.md}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# ------------------------------------------------------------------ extraction
if [[ -d "$INPUT" ]]; then
  EXDIR="$INPUT"
else
  mkdir -p "$WORK/apk"
  # A .apks / .apkm / .xapk is a zip of zips or a zip of splits; try both levels.
  unzip -q -o "$INPUT" -d "$WORK/apk" 2>/dev/null || true
  # .apks/.apkm/.xapk wrap one or more split APKs at an arbitrary depth.
  while IFS= read -r nested; do
    [[ -f "$nested" ]] || continue
    d="${nested%.apk}.d"
    mkdir -p "$d"
    unzip -q -o "$nested" -d "$d" 2>/dev/null || true
  done < <(find "$WORK/apk" -mindepth 1 -type f -name '*.apk' 2>/dev/null)
  EXDIR="$WORK/apk"
fi

find "$EXDIR" -maxdepth 9 -type f -name 'global-metadata.dat' -print 2>/dev/null | sort >"$WORK/metadata.txt" || true
find "$EXDIR" -maxdepth 9 -type f -name '*.so' -print 2>/dev/null | sort >"$WORK/so.txt" || true

# ------------------------------------------------------------------- report head
{
  echo "# Static IL2CPP triage report"
  echo
  echo "- Generated (UTC): $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "- Input: \`$(basename "$INPUT")\`"
  if [[ -f "$INPUT" ]]; then
    echo "- Input SHA-256: \`$(sha256sum "$INPUT" | cut -d' ' -f1)\`"
  fi
  echo "- Tool: \`docs/worldbox/triage-static.sh\`"
  echo
  echo "This report contains aggregates only: no type names, no string literals, no code."
  echo
} >"$WORK/01-head.md"

# --------------------------------------------------------------- 1. metadata
{
  echo "## 1. global-metadata.dat"
  echo
  if [[ ! -s "$WORK/metadata.txt" ]]; then
    echo "> No \`global-metadata.dat\` found in the package."
    echo ">"
    echo "> Either the metadata is embedded inside \`libil2cpp.so\` (some Unity 6 builds),"
    echo "> or the package is split and only one split was fetched. Extract every split"
    echo "> (\`.apks\` / \`.apkm\` / \`.xapk\`) before drawing conclusions."
    echo
  else
    while IFS= read -r m; do
      echo "### \`${m#"$EXDIR"/}\`"
      echo
      echo "| Property | Value |"
      echo "| --- | --- |"
      python3 - "$m" <<'PY'
import sys, math, collections, hashlib, re

data = open(sys.argv[1], 'rb').read()
size = len(data)

def entropy(b):
    if not b:
        return 0.0
    c = collections.Counter(b)
    n = len(b)
    return -sum((v / n) * math.log2(v / n) for v in c.values())

magic = int.from_bytes(data[0:4], 'little') if size >= 4 else 0
version = int.from_bytes(data[4:8], 'little') if size >= 8 else 0
ok = magic == 0xFAB11BAF
plausible_version = 16 <= version <= 40 or 100 <= version <= 120

print(f"| Size | {size:,} bytes |")
print(f"| SHA-256 | `{hashlib.sha256(data).hexdigest()}` |")
print(f"| First 16 bytes | `{data[0:16].hex(' ')}` |")
print(f"| Magic as LE u32 | `0x{magic:08X}` |")
print(f"| Standard IL2CPP magic (0xFAB11BAF) | {'**YES**' if ok else '**NO**'} |")
print(f"| Version field (u32 @4) | `{version}` {'(plausible)' if plausible_version else '(IMPLAUSIBLE)'} |")
print(f"| Whole-file entropy (bits/byte) | {entropy(data):.2f} |")

blocks = [entropy(data[i:i + 65536]) for i in range(0, size, 65536)]
if blocks:
    print(f"| 64 KiB block entropy min / mean / max | {min(blocks):.2f} / {sum(blocks)/len(blocks):.2f} / {max(blocks):.2f} |")
    print(f"| Blocks below 6.0 b/B (plaintext-ish) | {sum(1 for b in blocks if b < 6.0)}/{len(blocks)} |")

runs = re.findall(rb'[ -~]{8,}', data)
print(f"| Printable ASCII runs >= 8 chars | {len(runs):,} |")
for needle in (b'mscorlib', b'System.Private.CoreLib', b'UnityEngine', b'Assembly-CSharp'):
    print(f"| Occurrences of `{needle.decode()}` | {data.count(needle):,} |")

if size >= 0x40:
    fields = [int.from_bytes(data[i:i + 4], 'little') for i in range(0, 0x40, 4)]
    print(f"| First 16 u32 header fields within file size | {sum(1 for f in fields if f == 0 or f <= size)}/16 |")
PY
      echo
    done <"$WORK/metadata.txt"
  fi
} >"$WORK/02-metadata.md"

# ----------------------------------------------------------- 2. native libraries
{
  echo "## 2. Native libraries"
  echo
  if [[ ! -s "$WORK/so.txt" ]]; then
    echo "> No \`.so\` files found (split APK? use the \`.apks\` bundle / all splits)."
    echo
  else
    echo "| Path | Class | Machine | Size | Sections | Dynsym entries | Dynsym FUNC defined |"
    echo "| --- | --- | --- | --- | --- | --- | --- |"
    while IFS= read -r s; do
      rel="${s#"$EXDIR"/}"
      size=$(stat -c%s "$s" 2>/dev/null || echo '?')
      if [[ "$(head -c4 "$s" 2>/dev/null || true)" != $'\x7fELF' ]]; then
        echo "| \`$rel\` | not an ELF | - | $size | - | - | - |"
        continue
      fi
      cls=$(readelf -h "$s" 2>/dev/null | awk -F: '/Class:/{gsub(/^ +/,"",$2); print $2; exit}')
      mach=$(readelf -h "$s" 2>/dev/null | awk -F: '/Machine:/{gsub(/^ +/,"",$2); print $2; exit}')
      secs=$(readelf -S -W "$s" 2>/dev/null | grep -c '^\s*\[' || true)
      dyn=$(readelf --dyn-syms -W "$s" 2>/dev/null | awk '$7!="UND" && NF>=8' | wc -l)
      funcs=$(readelf --dyn-syms -W "$s" 2>/dev/null | awk '$4=="FUNC" && $7!="UND"' | wc -l)
      echo "| \`$rel\` | ${cls:-?} | ${mach:-?} | $size | ${secs:-?} | $dyn | $funcs |"
    done <"$WORK/so.txt"
    echo

    IL2CPP="$(grep -E '/libil2cpp\.so$' "$WORK/so.txt" | head -1 || true)"
    if [[ -n "$IL2CPP" ]]; then
      echo "### libil2cpp.so details (\`${IL2CPP#"$EXDIR"/}\`)"
      echo
      echo "| Property | Value |"
      echo "| --- | --- |"
      for sym in il2cpp_init il2cpp_domain_get il2cpp_class_from_name il2cpp_thread_attach il2cpp_assembly_get_image; do
        if readelf --dyn-syms -W "$IL2CPP" 2>/dev/null | grep -qw "$sym"; then
          echo "| Export \`$sym\` | present |"
        else
          echo "| Export \`$sym\` | **absent** |"
        fi
      done
      if readelf -S -W "$IL2CPP" 2>/dev/null | grep -q '\.symtab'; then
        echo "| \`.symtab\` present (non-dynamic symbols) | yes |"
      else
        echo "| \`.symtab\` present (non-dynamic symbols) | no |"
      fi
      for pat in libjiagu libDexHelper libnesec libmobisec libappsealing libsgmain 'upx!' libmetasec; do
        n=$(strings -a -n 6 "$IL2CPP" 2>/dev/null | grep -c -i -- "$pat" || true)
        echo "| Fingerprint \`$pat\` | $n hit(s) |"
      done
      echo
      echo "Interpretation:"
      echo
      echo "- A missing \`.symtab\` is **normal** on Android and harmless. It only matters if"
      echo "  the **dynsym** exports above are absent too, because that breaks every"
      echo "  export-based tool (Zygisk-Il2CppDumper, frida-il2cpp-bridge, Interceptor.attach)."
      echo "- Il2CppDumper does not need symbols at all: it pattern-scans for"
      echo "  Il2CppCodeRegistration / Il2CppMetadataRegistration."
      echo "- A packer fingerprint is a strong hint that the file on disk is not the"
      echo "  file that runs; runtime inspection may be useful in that case."
      echo
    fi
  fi
} >"$WORK/03-libs.md"

cat "$WORK/01-head.md" "$WORK/02-metadata.md" "$WORK/03-libs.md" >"$REPORT"

echo "Report written to: $REPORT"
echo
echo "Next: review the limitations and observations in docs/worldbox-research.md"
echo "(plaintext tables / scrambled header / real cipher / packed binary)."

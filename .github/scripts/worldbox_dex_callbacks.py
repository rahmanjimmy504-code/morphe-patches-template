#!/usr/bin/env python3
"""Map Android DEX purchase bridge declarations and callback implementers.

This is structural evidence only: it does not infer IL2CPP behavior or establish
that a Java callback grants the game's Premium entitlement.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import zipfile
from pathlib import Path
from typing import Iterable

TARGET = re.compile(r"L([^;]+);->([^ (]+)(\([^)]*\)[^ ]*)?")
FOCUS = re.compile(r"purchas|billing|product|receipt|UnitySendMessage|IUnityCallback", re.I)


def java_name(value: str) -> str:
    return value.strip(";L").replace("/", ".")


def _call_targets(method) -> list[str]:
    code = method.get_code()
    if code is None:
        return []
    result = []
    for instruction in code.get_bc().get_instructions():
        output = instruction.get_output()
        if not output:
            continue
        for match in TARGET.finditer(output):
            owner, name, signature = match.groups()
            result.append(f"{java_name(owner)}->{name}{signature or ''}")
    return result


def analyze_classes(classes: Iterable) -> dict:
    classes = list(classes)
    defs = {java_name(cls.get_name()): cls for cls in classes}
    callback = "com.unity.purchasing.common.IUnityCallback"
    implementers = []
    focus_methods = []
    callback_reference_classes = []
    callback_reference_methods = []
    purchasing_bridge_classes = []
    callback_def = defs.get(callback)
    callback_methods = []
    if callback_def:
        callback_methods = [
            {"name": method.get_name(), "descriptor": method.get_descriptor()}
            for method in callback_def.get_methods()
        ]
    callback_signatures = {(row["name"], row["descriptor"]) for row in callback_methods}

    for class_name, cls in sorted(defs.items()):
        interfaces = sorted(java_name(i) for i in (cls.get_interfaces() or []))
        if callback in interfaces:
            implemented = [
                {"name": method.get_name(), "descriptor": method.get_descriptor()}
                for method in cls.get_methods()
                if (method.get_name(), method.get_descriptor()) in callback_signatures
            ]
            implementers.append({"class": class_name, "interfaces": interfaces, "callbackMethods": implemented})

        fields = []
        for field in cls.get_fields():
            field_type = field.get_descriptor()
            if callback.replace('.', '/') in field_type:
                fields.append({"name": field.get_name(), "descriptor": field_type})
        if fields:
            callback_reference_classes.append({"class": class_name, "fields": fields})

        bridge_methods = []
        for method in cls.get_methods():
            calls = _call_targets(method)
            descriptor = method.get_descriptor()
            row = {
                "class": class_name,
                "method": method.get_name(),
                "descriptor": descriptor,
                "calls": [target for target in calls if FOCUS.search(target) or "UnityPurchasing" in target or "UnityPlayer" in target],
            }
            if class_name == "com.unity.purchasing.common.UnityPurchasing":
                bridge_methods.append(row)
            if callback.replace('.', '/') in descriptor or any(callback in target for target in calls):
                callback_reference_methods.append(row)

            searchable = " ".join((class_name, method.get_name(), descriptor, *calls))
            if FOCUS.search(searchable):
                focus_methods.append({
                    "class": class_name,
                    "method": method.get_name(),
                    "descriptor": descriptor,
                    "calls": [target for target in calls if FOCUS.search(target) or "UnityPurchasing" in target],
                })
        if class_name == "com.unity.purchasing.common.UnityPurchasing":
            purchasing_bridge_classes.append({"class": class_name, "methods": bridge_methods})

    return {
        "classesScanned": len(defs),
        "callbackInterfaceFound": callback in defs,
        "callbackMethods": callback_methods,
        "callbackImplementers": implementers,
        "callbackReferenceClasses": callback_reference_classes,
        "callbackReferenceMethods": callback_reference_methods,
        "purchasingBridgeClasses": purchasing_bridge_classes,
        "focusedMethods": focus_methods[:160],
        "limitations": "DEX declarations and call-site references only; dynamic dispatch, reflection, Unity native behavior and Premium entitlement semantics are not established.",
    }


def analyze_apks(paths: Iterable[Path]) -> dict:
    from androguard.core.dex import DEX

    rows = []
    for path in paths:
        with zipfile.ZipFile(path) as apk:
            for name in sorted(n for n in apk.namelist() if re.fullmatch(r"classes(?:\d+)?\.dex", Path(n).name)):
                dex = DEX(apk.read(name))
                result = analyze_classes(dex.get_classes())
                rows.append({"apk": path.name, "dex": name, **result})
    return {"kind": "worldbox-dex-callback-map", "dexFiles": rows}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("apks", nargs="+", type=Path, help="Extracted APK splits (kept temporary by caller).")
    args = parser.parse_args()
    try:
        report = analyze_apks(args.apks)
    except Exception as exc:
        print(f"DEX callback analysis failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(report, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

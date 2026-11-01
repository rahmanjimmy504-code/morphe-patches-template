"""Synthetic unit tests for DEX purchase-bridge structural analysis."""
from pathlib import Path
import sys
import unittest
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / ".github/scripts"))
import worldbox_dex_callbacks as probe


class FakeCode:
    def __init__(self, outputs):
        self.outputs = outputs

    def get_bc(self):
        return self

    def get_instructions(self):
        return [SimpleNamespace(get_output=lambda text=text: text) for text in self.outputs]


class FakeMethod:
    def __init__(self, name, descriptor="()V", outputs=(), code=True):
        self.name, self.descriptor = name, descriptor
        self.code = FakeCode(outputs) if code else None

    def get_name(self): return self.name
    def get_descriptor(self): return self.descriptor
    def get_code(self): return self.code


class FakeClass:
    def __init__(self, name, interfaces=(), methods=(), fields=()):
        self.name, self.interfaces, self.methods, self.fields = name, interfaces, methods, fields

    def get_name(self): return self.name
    def get_interfaces(self): return self.interfaces
    def get_methods(self): return self.methods
    def get_fields(self): return self.fields


class DexCallbackProbeTest(unittest.TestCase):
    def test_maps_callback_interface_and_implementation_calls(self):
        interface = FakeClass(
            "Lcom/unity/purchasing/common/IUnityCallback;",
            methods=[FakeMethod("OnPurchaseSucceeded", "(Ljava/lang/String;)V", code=False)],
        )
        handler = FakeClass(
            "Lgame/StoreBridge;",
            interfaces=["Lcom/unity/purchasing/common/IUnityCallback;"],
            methods=[FakeMethod("OnPurchaseSucceeded", "(Ljava/lang/String;)V", outputs=[
                "v0, Lcom/unity/purchasing/common/UnityPurchasing;->OnPurchaseSucceeded(Ljava/lang/String;)V"
            ])],
        )
        bridge = FakeClass(
            "Lcom/unity/purchasing/common/UnityPurchasing;",
            methods=[FakeMethod("<init>", "(Lcom/unity/purchasing/common/IUnityCallback;)V")],
        )
        report = probe.analyze_classes([interface, handler, bridge])
        self.assertTrue(report["callbackInterfaceFound"])
        self.assertEqual(report["callbackMethods"][0]["name"], "OnPurchaseSucceeded")
        self.assertEqual(report["callbackImplementers"][0]["class"], "game.StoreBridge")
        self.assertEqual(report["callbackImplementers"][0]["callbackMethods"][0]["name"], "OnPurchaseSucceeded")
        self.assertEqual(report["callbackReferenceMethods"][0]["class"], "com.unity.purchasing.common.UnityPurchasing")
        self.assertEqual(report["purchasingBridgeClasses"][0]["methods"][0]["method"], "<init>")
        focused = next(row for row in report["focusedMethods"] if row["class"] == "game.StoreBridge")
        self.assertIn("com.unity.purchasing.common.UnityPurchasing->OnPurchaseSucceeded(Ljava/lang/String;)V", focused["calls"])
        self.assertIn("not established", report["limitations"])

    def test_ignores_unrelated_methods_and_handles_missing_code(self):
        unrelated = FakeClass("Lgame/Other;", methods=[FakeMethod("tick", code=False)])
        report = probe.analyze_classes([unrelated])
        self.assertEqual(report["classesScanned"], 1)
        self.assertFalse(report["callbackInterfaceFound"])
        self.assertEqual(report["focusedMethods"], [])

    def test_java_name_normalization(self):
        self.assertEqual(probe.java_name("Lfoo/bar/Baz;"), "foo.bar.Baz")


if __name__ == "__main__":
    unittest.main()

"""Count exact WorldBox bridge/Premium name leads in opaque metadata bytes."""

NEEDLES = {
    "unity_purchasing": "UnityPurchasing",
    "unity_callback": "IUnityCallback",
    "purchase_succeeded": "OnPurchaseSucceeded",
    "products_retrieved": "OnProductsRetrieved",
    "purchase_failed": "OnPurchaseFailed",
    "premium_elements_checker": "PremiumElementsChecker",
    "premium_window": "PremiumWindow",
    "premium_unlock_animation": "PremiumUnlockAnimation",
}


def _overlapping_count(data: bytes, needle: bytes) -> int:
    count = 0
    offset = 0
    while True:
        position = data.find(needle, offset)
        if position < 0:
            return count
        count += 1
        offset = position + 1


def count_string_leads(data: bytes) -> dict[str, dict[str, int]]:
    """Return exact ASCII and UTF-16LE occurrence counts without retaining data."""
    return {
        label: {
            "ascii": _overlapping_count(data, text.encode("ascii")),
            "utf16le": _overlapping_count(data, text.encode("utf-16le")),
        }
        for label, text in NEEDLES.items()
    }

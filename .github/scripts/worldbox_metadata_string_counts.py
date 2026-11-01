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


def printable_run_contexts(data: bytes, text: str, limit: int = 4, radius: int = 64) -> list[str]:
    """Return bounded printable runs containing a target marker, without offsets."""
    marker = text.encode("ascii")
    contexts: list[str] = []
    seen: set[str] = set()
    position = data.find(marker)
    while position >= 0:
        start = position
        while start > 0 and position - start < radius and 0x20 <= data[start - 1] <= 0x7e:
            start -= 1
        end = position + len(marker)
        while end < len(data) and end - (position + len(marker)) < radius and 0x20 <= data[end] <= 0x7e:
            end += 1
        context = data[start:end].decode("ascii")
        if context not in seen:
            seen.add(context)
            contexts.append(context)
        if len(contexts) >= limit:
            break
        position = data.find(marker, position + 1)
    return contexts

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


def nearby_identifier_runs(data: bytes, text: str, radius: int = 256, limit: int = 4) -> list[str]:
    """Return a few nearby NUL-delimited identifier-like strings as weak context.

    This is a neighborhood heuristic only; proximity in the file is not a
    metadata reference or semantic relationship. Raw bytes and offsets are
    never returned.
    """
    marker = text.encode("ascii")
    candidates: list[tuple[int, str]] = []
    position = data.find(marker)
    while position >= 0:
        low = max(0, position - radius)
        high = min(len(data), position + len(marker) + radius)
        target_start = data.rfind(b"\0", 0, position) + 1
        previous_separator = data.rfind(b"\0", 0, max(0, target_start - 1))
        cursor = max(0, previous_separator + 1)
        if cursor < low and low - cursor > 80:
            cursor = data.rfind(b"\0", low, position) + 1
            if cursor == 0 and low > 0:
                cursor = low
        while cursor < high:
            end = data.find(b"\0", cursor, high)
            if end < 0:
                break
            token = data[cursor:end]
            if (token and marker not in token and len(token) <= 80 and
                    all(0x21 <= byte <= 0x7e for byte in token) and
                    all(chr(byte).isalnum() or chr(byte) in "_.$`<>+-" for byte in token)):
                distance = min(abs(position - end), abs(cursor - (position + len(marker))))
                candidates.append((distance, token.decode("ascii")))
            cursor = end + 1
        position = data.find(marker, position + 1)
    unique: list[tuple[int, str]] = []
    seen: set[str] = set()
    for distance, name in sorted(candidates):
        if name not in seen:
            seen.add(name)
            unique.append((distance, name))
        if len(unique) == limit:
            break
    return [name for _, name in unique]

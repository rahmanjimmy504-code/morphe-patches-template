"""Count exact WorldBox bridge/Premium name leads in opaque metadata bytes."""

from collections import Counter
import struct

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


def _overlapping_offsets(data: bytes, needle: bytes, limit: int = 8) -> list[int]:
    positions: list[int] = []
    offset = 0
    while len(positions) < limit:
        position = data.find(needle, offset)
        if position < 0:
            break
        positions.append(position)
        offset = position + 1
    return positions


def _overlapping_count(data: bytes, needle: bytes) -> int:
    count = 0
    offset = 0
    while True:
        position = data.find(needle, offset)
        if position < 0:
            return count
        count += 1
        offset = position + 1


def occurrence_offsets(data: bytes, text: str, limit: int = 8) -> list[int]:
    """Return capped relative offsets for targeted exact ASCII markers."""
    return _overlapping_offsets(data, text.encode("ascii"), limit)


def candidate_string_heap_bases(data: bytes, texts: tuple[str, ...], min_support: int = 4) -> dict[str, int]:
    """Score aligned bases whose relative marker offsets recur as little-endian u32s.

    This deliberately does not claim to parse IL2CPP tables; false candidates
    are possible in arbitrary binary data and must be validated structurally.
    """
    offsets = sorted({offset for text in texts for offset in occurrence_offsets(data, text)})
    if len(offsets) < min_support:
        return {"anchorCount": len(offsets), "candidateCount": 0,
                "maximumSupport": 0, "maximumSupportCandidateCount": 0}
    aligned_size = len(data) & ~3
    words = Counter(value for (value,) in struct.iter_unpack("<I", data[:aligned_size]) if value <= len(data))
    candidate_bases: set[int] = set()
    for offset in offsets:
        for value in words:
            base = offset - value
            if 0 < base < offset and base % 4 == 0:
                candidate_bases.add(base)
    support_counts = []
    for base in candidate_bases:
        support = sum(offset > base and offset - base in words for offset in offsets)
        if support >= min_support:
            support_counts.append(support)
    maximum_support = max(support_counts, default=0)
    return {"anchorCount": len(offsets), "candidateCount": len(support_counts),
            "maximumSupport": maximum_support,
            "maximumSupportCandidateCount": sum(support == maximum_support for support in support_counts)}


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


def nearby_null_identifiers(data: bytes, text: str, radius: int = 4096, limit: int = 8) -> list[str]:
    """Return a few nearby NUL-delimited identifier-like tokens, not their offsets."""
    marker = text.encode("ascii")
    candidates: list[tuple[int, str]] = []
    position = data.find(marker)
    while position >= 0:
        low = max(0, position - radius)
        high = min(len(data), position + len(marker) + radius)
        cursor = data.rfind(b"\0", 0, low) + 1
        while cursor < high:
            end = data.find(b"\0", cursor, high)
            if end < 0:
                break
            token = data[cursor:end]
            if (5 <= len(token) <= 80 and marker not in token and
                    all(0x21 <= byte <= 0x7e for byte in token) and
                    any(chr(byte).isalpha() for byte in token) and
                    all(chr(byte).isalnum() or chr(byte) in "_.$`<>+-" for byte in token)):
                distance = position - end if end <= position else cursor - (position + len(marker))
                candidates.append((abs(distance), token.decode("ascii")))
            cursor = end + 1
        position = data.find(marker, position + 1)
    result: list[str] = []
    seen: set[str] = set()
    for _, token in sorted(candidates):
        if token not in seen:
            seen.add(token)
            result.append(token)
        if len(result) >= limit:
            break
    return result

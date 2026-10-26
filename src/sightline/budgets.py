"""Per-tag daily token budgets, WARN mode only.

Caller tags are not authenticated, so a budget must never block a request: it only records a
``budget:<prefix>`` reason that dashboards and foundry alert on.
"""

from __future__ import annotations

import calendar
import time

from .store import Store


def day_start(now: float) -> float:
    """The start of the UTC day containing ``now`` -- UTC, never local time."""
    t = time.gmtime(now)
    return float(calendar.timegm((t.tm_year, t.tm_mon, t.tm_mday, 0, 0, 0, 0, 0, 0)))


def budget_reason(budgets: dict, store: Store, tag: str | None, tokens: int, now: float) -> str | None:
    """Return ``f"budget:{p}"`` if the longest matching prefix's daily total would be exceeded.

    ``None`` if the tag is falsy or no prefix of ``budgets`` matches. When several prefixes match, the
    longest one wins.
    """
    if not tag:
        return None
    p = None
    for prefix in budgets:
        if tag.startswith(prefix):
            if p is None or len(prefix) > len(p):
                p = prefix
    if p is None:
        return None
    if store.tag_tokens_since(p, day_start(now)) + tokens > budgets[p]:
        return f"budget:{p}"
    return None

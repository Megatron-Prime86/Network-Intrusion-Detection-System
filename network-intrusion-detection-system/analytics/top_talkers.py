"""Rank source IPs by packet volume."""

from __future__ import annotations

from collections import Counter
from typing import Any


def get_top_talkers(packets: list[dict[str, Any]], limit: int = 10) -> list[tuple[str, int]]:
    """Return the most active source IPs by packet count.

    Args:
        packets: Parsed packets, each expected to have a `src_ip` key.
        limit: Maximum number of source IPs to return.

    Returns:
        A list of `(src_ip, count)` tuples, most active first.
    """
    counter: Counter = Counter()
    for packet in packets:
        counter[packet["src_ip"]] += 1
    return counter.most_common(limit)

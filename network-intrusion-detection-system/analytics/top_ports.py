"""Rank destination ports by how often they were contacted."""

from __future__ import annotations

from collections import Counter
from typing import Any


def get_top_ports(packets: list[dict[str, Any]], limit: int = 10) -> list[tuple[int, int]]:
    """Return the most frequently contacted destination ports.

    Args:
        packets: Parsed packets, each expected to have a `dst_port` key.
        limit: Maximum number of ports to return.

    Returns:
        A list of `(port, count)` tuples, most frequent first. Packets
        with no destination port (e.g. non-TCP/UDP) are excluded.
    """
    counter: Counter = Counter()
    for packet in packets:
        if packet["dst_port"]:
            counter[packet["dst_port"]] += 1
    return counter.most_common(limit)

"""Count packets per protocol."""

from __future__ import annotations

from collections import Counter
from typing import Any


def analyze_protocols(packets: list[dict[str, Any]]) -> Counter:
    """Count how many packets were seen for each protocol.

    Args:
        packets: Parsed packets, each expected to have a `protocol` key.

    Returns:
        A `Counter` mapping protocol -> packet count.
    """
    protocol_counter: Counter = Counter()
    for packet in packets:
        protocol_counter[packet["protocol"]] += 1
    return protocol_counter

"""Summarize a run's alerts into top-level statistics."""

from __future__ import annotations

from collections import Counter
from typing import Any, TypedDict


class RunStatistics(TypedDict):
    total_alerts: int
    most_common_attack: str
    most_active_source: str


def generate_statistics(alerts: list[dict[str, Any]]) -> RunStatistics:
    """Compute summary statistics from a batch of alerts.

    Args:
        alerts: Alerts to summarize, each expected to have `attack` and
            `src_ip` keys.

    Returns:
        A `RunStatistics` dict with the total alert count, the most
        frequently seen attack type, and the most active source IP.
        Falls back to `"None"` for either field when `alerts` is empty.
    """
    attack_counter: Counter[str] = Counter()
    ip_counter: Counter[str] = Counter()

    for alert in alerts:
        attack_counter[alert["attack"]] += 1
        ip_counter[alert["src_ip"]] += 1

    return {
        "total_alerts": len(alerts),
        "most_common_attack": (
            attack_counter.most_common(1)[0][0] if attack_counter else "None"
        ),
        "most_active_source": (
            ip_counter.most_common(1)[0][0] if ip_counter else "None"
        ),
    }

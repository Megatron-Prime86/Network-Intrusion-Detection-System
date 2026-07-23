"""Reduce alerts down to a compact Indicator-of-Compromise (IOC) summary."""

from __future__ import annotations

from typing import TypedDict

from detections.port_scan import Alert


class IOC(TypedDict):
    src_ip: str
    attack: str


def extract_iocs(alerts: list[Alert]) -> list[IOC]:
    """Extract the source-IP/attack-type pair from each alert.

    Args:
        alerts: Enriched or raw alerts to summarize.

    Returns:
        One `IOC` per alert, preserving order and duplicates (a source IP
        flagged for two different attacks yields two IOC entries).
    """
    return [{"src_ip": alert["src_ip"], "attack": alert["attack"]} for alert in alerts]

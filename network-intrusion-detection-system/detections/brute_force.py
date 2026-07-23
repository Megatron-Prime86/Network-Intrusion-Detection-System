"""Detect brute-force behavior: repeated connection attempts to one port."""

from __future__ import annotations

from collections import defaultdict

from data.packet_types import ParsedPacket
from detections.port_scan import Alert

# Minimum number of connection attempts from one source IP to a single
# destination port before it's flagged as a credential brute-force attempt.
BRUTE_FORCE_THRESHOLD = 5


def detect_bruteforce(packets: list[ParsedPacket]) -> list[Alert]:
    """Flag source/port pairs with an unusually high number of attempts.

    Args:
        packets: Parsed packets to analyze (see `data.pcap_loader.load_pcap`).

    Returns:
        One `Alert` per (source IP, destination port) pair whose attempt
        count meets or exceeds `BRUTE_FORCE_THRESHOLD`.
    """
    attempts: dict[tuple[str, int | None], int] = defaultdict(int)

    for packet in packets:
        key = (packet["src_ip"], packet["dst_port"])
        attempts[key] += 1

    return [
        {"src_ip": src_ip, "attack": "Brute Force"}
        for (src_ip, _dst_port), count in attempts.items()
        if count >= BRUTE_FORCE_THRESHOLD
    ]

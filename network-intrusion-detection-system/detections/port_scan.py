"""Detect port-scanning behavior: one source IP touching many distinct ports."""

from __future__ import annotations

from collections import defaultdict
from typing import TypedDict

from data.packet_types import ParsedPacket

# Minimum number of distinct destination ports a single source IP must
# touch within the analyzed packet set before it's flagged as a scan.
PORT_SCAN_THRESHOLD = 4


class Alert(TypedDict):
    """A raw detection hit before MITRE/risk enrichment."""

    src_ip: str
    attack: str


def detect_port_scans(packets: list[ParsedPacket]) -> list[Alert]:
    """Flag source IPs that contacted an unusually wide spread of ports.

    Args:
        packets: Parsed packets to analyze (see `data.pcap_loader.load_pcap`).

    Returns:
        One `Alert` per source IP whose distinct destination-port count
        meets or exceeds `PORT_SCAN_THRESHOLD`.
    """
    scanned_ports: dict[str, set] = defaultdict(set)

    for packet in packets:
        scanned_ports[packet["src_ip"]].add(packet["dst_port"])

    return [
        {"src_ip": ip, "attack": "Port Scan"}
        for ip, ports in scanned_ports.items()
        if len(ports) >= PORT_SCAN_THRESHOLD
    ]

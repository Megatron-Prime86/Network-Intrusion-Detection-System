"""Capture live packets from a network interface using scapy."""

from __future__ import annotations

import logging
from typing import Optional

from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP

from data.packet_types import ParsedPacket

logger = logging.getLogger(__name__)


def capture_packets(
    count: int = 100, interface: Optional[str] = None
) -> list[ParsedPacket]:
    """Sniff a fixed number of packets from a live network interface.

    Args:
        count: Number of packets to capture before returning. Use ``0``
            for scapy's "capture indefinitely" behavior (not recommended
            for this helper; prefer `dashboard/capture_engine.py` for
            continuous, non-blocking capture).
        interface: Name of the network interface to sniff on (e.g.
            ``"eth0"``, ``"Wi-Fi"``). ``None`` lets scapy choose its
            default interface.

    Returns:
        A list of parsed IP packets (see `data.pcap_loader.ParsedPacket`).
        Non-IP packets are skipped.

    Raises:
        PermissionError: If the process lacks the privileges required to
            open a raw socket (run as root/Administrator).
    """
    logger.info(
        "Starting live capture: count=%d, interface=%s", count, interface or "default"
    )

    try:
        packets = sniff(count=count, iface=interface)
    except PermissionError:
        logger.error(
            "Permission denied opening interface %s. Run with elevated "
            "privileges (sudo on Linux/macOS, Administrator + Npcap on Windows).",
            interface or "default",
        )
        raise

    captured: list[ParsedPacket] = []
    for packet in packets:
        if not packet.haslayer(IP):
            continue

        dst_port: Optional[int] = None
        if packet.haslayer(TCP):
            dst_port = packet[TCP].dport
        elif packet.haslayer(UDP):
            dst_port = packet[UDP].dport

        captured.append(
            {
                "src_ip": packet[IP].src,
                "dst_ip": packet[IP].dst,
                "protocol": packet[IP].proto,
                "dst_port": dst_port,
            }
        )

    logger.info("Captured %d IP packets out of %d total", len(captured), len(packets))
    return captured

"""Load packets from a `.pcap` file and normalize them into plain dicts."""

from __future__ import annotations

import logging
from typing import Any, Optional

from scapy.all import rdpcap
from scapy.layers.inet import IP, TCP, UDP

from data.packet_types import ParsedPacket

logger = logging.getLogger(__name__)


def _parse_packet(packet: Any) -> Optional[ParsedPacket]:
    """Convert a raw scapy packet into a :class:`ParsedPacket`.

    Returns ``None`` for packets that don't carry an IP layer, since the
    detection engine only reasons about IP traffic.
    """
    if not packet.haslayer(IP):
        return None

    dst_port: Optional[int] = None
    if packet.haslayer(TCP):
        dst_port = packet[TCP].dport
    elif packet.haslayer(UDP):
        dst_port = packet[UDP].dport

    return {
        "src_ip": packet[IP].src,
        "dst_ip": packet[IP].dst,
        "protocol": packet[IP].proto,
        "dst_port": dst_port,
    }


def load_pcap(file_path: str) -> list[ParsedPacket]:
    """Read a `.pcap` file from disk and return its IP packets as dicts.

    Args:
        file_path: Path to the `.pcap` (or `.pcapng`) file to load.

    Returns:
        A list of `ParsedPacket` dicts, one per IP packet found in the
        capture. Non-IP packets are skipped.

    Raises:
        FileNotFoundError: If `file_path` does not exist.
        Exception: Re-raises any other error scapy encounters while
            parsing a malformed or unsupported capture file.
    """
    logger.info("Loading packets from %s", file_path)

    try:
        raw_packets = rdpcap(file_path)
    except FileNotFoundError:
        logger.error("PCAP file not found: %s", file_path)
        raise
    except Exception:
        logger.exception("Failed to parse PCAP file: %s", file_path)
        raise

    parsed_packets = [
        parsed
        for packet in raw_packets
        if (parsed := _parse_packet(packet)) is not None
    ]

    logger.info(
        "Loaded %d IP packets out of %d total from %s",
        len(parsed_packets),
        len(raw_packets),
        file_path,
    )
    return parsed_packets

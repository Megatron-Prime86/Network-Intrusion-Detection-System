"""CLI entry point: run a short, foreground live-capture detection session.

Sniffs a fixed number of packets from a network interface, checks each one
against the threat-intel feed and the suspicious-ports rule in real time,
and prints an end-of-session summary. Requires elevated privileges to
open a raw socket (sudo on Linux/macOS, Administrator + Npcap on Windows).

For continuous, non-blocking capture backing the web dashboard, see
`dashboard/capture_engine.py` instead.

Usage:
    sudo python live_ids.py
    sudo python live_ids.py --count 200 --interface eth0
"""

from __future__ import annotations

import argparse
import logging
from typing import Any, Optional

from analytics.dashboard import print_dashboard
from data.packet_types import ParsedPacket
from detections.suspicious_ports import detect
from live_alert import generate_live_alert
from logging_config import configure_logging
from threat_intel.threat_matcher import check_ip

logger = logging.getLogger(__name__)


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments for the live-capture session."""
    parser = argparse.ArgumentParser(
        description="Run a short foreground live packet-capture IDS session."
    )
    parser.add_argument(
        "--count",
        type=int,
        default=100,
        help="Number of packets to capture before stopping (default: 100).",
    )
    parser.add_argument(
        "--interface",
        default=None,
        help="Network interface to sniff on (default: scapy's default interface).",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging verbosity (default: INFO).",
    )
    return parser.parse_args()


class SessionCounters:
    """Mutable counters for a single live-capture session."""

    def __init__(self) -> None:
        self.total_packets = 0
        self.total_alerts = 0
        self.threat_hits = 0


def _parse_packet(packet: Any) -> Optional[ParsedPacket]:
    """Convert a raw scapy packet into a `ParsedPacket`, or `None` if not IP."""
    from scapy.layers.inet import IP, TCP, UDP

    if not packet.haslayer(IP):
        return None

    dst_port = None
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


def make_packet_handler(counters: SessionCounters):
    """Build a scapy `prn` callback bound to a given session's counters.

    Args:
        counters: The `SessionCounters` instance to update as packets arrive.

    Returns:
        A callable suitable for `scapy.sniff(prn=...)`.
    """

    def process_packet(packet: Any) -> None:
        counters.total_packets += 1

        parsed_packet = _parse_packet(packet)
        if parsed_packet is None:
            return

        if check_ip(parsed_packet["src_ip"]):
            counters.threat_hits += 1
            logger.warning("THREAT INTELLIGENCE MATCH: %s", parsed_packet)

        result = detect(parsed_packet)
        if result:
            counters.total_alerts += 1
            generate_live_alert(result["attack"], parsed_packet)

    return process_packet


def run(count: int, interface: Optional[str]) -> None:
    """Run a foreground live-capture session and print the summary dashboard.

    Args:
        count: Number of packets to capture before stopping.
        interface: Network interface to sniff on, or `None` for the default.
    """
    from scapy.all import sniff

    counters = SessionCounters()

    logger.info("LIVE IDS STARTED")
    try:
        sniff(count=count, iface=interface, prn=make_packet_handler(counters), store=False)
    except PermissionError:
        logger.error(
            "Permission denied opening interface %s. Run with elevated "
            "privileges (sudo on Linux/macOS, Administrator + Npcap on Windows).",
            interface or "default",
        )
        return
    logger.info("LIVE IDS STOPPED")

    print_dashboard(counters.total_packets, counters.total_alerts, counters.threat_hits)


def main() -> None:
    args = parse_args()
    configure_logging(level=getattr(logging, args.log_level))
    run(args.count, args.interface)


if __name__ == "__main__":
    main()

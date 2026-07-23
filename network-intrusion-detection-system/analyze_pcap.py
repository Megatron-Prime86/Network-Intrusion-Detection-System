"""CLI utility: print the most frequently contacted destination ports in a PCAP.

Usage:
    python analyze_pcap.py
    python analyze_pcap.py --pcap pcap/sample.pcap --limit 15
"""

from __future__ import annotations

import argparse
import logging

from analytics.top_ports import get_top_ports
from data.pcap_loader import load_pcap
from logging_config import configure_logging

logger = logging.getLogger(__name__)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Show the top destination ports in a PCAP file.")
    parser.add_argument("--pcap", default="pcap/sample.pcap", help="Path to the .pcap file.")
    parser.add_argument("--limit", type=int, default=15, help="Number of ports to show.")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    configure_logging(level=logging.INFO)

    packets = load_pcap(args.pcap)

    logger.info("TOP PORTS")
    for port, count in get_top_ports(packets, limit=args.limit):
        logger.info("Port %s: %d", port, count)


if __name__ == "__main__":
    main()

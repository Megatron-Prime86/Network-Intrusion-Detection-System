"""CLI utility: print the most active source IPs ("top talkers") in a PCAP.

Usage:
    python analyze_hosts.py
    python analyze_hosts.py --pcap pcap/sample.pcap --limit 20
"""

from __future__ import annotations

import argparse
import logging

from analytics.top_talkers import get_top_talkers
from data.pcap_loader import load_pcap
from logging_config import configure_logging

logger = logging.getLogger(__name__)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Show the top talkers in a PCAP file.")
    parser.add_argument("--pcap", default="pcap/sample.pcap", help="Path to the .pcap file.")
    parser.add_argument("--limit", type=int, default=10, help="Number of hosts to show.")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    configure_logging(level=logging.INFO)

    packets = load_pcap(args.pcap)

    logger.info("TOP TALKERS")
    for ip, count in get_top_talkers(packets, limit=args.limit):
        logger.info("%s: %d", ip, count)


if __name__ == "__main__":
    main()

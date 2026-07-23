"""CLI utility: print a protocol breakdown for a PCAP file.

Usage:
    python analyze_protocols.py
    python analyze_protocols.py --pcap pcap/sample.pcap
"""

from __future__ import annotations

import argparse
import logging

from analytics.protocol_analysis import analyze_protocols
from data.pcap_loader import load_pcap
from logging_config import configure_logging

logger = logging.getLogger(__name__)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Show a protocol breakdown for a PCAP file.")
    parser.add_argument("--pcap", default="pcap/sample.pcap", help="Path to the .pcap file.")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    configure_logging(level=logging.INFO)

    packets = load_pcap(args.pcap)

    logger.info("PROTOCOL ANALYSIS")
    for proto, count in analyze_protocols(packets).items():
        logger.info("%s: %d", proto, count)


if __name__ == "__main__":
    main()

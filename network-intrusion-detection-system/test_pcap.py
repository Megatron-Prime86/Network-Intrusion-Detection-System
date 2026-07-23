"""Manual smoke test: load a PCAP and print the first few parsed packets.

Not a pytest suite — a quick sanity-check script for verifying that
`data.pcap_loader.load_pcap` works against a given capture file.

Usage:
    python test_pcap.py
    python test_pcap.py --pcap pcap/sample.pcap --preview 10
"""

from __future__ import annotations

import argparse
import logging

from data.pcap_loader import load_pcap
from logging_config import configure_logging

logger = logging.getLogger(__name__)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Smoke-test PCAP loading.")
    parser.add_argument("--pcap", default="pcap/sample.pcap", help="Path to the .pcap file.")
    parser.add_argument("--preview", type=int, default=10, help="Number of packets to print.")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    configure_logging(level=logging.INFO)

    packets = load_pcap(args.pcap)
    logger.info("Packets Loaded: %d", len(packets))

    for packet in packets[: args.preview]:
        logger.info("%s", packet)


if __name__ == "__main__":
    main()

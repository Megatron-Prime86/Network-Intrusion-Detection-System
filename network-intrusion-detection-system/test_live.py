"""Manual smoke test: capture a handful of live packets and print them.

Not a pytest suite — a quick sanity-check script for verifying that
`data.live_capture.capture_packets` can open the network interface.
Requires elevated privileges (sudo on Linux/macOS, Administrator +
Npcap on Windows).

Usage:
    sudo python test_live.py
    sudo python test_live.py --count 20 --interface eth0
"""

from __future__ import annotations

import argparse
import logging

from data.live_capture import capture_packets
from logging_config import configure_logging

logger = logging.getLogger(__name__)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Smoke-test live packet capture.")
    parser.add_argument("--count", type=int, default=20, help="Number of packets to capture.")
    parser.add_argument("--interface", default=None, help="Network interface to sniff on.")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    configure_logging(level=logging.INFO)

    packets = capture_packets(count=args.count, interface=args.interface)
    logger.info("Captured %d packets", len(packets))

    for packet in packets:
        logger.info("%s", packet)


if __name__ == "__main__":
    main()

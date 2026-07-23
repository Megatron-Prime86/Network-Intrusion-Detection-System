"""Print an end-of-run console summary for the live-capture CLI (`live_ids.py`)."""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


def print_dashboard(packets: int, alerts: int, threat_hits: int) -> None:
    """Log a formatted end-of-session capture summary.

    Args:
        packets: Total number of packets captured during the session.
        alerts: Total number of detection alerts raised.
        threat_hits: Total number of threat-intelligence IOC matches.
    """
    logger.info("=" * 50)
    logger.info("NETWORK SECURITY DASHBOARD")
    logger.info("=" * 50)
    logger.info("Packets Captured: %s", packets)
    logger.info("Alerts Generated: %s", alerts)
    logger.info("Threat Intel Hits: %s", threat_hits)
    logger.info("=" * 50)

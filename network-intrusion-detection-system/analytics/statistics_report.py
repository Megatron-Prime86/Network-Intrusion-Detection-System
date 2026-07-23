"""Print run statistics to the console in a readable block."""

from __future__ import annotations

import logging

from analytics.statistics import RunStatistics

logger = logging.getLogger(__name__)


def print_statistics(stats: RunStatistics) -> None:
    """Log a formatted summary of run statistics.

    Args:
        stats: Statistics produced by `analytics.statistics.generate_statistics`.
    """
    logger.info("=" * 50)
    logger.info("NETWORK SECURITY ANALYTICS")
    logger.info("=" * 50)
    logger.info("Total Alerts: %s", stats["total_alerts"])
    logger.info("Most Common Attack: %s", stats["most_common_attack"])
    logger.info("Most Active Source: %s", stats["most_active_source"])
    logger.info("=" * 50)

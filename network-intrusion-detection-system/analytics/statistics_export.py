"""Export run statistics to a JSON file in `exports/`."""

from __future__ import annotations

import json
import logging
import os

from analytics.statistics import RunStatistics

logger = logging.getLogger(__name__)

STATISTICS_JSON_PATH = os.path.join("exports", "network_statistics.json")


def export_statistics(
    stats: RunStatistics, path: str = STATISTICS_JSON_PATH
) -> None:
    """Write run statistics to a JSON file.

    Args:
        stats: Statistics to export.
        path: Destination file path. Defaults to `STATISTICS_JSON_PATH`.
    """
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as file:
            json.dump(stats, file, indent=4)
    except OSError:
        logger.exception("Failed to export statistics: %s", path)
        raise
    logger.info("Exported statistics to %s", path)

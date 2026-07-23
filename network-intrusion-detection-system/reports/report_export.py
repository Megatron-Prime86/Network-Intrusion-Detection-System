"""Write alerts and reports out to the `exports/` directory."""

from __future__ import annotations

import json
import logging
import os
from typing import Any

logger = logging.getLogger(__name__)

EXPORTS_DIR = "exports"
ALERTS_JSON_PATH = os.path.join(EXPORTS_DIR, "alerts.json")
INCIDENT_REPORT_PATH = os.path.join(EXPORTS_DIR, "incident_report.txt")
NETWORK_REPORT_PATH = os.path.join(EXPORTS_DIR, "network_security_report.txt")

INCIDENT_ENTRY_TEMPLATE = """
================================

Attack:
{attack}

Source IP:
{src_ip}

================================

"""


def _ensure_exports_dir() -> None:
    """Create the `exports/` directory if it doesn't already exist."""
    try:
        os.makedirs(EXPORTS_DIR, exist_ok=True)
    except OSError:
        logger.exception("Could not create exports directory: %s", EXPORTS_DIR)
        raise


def export_alerts(alerts: list[dict[str, Any]], path: str = ALERTS_JSON_PATH) -> None:
    """Write alerts to a JSON file.

    Args:
        alerts: The alerts to export.
        path: Destination file path. Defaults to `ALERTS_JSON_PATH`.
    """
    _ensure_exports_dir()
    try:
        with open(path, "w") as file:
            json.dump(alerts, file, indent=4)
    except OSError:
        logger.exception("Failed to write alerts export: %s", path)
        raise
    logger.info("Exported %d alerts to %s", len(alerts), path)


def export_txt_report(
    alerts: list[dict[str, Any]], path: str = INCIDENT_REPORT_PATH
) -> None:
    """Write a plain-text incident report listing each alert.

    Args:
        alerts: The alerts to include in the report.
        path: Destination file path. Defaults to `INCIDENT_REPORT_PATH`.
    """
    _ensure_exports_dir()
    try:
        with open(path, "w") as file:
            for alert in alerts:
                file.write(
                    INCIDENT_ENTRY_TEMPLATE.format(
                        attack=alert["attack"], src_ip=alert["src_ip"]
                    )
                )
    except OSError:
        logger.exception("Failed to write incident report: %s", path)
        raise
    logger.info("Exported incident report to %s", path)


def export_network_report(report: str, path: str = NETWORK_REPORT_PATH) -> None:
    """Write the full network security report to a text file.

    Args:
        report: The formatted report text, typically from
            `reports.network_report.generate_network_report`.
        path: Destination file path. Defaults to `NETWORK_REPORT_PATH`.
    """
    _ensure_exports_dir()
    try:
        with open(path, "w") as file:
            file.write(report)
    except OSError:
        logger.exception("Failed to write network report: %s", path)
        raise
    logger.info("Exported network report to %s", path)

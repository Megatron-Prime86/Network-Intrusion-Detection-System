"""Generate a full incident + network security report from a live run.

Run this *after* stopping `dashboard/app.py`. It reads whatever alerts are
currently sitting in `exports/alerts.json` (written by `capture_engine.py`
during the live run) and produces the same kind of report the offline
`main.py` pipeline produces for a PCAP file: statistics, IOC summary, a
plain-text incident report, and a full network security report.

Note: `exports/alerts.json` only holds the most recent `MAX_ALERTS` (200 by
default) alerts from the live run — see `dashboard/capture_engine.py`. If
your run generated more than that, older alerts are already gone and won't
appear in this report.

Usage:
    python generate_report.py
    python generate_report.py --alerts exports/alerts.json
"""

from __future__ import annotations

import argparse
import json
import logging
from typing import Any

from analytics.statistics import generate_statistics
from analytics.statistics_export import export_statistics
from analytics.statistics_report import print_statistics
from detections.ioc_extractor import extract_iocs
from logging_config import configure_logging
from reports.network_report import generate_network_report
from reports.report_export import export_network_report, export_txt_report

logger = logging.getLogger(__name__)

DEFAULT_ALERTS_PATH = "exports/alerts.json"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build a full report from a live-run alerts export."
    )
    parser.add_argument(
        "--alerts",
        default=DEFAULT_ALERTS_PATH,
        help=f"Path to the alerts JSON file (default: {DEFAULT_ALERTS_PATH}).",
    )
    return parser.parse_args()


def load_alerts(path: str) -> list[dict[str, Any]]:
    try:
        with open(path, "r") as file:
            return json.load(file)
    except FileNotFoundError:
        logger.error(
            "No alerts file found at %s. Run the dashboard first so "
            "capture_engine.py has something to export.",
            path,
        )
        return []
    except json.JSONDecodeError:
        logger.error("Could not parse %s as JSON.", path)
        return []


def build_report(alerts: list[dict[str, Any]]) -> None:
    """Write the incident report, statistics, and network report to exports/.

    Shared by the CLI (`main()` below) and the dashboard's
    `/api/generate-report` route, so both produce identical output from
    whatever alerts they're given.

    Args:
        alerts: Alerts to report on (already loaded, not a file path).
    """
    export_txt_report(alerts)

    stats = generate_statistics(alerts)
    export_statistics(stats)
    print_statistics(stats)

    iocs = extract_iocs(alerts)
    report = generate_network_report(alerts, stats, iocs)
    export_network_report(report)

    logger.info("IOC SUMMARY")
    for ioc in iocs:
        logger.info("Source IP: %s", ioc["src_ip"])
        logger.info("Attack: %s", ioc["attack"])
        logger.info("-" * 30)

    logger.info(
        "Report generated: exports/incident_report.txt, "
        "exports/network_security_report.txt, exports/network_statistics.json"
    )


def main() -> None:
    args = parse_args()
    configure_logging(level=logging.INFO)

    alerts = load_alerts(args.alerts)
    if not alerts:
        logger.warning("No alerts to report on. Exiting.")
        return

    build_report(alerts)


if __name__ == "__main__":
    main()
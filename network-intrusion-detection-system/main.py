"""CLI entry point: run the full offline NIDS pipeline against a PCAP file.

Loads a capture file, runs all detection rules, enriches each alert with
MITRE ATT&CK context/risk/severity, prints a console report, and exports
alerts/statistics/report artifacts to `exports/`.

Usage:
    python main.py
    python main.py --pcap pcap/sample.pcap
    python main.py --pcap pcap/sample.pcap --log-level DEBUG
"""

from __future__ import annotations

import argparse
import logging

from analytics.statistics import generate_statistics
from analytics.statistics_export import export_statistics
from analytics.statistics_report import print_statistics
from data.pcap_loader import load_pcap
from detections.detection_manager import run_detections
from detections.ioc_extractor import extract_iocs
from logging_config import configure_logging
from mappings.mitre_mapping import get_mitre_entry
from mappings.risk_scores import get_risk_score
from mappings.severity import get_severity
from reports.alert_generator import generate_alert
from reports.network_report import generate_network_report
from reports.report_export import export_alerts, export_network_report, export_txt_report

logger = logging.getLogger(__name__)


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments for the offline analysis run."""
    parser = argparse.ArgumentParser(
        description="Run the NIDS detection pipeline against a PCAP file."
    )
    parser.add_argument(
        "--pcap",
        default="pcap/sample.pcap",
        help="Path to the .pcap file to analyze (default: pcap/sample.pcap).",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging verbosity (default: INFO).",
    )
    return parser.parse_args()


def run(pcap_path: str) -> None:
    """Execute the full offline detection pipeline for a single PCAP file.

    Args:
        pcap_path: Path to the `.pcap` file to analyze.
    """
    logger.info("NETWORK INTRUSION DETECTION SYSTEM")

    packets = load_pcap(pcap_path)
    alerts = run_detections(packets)

    for alert in alerts:
        attack = alert["attack"]
        mitre = get_mitre_entry(attack)
        risk_score = get_risk_score(attack)
        severity = get_severity(risk_score)

        report = generate_alert(
            attack,
            alert["src_ip"],
            mitre["technique"],
            mitre["tactic"],
            severity,
            risk_score,
        )
        logger.info(report)

    export_alerts(alerts)
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

    logger.info("Alerts exported successfully.")


def main() -> None:
    args = parse_args()
    configure_logging(level=getattr(logging, args.log_level))
    run(args.pcap)


if __name__ == "__main__":
    main()

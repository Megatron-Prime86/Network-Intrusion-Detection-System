"""Render a full end-of-run network security report (summary + IOCs)."""

from __future__ import annotations

from typing import Any

REPORT_HEADER_TEMPLATE = """
==================================================

NETWORK SECURITY REPORT

Total Alerts:
{total_alerts}

Most Common Attack:
{most_common_attack}

Most Active Source:
{most_active_source}

==================================================

IOC SUMMARY
"""

IOC_ENTRY_TEMPLATE = """
Source IP:
{src_ip}

Attack:
{attack}
"""


def generate_network_report(
    alerts: list[dict[str, Any]],
    stats: dict[str, Any],
    iocs: list[dict[str, Any]],
) -> str:
    """Build the full text report combining run statistics and IOCs.

    Args:
        alerts: All alerts generated during the run (currently unused
            directly here, but accepted for API symmetry with the other
            report-building steps in `main.py`).
        stats: Summary statistics from `analytics.statistics.generate_statistics`.
        iocs: Extracted IOCs from `detections.ioc_extractor.extract_iocs`.

    Returns:
        The full formatted report as a single string.
    """
    report = REPORT_HEADER_TEMPLATE.format(
        total_alerts=stats["total_alerts"],
        most_common_attack=stats["most_common_attack"],
        most_active_source=stats["most_active_source"],
    )

    for ioc in iocs:
        report += IOC_ENTRY_TEMPLATE.format(src_ip=ioc["src_ip"], attack=ioc["attack"])

    return report

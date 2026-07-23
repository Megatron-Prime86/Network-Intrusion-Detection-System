"""Build and log a single enriched real-time alert for the live pipeline."""

from __future__ import annotations

import logging
from typing import Any

from data.packet_types import ParsedPacket
from mappings.mitre_mapping import get_mitre_entry
from mappings.risk_scores import get_risk_score
from mappings.severity import get_severity

logger = logging.getLogger(__name__)

LIVE_ALERT_TEMPLATE = """
==================================================

LIVE ALERT

Attack:
{attack}

Source IP:
{src_ip}

Destination IP:
{dst_ip}

Destination Port:
{dst_port}

MITRE Technique:
{technique}

MITRE Tactic:
{tactic}

Severity:
{severity}

Risk Score:
{risk}/100

==================================================
"""


def generate_live_alert(attack: str, packet: ParsedPacket) -> dict[str, Any]:
    """Enrich a live detection hit with MITRE/risk/severity context and log it.

    Args:
        attack: Internal attack label (e.g. ``"Suspicious Port Access"``).
        packet: The parsed packet that triggered the detection.

    Returns:
        The enriched alert as a dict, suitable for export via
        `reports.report_export.export_alerts`.
    """
    mitre = get_mitre_entry(attack)
    risk = get_risk_score(attack)
    severity = get_severity(risk)

    logger.info(
        LIVE_ALERT_TEMPLATE.format(
            attack=attack,
            src_ip=packet.get("src_ip"),
            dst_ip=packet.get("dst_ip"),
            dst_port=packet.get("dst_port"),
            technique=mitre["technique"],
            tactic=mitre["tactic"],
            severity=severity,
            risk=risk,
        )
    )

    return {
        "attack": attack,
        "src_ip": packet.get("src_ip"),
        "dst_ip": packet.get("dst_ip"),
        "dst_port": packet.get("dst_port"),
        "mitre_technique": mitre["technique"],
        "mitre_tactic": mitre["tactic"],
        "severity": severity,
        "risk_score": risk,
    }

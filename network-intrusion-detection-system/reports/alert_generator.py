"""Render a single enriched alert as a human-readable text block."""

from __future__ import annotations

ALERT_TEMPLATE = """
==================================================

NETWORK ALERT

Attack:
{attack}

Source IP:
{src_ip}

MITRE Technique:
{technique}

MITRE Tactic:
{tactic}

Severity:
{severity}

Risk Score:
{risk_score}/100

==================================================
"""


def generate_alert(
    attack: str,
    src_ip: str,
    technique: str,
    tactic: str,
    severity: str,
    risk_score: int,
) -> str:
    """Format an enriched alert into the standard NIDS alert block.

    Args:
        attack: Internal attack label (e.g. ``"Port Scan"``).
        src_ip: Source IP address associated with the alert.
        technique: MITRE ATT&CK technique ID (e.g. ``"T1046"``).
        tactic: MITRE ATT&CK tactic name (e.g. ``"Discovery"``).
        severity: Severity band (``"LOW"``/``"MEDIUM"``/``"HIGH"``/``"CRITICAL"``).
        risk_score: Numeric risk score out of 100.

    Returns:
        A formatted, multi-line alert string ready to print or log.
    """
    return ALERT_TEMPLATE.format(
        attack=attack,
        src_ip=src_ip,
        technique=technique,
        tactic=tactic,
        severity=severity,
        risk_score=risk_score,
    )

from mappings.mitre_mapping import (
    MITRE_MAP
)

from mappings.risk_scores import (
    RISK_SCORES
)

from mappings.severity import (
    get_severity
)


def generate_live_alert(
    attack,
    packet
):

    mitre = MITRE_MAP.get(
        attack,
        {
            "technique": "Unknown",
            "tactic": "Unknown"
        }
    )

    risk = RISK_SCORES.get(
        attack,
        10
    )

    severity = get_severity(
        risk
    )

    print(
        f"""

==================================================

LIVE ALERT

Attack:
{attack}

Source IP:
{packet['src_ip']}

Destination IP:
{packet['dst_ip']}

Destination Port:
{packet['dst_port']}

MITRE Technique:
{mitre['technique']}

MITRE Tactic:
{mitre['tactic']}

Severity:
{severity}

Risk Score:
{risk}/100

==================================================

"""
    )
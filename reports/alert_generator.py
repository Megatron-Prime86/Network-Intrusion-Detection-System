def generate_alert(
    attack,
    src_ip,
    technique,
    tactic,
    severity,
    risk_score
):

    return f"""
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
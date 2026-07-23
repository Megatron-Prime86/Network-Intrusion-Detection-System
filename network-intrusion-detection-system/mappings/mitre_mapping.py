"""Map internal attack labels to MITRE ATT&CK techniques/tactics."""

from __future__ import annotations

from typing import TypedDict


class MitreEntry(TypedDict):
    technique: str
    name: str
    tactic: str


UNKNOWN_MITRE_ENTRY: MitreEntry = {
    "technique": "Unknown",
    "name": "Unknown",
    "tactic": "Unknown",
}

MITRE_MAP: dict[str, MitreEntry] = {
    "Port Scan": {
        "technique": "T1046",
        "name": "Network Service Discovery",
        "tactic": "Discovery",
    },
    "Brute Force": {
        "technique": "T1110",
        "name": "Brute Force",
        "tactic": "Credential Access",
    },
    "Suspicious Port Access": {
        "technique": "T1595",
        "name": "Active Scanning",
        "tactic": "Reconnaissance",
    },
    "Threat Intelligence Match": {
        "technique": "T1583",
        "name": "Malicious Infrastructure",
        "tactic": "Resource Development",
    },
}


def get_mitre_entry(attack: str) -> MitreEntry:
    """Look up the MITRE ATT&CK mapping for an attack label.

    Args:
        attack: The internal attack label (e.g. ``"Port Scan"``).

    Returns:
        The matching `MitreEntry`, or `UNKNOWN_MITRE_ENTRY` if the label
        isn't in `MITRE_MAP`.
    """
    return MITRE_MAP.get(attack, UNKNOWN_MITRE_ENTRY)

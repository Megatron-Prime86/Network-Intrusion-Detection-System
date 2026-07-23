"""Static risk-score lookup table (0-100) for each attack label."""

from __future__ import annotations

DEFAULT_RISK_SCORE = 10

RISK_SCORES: dict[str, int] = {
    "Port Scan": 85,
    "Brute Force": 95,
    "Suspicious Port Access": 70,
    "Threat Intelligence Match": 100,
}


def get_risk_score(attack: str) -> int:
    """Look up the risk score for an attack label.

    Args:
        attack: The internal attack label (e.g. ``"Brute Force"``).

    Returns:
        The mapped risk score, or `DEFAULT_RISK_SCORE` if unmapped.
    """
    return RISK_SCORES.get(attack, DEFAULT_RISK_SCORE)

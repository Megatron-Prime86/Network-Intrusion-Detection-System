"""Convert a numeric risk score into a human-readable severity band."""

from __future__ import annotations

CRITICAL_THRESHOLD = 90
HIGH_THRESHOLD = 70
MEDIUM_THRESHOLD = 40


def get_severity(score: int) -> str:
    """Map a 0-100 risk score to a severity label.

    Args:
        score: Numeric risk score, typically from `mappings.risk_scores`.

    Returns:
        One of ``"CRITICAL"``, ``"HIGH"``, ``"MEDIUM"``, or ``"LOW"``.
    """
    if score >= CRITICAL_THRESHOLD:
        return "CRITICAL"
    if score >= HIGH_THRESHOLD:
        return "HIGH"
    if score >= MEDIUM_THRESHOLD:
        return "MEDIUM"
    return "LOW"

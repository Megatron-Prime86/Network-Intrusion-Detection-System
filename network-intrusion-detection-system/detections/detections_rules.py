"""Human-readable descriptions for each detection rule's category.

Reference/documentation table — not currently wired into the alert
pipeline, but kept for use in reports or UI tooltips that want a plain-
English explanation of what a given `attack` label represents.
"""

from __future__ import annotations

DETECTION_RULES: dict[str, str] = {
    "Port Scan": "Network Discovery Activity",
    "Brute Force": "Credential Attack Activity",
    "Suspicious Port Access": "Reconnaissance / High-Risk Port Access",
    "Threat Intelligence Match": "Known Malicious Infrastructure",
}

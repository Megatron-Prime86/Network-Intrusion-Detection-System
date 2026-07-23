"""Match source IPs against a local threat-intelligence IOC feed."""

from __future__ import annotations

import json
import logging
import os
from functools import lru_cache

logger = logging.getLogger(__name__)

_DEFAULT_IOC_PATH = os.path.join(os.path.dirname(__file__), "malicious_ips.json")


@lru_cache(maxsize=1)
def load_iocs(path: str = _DEFAULT_IOC_PATH) -> frozenset[str]:
    """Load known-malicious IPs from the JSON threat-intel feed.

    Results are cached (`functools.lru_cache`) since this is called once
    per packet in the live-capture pipeline and the feed rarely changes
    mid-run. Call `load_iocs.cache_clear()` to force a reload after
    updating `malicious_ips.json` on disk.

    Args:
        path: Path to the JSON file containing a list of malicious IPs.

    Returns:
        A frozenset of malicious IP strings. Returns an empty set (with a
        logged error) if the file is missing or malformed, so a bad feed
        degrades the IDS gracefully instead of crashing it.
    """
    try:
        with open(path, "r") as file:
            iocs = json.load(file)
    except FileNotFoundError:
        logger.error("Threat intel feed not found: %s", path)
        return frozenset()
    except json.JSONDecodeError:
        logger.error("Threat intel feed is not valid JSON: %s", path)
        return frozenset()

    return frozenset(iocs)


def check_ip(ip: str) -> bool:
    """Check whether an IP address appears in the threat-intel feed.

    Args:
        ip: The IP address to check.

    Returns:
        True if `ip` is a known-malicious IOC, False otherwise.
    """
    return ip in load_iocs()

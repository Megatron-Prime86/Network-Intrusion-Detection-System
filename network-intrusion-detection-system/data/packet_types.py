"""Shared packet type definitions.

Kept separate from `pcap_loader.py`/`live_capture.py` (which import
scapy) so that modules which only need the *shape* of a parsed packet —
detections, analytics, reports — don't have to pull in the scapy/libpcap
dependency just for a type hint.
"""

from __future__ import annotations

from typing import Optional, TypedDict


class ParsedPacket(TypedDict):
    """Normalized representation of a single IP packet used throughout the NIDS."""

    src_ip: str
    dst_ip: str
    protocol: int
    dst_port: Optional[int]

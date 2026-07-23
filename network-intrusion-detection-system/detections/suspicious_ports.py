"""Detect single-packet access to commonly-abused/high-risk ports."""

from __future__ import annotations

from typing import Optional, TypedDict

from data.packet_types import ParsedPacket

# Ports frequently targeted for reconnaissance or exploitation
# (web, FTP, SSH, Telnet, RDP, VNC).
RISKY_PORTS = {80, 443, 21, 22, 23, 3389, 5900}


class SuspiciousPortResult(TypedDict):
    attack: str


def detect(packet: ParsedPacket) -> Optional[SuspiciousPortResult]:
    """Check a single packet's destination port against `RISKY_PORTS`.

    Used by the live-capture pipeline (`live_ids.py`,
    `dashboard/capture_engine.py`), where alerts must be raised per
    packet in real time rather than after batching a whole capture.

    Args:
        packet: A single parsed packet.

    Returns:
        A result dict with `attack: "Suspicious Port Access"` if the
        packet's destination port is in `RISKY_PORTS`, otherwise `None`.
    """
    if packet["dst_port"] in RISKY_PORTS:
        return {"attack": "Suspicious Port Access"}
    return None

"""Batch entry point that runs all offline (post-capture) detection rules."""

from __future__ import annotations

from data.packet_types import ParsedPacket
from detections.brute_force import detect_bruteforce
from detections.port_scan import Alert, detect_port_scans


def run_detections(packets: list[ParsedPacket]) -> list[Alert]:
    """Run every batch detection rule against a set of packets.

    Args:
        packets: Parsed packets to analyze, typically loaded from a PCAP
            file via `data.pcap_loader.load_pcap`.

    Returns:
        The combined list of alerts from all detection rules. Note this
        does not include `detections.suspicious_ports.detect`, which is
        a per-packet, real-time check used by the live pipeline instead.
    """
    alerts: list[Alert] = []
    alerts.extend(detect_port_scans(packets))
    alerts.extend(detect_bruteforce(packets))
    return alerts

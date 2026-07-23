"""Static sample packets used for quick manual testing without a PCAP file.

Not imported by the production pipeline (`main.py`, `live_ids.py`, or the
dashboard) — kept as a lightweight fixture for ad-hoc experimentation in a
REPL, e.g.:

    >>> from data.packet_data import SAMPLE_PACKETS
    >>> from detections.port_scan import detect_port_scans
    >>> detect_port_scans(SAMPLE_PACKETS)
"""

from __future__ import annotations

from data.packet_types import ParsedPacket

SAMPLE_PACKETS: list[ParsedPacket] = [
    {"src_ip": "192.168.1.100", "dst_ip": "10.0.0.1", "dst_port": 21, "protocol": "TCP"},
    {"src_ip": "192.168.1.100", "dst_ip": "10.0.0.1", "dst_port": 22, "protocol": "TCP"},
    {"src_ip": "192.168.1.100", "dst_ip": "10.0.0.1", "dst_port": 23, "protocol": "TCP"},
    {"src_ip": "192.168.1.100", "dst_ip": "10.0.0.1", "dst_port": 80, "protocol": "TCP"},
    {"src_ip": "192.168.1.100", "dst_ip": "10.0.0.1", "dst_port": 443, "protocol": "TCP"},
    {"src_ip": "10.0.0.5", "dst_ip": "10.0.0.1", "dst_port": 3389, "protocol": "TCP"},
]

"""Live capture engine for the NIDS dashboard.

Wraps the existing live-IDS pipeline instead of reinventing detection.
Two kinds of detection run against the live traffic:

  - Per-packet checks (detections.suspicious_ports.detect +
    threat_intel.threat_matcher.check_ip) — evaluated immediately as
    each packet is sniffed, same as live_ids.py.
  - Threshold/batch checks (detections.port_scan.detect_port_scans,
    detections.brute_force.detect_bruteforce) — these need to look
    across many packets (e.g. "one IP touched >= 4 ports"), so they're
    periodically re-evaluated against a rolling window of recently
    captured packets instead of packet-by-packet. A per-(src_ip, attack)
    cooldown keeps an ongoing scan/brute-force from re-alerting every
    cycle while it's still in progress.

All resulting alerts are collected via live_alert.generate_live_alert
and periodically written out to exports/alerts.json and
exports/live_packets.json, so the dashboard's polling picks them up.

Requires elevated privileges to sniff:
  - Linux/macOS: run with sudo
  - Windows: run as Administrator, with Npcap installed

Usage (from dashboard/app.py):
    from capture_engine import start_capture
    start_capture(interface=None)  # None = scapy's default interface
"""

from __future__ import annotations

import json
import logging
import os
import sys
import threading
import time
from collections import deque
from typing import Any, Optional

# detections/, reports/, threat_intel/, and live_alert.py all live at the
# project root, one level above this file (dashboard/ is a subfolder), so
# the project root needs to be on sys.path before importing them.
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP

from data.packet_types import ParsedPacket
from detections.brute_force import detect_bruteforce
from detections.port_scan import Alert, detect_port_scans
from detections.suspicious_ports import detect
from live_alert import generate_live_alert
from reports.report_export import export_alerts
from threat_intel.threat_matcher import check_ip

logger = logging.getLogger(__name__)

PACKETS_FILE = "exports/live_packets.json"

MAX_ALERTS = 200  # alerts kept in exports/alerts.json
EXPORT_PACKET_LIMIT = 500  # packets kept for the flow-stats panel
EXPORT_INTERVAL_SECONDS = 1  # how often exports/ gets refreshed
DETECTION_INTERVAL_SECONDS = 2  # how often threshold rules re-scan the recent packet window
ALERT_COOLDOWN_SECONDS = 5  # suppress a repeat (src_ip, attack) alert within this window

_state_lock = threading.Lock()
_alerts: deque = deque(maxlen=MAX_ALERTS)
_recent_packets: deque = deque(maxlen=EXPORT_PACKET_LIMIT)

_stats_lock = threading.Lock()
_stats = {"total_packets": 0, "total_alerts": 0, "threat_hits": 0}

_cooldown_lock = threading.Lock()
_alert_cooldowns: dict[tuple[str, str], float] = {}


def _parse_packet(packet: Any) -> Optional[dict[str, Any]]:
    """Same shape live_ids.py / live_capture.py already produce."""
    if not packet.haslayer(IP):
        return None

    dst_port = None
    if packet.haslayer(TCP):
        dst_port = packet[TCP].dport
    elif packet.haslayer(UDP):
        dst_port = packet[UDP].dport

    return {
        "src_ip": packet[IP].src,
        "dst_ip": packet[IP].dst,
        "protocol": packet[IP].proto,
        "dst_port": dst_port,
    }


def _process_packet(packet: Any) -> None:
    """Parse, threat-check, and detect against a single sniffed packet."""
    parsed = _parse_packet(packet)
    if parsed is None:
        return

    with _stats_lock:
        _stats["total_packets"] += 1

    with _state_lock:
        _recent_packets.append(parsed)

    try:
        if check_ip(parsed["src_ip"]):
            with _stats_lock:
                _stats["threat_hits"] += 1
    except Exception:
        logger.exception("Threat intel check failed")

    try:
        result = detect(parsed)
    except Exception:
        logger.exception("Detection error")
        result = None

    if not result:
        return

    # Same cooldown used for threshold detections: without it, every packet
    # to a common port like 80/443 raises a fresh alert, flooding the
    # capped _alerts deque with "Suspicious Port Access" and starving out
    # the rarer Port Scan / Brute Force alerts before they're ever exported.
    if not _cooldown_ok(parsed["src_ip"], result["attack"]):
        return

    try:
        alert = generate_live_alert(result["attack"], parsed)
    except Exception:
        logger.exception("Alert generation failed")
        alert = None

    with _stats_lock:
        _stats["total_alerts"] += 1

    if alert:
        with _state_lock:
            _alerts.append(alert)


def _cooldown_ok(src_ip: str, attack: str) -> bool:
    """Check (and reset) the alert cooldown for a given (src_ip, attack) pair.

    Returns:
        True if enough time has passed since the last alert for this pair
        (and starts a new cooldown window), False if it's still on
        cooldown and should be suppressed.
    """
    key = (src_ip, attack)
    now = time.monotonic()
    with _cooldown_lock:
        last = _alert_cooldowns.get(key)
        if last is not None and (now - last) < ALERT_COOLDOWN_SECONDS:
            return False
        _alert_cooldowns[key] = now
    return True


def _representative_packet(src_ip: str, packets_snapshot: list[ParsedPacket]) -> ParsedPacket:
    """Find a recent packet from src_ip to attach dst_ip/dst_port context to an aggregate alert.

    Threshold alerts (port scan, brute force) span many packets rather
    than one, so there's no single "the" packet that triggered them —
    this just picks the most recent one from that source for display
    purposes in the alert.
    """
    for packet in reversed(packets_snapshot):
        if packet.get("src_ip") == src_ip:
            return packet
    return {"src_ip": src_ip, "dst_ip": "multiple", "protocol": "N/A", "dst_port": None}


def _run_threshold_detections() -> None:
    """Re-scan the recent packet window for threshold-based rules.

    Unlike the per-packet suspicious-ports/threat-intel checks in
    `_process_packet`, port-scan and brute-force detection need to look
    across a batch of packets, so they're evaluated periodically here
    against a rolling window instead of packet-by-packet.
    """
    with _state_lock:
        packets_snapshot = list(_recent_packets)

    if not packets_snapshot:
        return

    raw_alerts: list[Alert] = []
    try:
        raw_alerts.extend(detect_port_scans(packets_snapshot))
        raw_alerts.extend(detect_bruteforce(packets_snapshot))
    except Exception:
        logger.exception("Threshold detection failed")
        return

    for raw_alert in raw_alerts:
        src_ip = raw_alert["src_ip"]
        attack = raw_alert["attack"]

        if not _cooldown_ok(src_ip, attack):
            continue

        packet = _representative_packet(src_ip, packets_snapshot)

        try:
            alert = generate_live_alert(attack, packet)
        except Exception:
            logger.exception("Alert generation failed for %s / %s", src_ip, attack)
            continue

        with _stats_lock:
            _stats["total_alerts"] += 1
        with _state_lock:
            _alerts.append(alert)


def _detection_loop() -> None:
    while True:
        time.sleep(DETECTION_INTERVAL_SECONDS)
        _run_threshold_detections()


def _write_exports() -> None:
    """Flush the in-memory alert/packet buffers out to exports/."""
    try:
        os.makedirs("exports", exist_ok=True)
    except OSError:
        logger.exception("Could not create exports/ directory")
        return

    with _state_lock:
        packets_snapshot = list(_recent_packets)
        alerts_snapshot = list(_alerts)

    try:
        with open(PACKETS_FILE, "w") as file:
            json.dump(packets_snapshot, file, indent=4)
    except OSError:
        logger.exception("Failed to write %s", PACKETS_FILE)

    with _stats_lock:
        stats_snapshot = dict(_stats)
    logger.info(
        "heartbeat - packets seen: %d, alerts: %d, threat intel hits: %d",
        stats_snapshot["total_packets"],
        stats_snapshot["total_alerts"],
        stats_snapshot["threat_hits"],
    )

    try:
        export_alerts(alerts_snapshot)
    except OSError:
        logger.exception("Failed to export alerts")


def _export_loop() -> None:
    while True:
        time.sleep(EXPORT_INTERVAL_SECONDS)
        _write_exports()


def _sniff_loop(interface: Optional[str]) -> None:
    try:
        # No `count` limit here (unlike live_ids.py's count=100) — the
        # dashboard wants continuous capture, not a fixed test batch.
        sniff(iface=interface, prn=_process_packet, store=False)
    except PermissionError:
        logger.error(
            "Permission denied opening the interface. Run with sudo "
            "(Linux/macOS) or as Administrator with Npcap installed (Windows)."
        )
    except Exception:
        logger.exception("sniff() failed")


def start_capture(interface: Optional[str] = None) -> None:
    """Start background packet capture + detection using the existing
    live-IDS pipeline (detections/suspicious_ports.py + live_alert.py).

    Args:
        interface: Name of the NIC to sniff (e.g. "eth0", "Wi-Fi").
            `None` lets scapy pick its default interface.

    Safe to call once per process. If Flask's debug reloader is active,
    call this only in the reloader's worker process (see app.py).
    """
    threading.Thread(target=_sniff_loop, args=(interface,), daemon=True).start()
    threading.Thread(target=_export_loop, daemon=True).start()
    threading.Thread(target=_detection_loop, daemon=True).start()

    logger.info(
        "Capture started on interface=%s (exporting every %ds, "
        "threshold detection every %ds)",
        interface or "default",
        EXPORT_INTERVAL_SECONDS,
        DETECTION_INTERVAL_SECONDS,
    )
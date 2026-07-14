"""
Live capture engine for the NIDS dashboard.

Wraps the existing live-IDS pipeline instead of reinventing detection:
each sniffed packet is checked the same way live_ids.py already checks
it (detections/suspicious_ports.detect + threat_intel/threat_matcher),
and any resulting alert is collected via live_alert.generate_live_alert
and periodically written out to exports/alerts.json and
exports/live_packets.json, so the dashboard's polling picks it up.

Requires elevated privileges to sniff:
  - Linux/macOS: run with sudo
  - Windows: run as Administrator, with Npcap installed

Usage (from dashboard/app.py):
    from capture_engine import start_capture
    start_capture(interface=None)  # None = scapy's default interface
"""

import json
import os
import sys
import threading
import time
from collections import deque

# detections/, reports/, threat_intel/, and live_alert.py all live at the
# project root, one level above this file (dashboard/ is a subfolder), so
# the project root needs to be on sys.path before importing them.
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP

from detections.suspicious_ports import detect
from threat_intel.threat_matcher import check_ip
from live_alert import generate_live_alert
from reports.report_export import export_alerts

PACKETS_FILE = "exports/live_packets.json"

MAX_ALERTS = 200            # alerts kept in exports/alerts.json
EXPORT_PACKET_LIMIT = 500   # packets kept for the flow-stats panel
EXPORT_INTERVAL_SECONDS = 5  # how often exports/ gets refreshed

_state_lock = threading.Lock()
_alerts = deque(maxlen=MAX_ALERTS)
_recent_packets = deque(maxlen=EXPORT_PACKET_LIMIT)

_stats_lock = threading.Lock()
_stats = {"total_packets": 0, "total_alerts": 0, "threat_hits": 0}


def _parse_packet(packet):
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


def _process_packet(packet):
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
    except Exception as exc:
        print(f"[capture] threat intel check failed: {exc}")

    try:
        result = detect(parsed)
    except Exception as exc:
        print(f"[capture] detection error: {exc}")
        result = None

    if not result:
        return

    try:
        alert = generate_live_alert(result["attack"], parsed)
    except Exception as exc:
        print(f"[capture] alert generation failed: {exc}")
        alert = None

    with _stats_lock:
        _stats["total_alerts"] += 1

    if alert:
        with _state_lock:
            _alerts.append(alert)


def _write_exports():
    try:
        os.makedirs("exports", exist_ok=True)
    except Exception as exc:
        print(f"[capture] could not create exports/ directory: {exc}")
        return

    with _state_lock:
        packets_snapshot = list(_recent_packets)
        alerts_snapshot = list(_alerts)

    try:
        with open(PACKETS_FILE, "w") as file:
            json.dump(packets_snapshot, file, indent=4)
    except Exception as exc:
        print(f"[capture] failed to write {PACKETS_FILE}: {exc}")

    with _stats_lock:
        stats_snapshot = dict(_stats)
    print(
        f"[capture] heartbeat — packets seen: {stats_snapshot['total_packets']}, "
        f"alerts: {stats_snapshot['total_alerts']}, "
        f"threat intel hits: {stats_snapshot['threat_hits']}"
    )

    try:
        export_alerts(alerts_snapshot)
    except Exception as exc:
        print(f"[capture] failed to export alerts: {exc}")


def _export_loop():
    while True:
        time.sleep(EXPORT_INTERVAL_SECONDS)
        _write_exports()


def _sniff_loop(interface):
    try:
        # No `count` limit here (unlike live_ids.py's count=100) — the
        # dashboard wants continuous capture, not a fixed test batch.
        sniff(iface=interface, prn=_process_packet, store=False)
    except PermissionError:
        print(
            "[capture] permission denied opening the interface. "
            "Run with sudo (Linux/macOS) or as Administrator with "
            "Npcap installed (Windows)."
        )
    except Exception as exc:
        print(f"[capture] sniff() failed: {exc}")


def start_capture(interface=None):
    """
    Start background packet capture + detection using the existing
    live-IDS pipeline (detections/suspicious_ports.py + live_alert.py).

    interface: name of the NIC to sniff (e.g. "eth0", "Wi-Fi").
               None lets scapy pick its default interface.

    Safe to call once per process. If Flask's debug reloader is active,
    call this only in the reloader's worker process (see app.py).
    """
    threading.Thread(
        target=_sniff_loop, args=(interface,), daemon=True
    ).start()

    threading.Thread(target=_export_loop, daemon=True).start()

    print(
        f"[capture] started on interface={interface or 'default'} "
        f"(exporting every {EXPORT_INTERVAL_SECONDS}s)"
    )
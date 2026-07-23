"""Flask web dashboard for live NIDS monitoring.

Serves a single-page dashboard (`templates/index.html`) that polls
`/api/dashboard-data` for alert counts, attack-type breakdowns, and
top talkers/ports/destinations, sourced from the JSON files that
`capture_engine.py` continuously writes to `exports/`.

Usage:
    python dashboard/app.py
    python dashboard/app.py --interface eth0 --port 8080

Requires elevated privileges to capture packets (sudo on Linux/macOS,
Administrator + Npcap on Windows).
"""

from __future__ import annotations

import argparse
import json
import logging
import os
from typing import Any

# Pin the working directory to the project root (one level above this
# dashboard/ folder) so the relative "exports/..." paths below and the
# ones inside reports/report_export.py always resolve to the same
# exports/ folder, no matter where this script gets launched from.
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(_PROJECT_ROOT)

from flask import Flask, jsonify, render_template

from capture_engine import start_capture
from logging_config import configure_logging

logger = logging.getLogger(__name__)

app = Flask(__name__)

ALERTS_FILE = "exports/alerts.json"
PACKETS_FILE = "exports/live_packets.json"

TOP_N = 5


def load_alerts() -> list[dict[str, Any]]:
    """Load the latest alerts snapshot written by the capture engine.

    Returns:
        The parsed alert list, or an empty list if the export file
        doesn't exist yet (e.g. before the first export cycle) or is
        unreadable.
    """
    try:
        with open(ALERTS_FILE, "r") as file:
            return json.load(file)
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        logger.warning("Could not load %s: %s", ALERTS_FILE, exc)
        return []


def build_dashboard_data() -> dict[str, Any]:
    """Assemble the alert-centric metrics shown on the dashboard.

    Returns:
        A dict with total alert count, distinct-source "active incidents"
        proxy metric, attack-type label/value series for charting, and
        the raw alert list.
    """
    alerts = load_alerts()

    attack_counts: dict[str, int] = {}
    for alert in alerts:
        attack = alert.get("attack", "Unknown")
        attack_counts[attack] = attack_counts.get(attack, 0) + 1

    # Proxy metric: distinct source IPs currently generating alerts.
    active_incidents = len(
        {alert.get("src_ip") for alert in alerts if alert.get("src_ip")}
    )

    return {
        "total_alerts": len(alerts),
        "active_incidents": active_incidents,
        "attack_labels": list(attack_counts.keys()),
        "attack_values": list(attack_counts.values()),
        "alerts": alerts,
    }


def get_network_flows() -> dict[str, Any]:
    """Assemble the packet-centric metrics (top sources/destinations/ports).

    Returns:
        A dict with the top `TOP_N` source IPs, destination IPs, and
        destination ports by packet count, each as `(value, count)` pairs.
    """
    try:
        with open(PACKETS_FILE, "r") as file:
            packets = json.load(file)
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        logger.warning("Could not load %s: %s", PACKETS_FILE, exc)
        packets = []

    source_ips: dict[str, int] = {}
    destination_ips: dict[str, int] = {}
    ports: dict[int, int] = {}

    for packet in packets:
        src = packet.get("src_ip", "Unknown")
        dst = packet.get("dst_ip", "Unknown")
        port = packet.get("dst_port")

        source_ips[src] = source_ips.get(src, 0) + 1
        destination_ips[dst] = destination_ips.get(dst, 0) + 1

        if port:
            ports[port] = ports.get(port, 0) + 1

    return {
        "top_sources": sorted(source_ips.items(), key=lambda x: x[1], reverse=True)[:TOP_N],
        "top_destinations": sorted(
            destination_ips.items(), key=lambda x: x[1], reverse=True
        )[:TOP_N],
        "top_ports": sorted(ports.items(), key=lambda x: x[1], reverse=True)[:TOP_N],
    }


@app.route("/")
def home():
    """Render the dashboard page with the current snapshot of data."""
    data = build_dashboard_data()
    flows = get_network_flows()
    return render_template("index.html", flows=flows, **data)


@app.route("/api/dashboard-data")
def dashboard_data():
    """Return the current dashboard snapshot as JSON, for the polling frontend."""
    data = build_dashboard_data()
    data["flows"] = get_network_flows()
    return jsonify(data)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the NIDS web dashboard.")
    parser.add_argument(
        "--interface",
        default=None,
        help="Network interface to capture on (default: scapy's default interface).",
    )
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind Flask to.")
    parser.add_argument("--port", type=int, default=5000, help="Port to bind Flask to.")
    parser.add_argument("--debug", action="store_true", help="Run Flask in debug mode.")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    configure_logging(level=logging.INFO)

    start_capture(interface=args.interface)

    # use_reloader=False is deliberate: the reloader launches a second
    # process on every code change, which would start a second,
    # competing background capture thread. Restart manually instead.
    app.run(host=args.host, port=args.port, debug=args.debug, use_reloader=False)


if __name__ == "__main__":
    main()

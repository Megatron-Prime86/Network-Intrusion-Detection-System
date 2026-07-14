import os

# Pin the working directory to the project root (one level above this
# dashboard/ folder) so the relative "exports/..." paths below and the
# ones inside reports/report_export.py always resolve to the same
# exports/ folder, no matter where this script gets launched from.
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(_PROJECT_ROOT)

from flask import Flask, render_template, jsonify

import json

from capture_engine import start_capture

app = Flask(__name__)

ALERTS_FILE = "exports/alerts.json"
PACKETS_FILE = "exports/live_packets.json"

# Set this to your NIC name (e.g. "eth0", "en0", "Wi-Fi") or leave None
# to let scapy pick its default interface.
CAPTURE_INTERFACE = None


def load_alerts():
    try:
        with open(ALERTS_FILE, "r") as file:
            return json.load(file)
    except Exception:
        return []


def build_dashboard_data():
    alerts = load_alerts()

    total_alerts = len(alerts)

    attack_counts = {}
    for alert in alerts:
        attack = alert.get("attack", "Unknown")
        attack_counts[attack] = attack_counts.get(attack, 0) + 1

    # Proxy metric: distinct source IPs currently generating alerts.
    active_incidents = len(
        {alert.get("src_ip") for alert in alerts if alert.get("src_ip")}
    )

    return {
        "total_alerts": total_alerts,
        "active_incidents": active_incidents,
        "attack_labels": list(attack_counts.keys()),
        "attack_values": list(attack_counts.values()),
        "alerts": alerts,
    }


def get_network_flows():
    try:
        with open(PACKETS_FILE, "r") as file:
            packets = json.load(file)
    except Exception:
        packets = []

    source_ips = {}
    destination_ips = {}
    ports = {}

    for packet in packets:
        src = packet.get("src_ip", "Unknown")
        dst = packet.get("dst_ip", "Unknown")
        port = packet.get("dst_port", None)

        source_ips[src] = source_ips.get(src, 0) + 1
        destination_ips[dst] = destination_ips.get(dst, 0) + 1

        if port:
            ports[port] = ports.get(port, 0) + 1

    return {
        "top_sources": sorted(
            source_ips.items(), key=lambda x: x[1], reverse=True
        )[:5],
        "top_destinations": sorted(
            destination_ips.items(), key=lambda x: x[1], reverse=True
        )[:5],
        "top_ports": sorted(
            ports.items(), key=lambda x: x[1], reverse=True
        )[:5],
    }


@app.route("/")
def home():
    data = build_dashboard_data()
    flows = get_network_flows()
    return render_template("index.html", flows=flows, **data)


@app.route("/api/dashboard-data")
def dashboard_data():
    data = build_dashboard_data()
    data["flows"] = get_network_flows()
    return jsonify(data)


if __name__ == "__main__":
    # use_reloader=False is deliberate: the reloader launches a second
    # process on every code change, which would start a second,
    # competing background capture thread. Restart manually instead.
    start_capture(interface=CAPTURE_INTERFACE)

    app.run(debug=True, use_reloader=False)
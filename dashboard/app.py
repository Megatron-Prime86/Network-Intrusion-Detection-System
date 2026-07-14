from flask import Flask, render_template, jsonify
import json

app = Flask(__name__)

ALERTS_FILE = "exports/alerts.json"


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


@app.route("/")

def get_network_flows():

    try:

        with open(
            "exports/live_packets.json",
            "r"
        ) as file:

            packets = json.load(file)

    except:

        packets = []

    source_ips = {}
    destination_ips = {}
    ports = {}

    for packet in packets:

        src = packet.get(
            "src_ip",
            "Unknown"
        )

        dst = packet.get(
            "dst_ip",
            "Unknown"
        )

        port = packet.get(
            "dst_port",
            None
        )

        source_ips[src] = (
            source_ips.get(
                src,
                0
            ) + 1
        )

        destination_ips[dst] = (
            destination_ips.get(
                dst,
                0
            ) + 1
        )

        if port:

            ports[port] = (
                ports.get(
                    port,
                    0
                ) + 1
            )

    return {

        "top_sources":
        sorted(
            source_ips.items(),
            key=lambda x: x[1],
            reverse=True
        )[:5],

        "top_destinations":
        sorted(
            destination_ips.items(),
            key=lambda x: x[1],
            reverse=True
        )[:5],

        "top_ports":
        sorted(
            ports.items(),
            key=lambda x: x[1],
            reverse=True
        )[:5]
    }

def home():
    data = build_dashboard_data()
    return render_template("index.html", **data)
    flows=get_network_flows()


@app.route("/api/dashboard-data")
def dashboard_data():
    return jsonify(build_dashboard_data())


if __name__ == "__main__":
    app.run(debug=True)

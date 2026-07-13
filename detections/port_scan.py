from collections import defaultdict


def detect_port_scans(packets):

    scanned_ports = defaultdict(set)

    alerts = []

    for packet in packets:

        scanned_ports[
            packet["src_ip"]
        ].add(
            packet["dst_port"]
        )

    for ip, ports in scanned_ports.items():

        if len(ports) >= 4:

            alerts.append(
                {
                    "src_ip": ip,
                    "attack": "Port Scan"
                }
            )

    return alerts
from detections.port_scan import detect_port_scans
from detections.brute_force import detect_bruteforce


def run_detections(packets):

    alerts = []

    alerts.extend(
        detect_port_scans(packets)
    )

    alerts.extend(
        detect_bruteforce(packets)
    )

    return alerts
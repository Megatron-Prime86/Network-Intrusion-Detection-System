from data.pcap_loader import load_pcap

packets = load_pcap(
    "pcap/sample.pcap"
)

from reports.network_report import (
    generate_network_report
)

from detections.detection_manager import (
    run_detections
)

from detections.ioc_extractor import (
    extract_iocs
)

from mappings.mitre_mapping import (
    MITRE_MAP
)

from mappings.risk_scores import (
    RISK_SCORES
)

from mappings.severity import (
    get_severity
)

from reports.alert_generator import (
    generate_alert
)

from reports.report_export import (
    export_alerts,
    export_txt_report,
    export_network_report
)

from analytics.statistics import (
    generate_statistics
)

from analytics.statistics_report import (
    print_statistics
)
from reports.report_export import (
    export_alerts,
    export_txt_report
)

from analytics.statistics_export import (
    export_statistics
)

print(
    "\nNETWORK INTRUSION DETECTION SYSTEM\n"
)

alerts = run_detections(
    packets
)

for alert in alerts:

    attack = alert["attack"]

    mitre = MITRE_MAP.get(
        attack,
        {
            "technique": "Unknown",
            "name": "Unknown",
            "tactic": "Unknown"
        }
    )

    risk_score = RISK_SCORES.get(
        attack,
        10
    )

    severity = get_severity(
        risk_score
    )

    output = generate_alert(
        attack,
        alert["src_ip"],
        mitre["technique"],
        mitre["tactic"],
        severity,
        risk_score
    )

    print(output)

# Export Alerts
export_alerts(
    alerts
)
export_txt_report(
    alerts
)

# Analytics
stats = generate_statistics(
    alerts
)
export_statistics(
    stats
)

print_statistics(
    stats
)

# IOC Extraction
iocs = extract_iocs(
    alerts
)

report = generate_network_report(
    alerts,
    stats,
    iocs
)

export_network_report(
    report
)

print("\nIOC SUMMARY\n")

for ioc in iocs:

    print(
        f"Source IP: {ioc['src_ip']}"
    )

    print(
        f"Attack: {ioc['attack']}"
    )

    print("-" * 30)

print(
    "\nAlerts exported successfully.\n"
)
from scapy.all import sniff
from scapy.layers.inet import (
    IP,
    TCP,
    UDP
)

from detections.suspicious_ports import detect

from threat_intel.threat_matcher import (
    check_ip
)

from live_alert import (
    generate_live_alert
)

from analytics.dashboard import (
    print_dashboard
)

# Counters
threat_hits = 0
total_packets = 0
total_alerts = 0


def process_packet(packet):

    global threat_hits
    global total_packets
    global total_alerts

    total_packets += 1

    if packet.haslayer(IP):

        dst_port = None

        if packet.haslayer(TCP):

            dst_port = packet[TCP].dport

        elif packet.haslayer(UDP):

            dst_port = packet[UDP].dport

        parsed_packet = {

            "src_ip":
            packet[IP].src,

            "dst_ip":
            packet[IP].dst,

            "protocol":
            packet[IP].proto,

            "dst_port":
            dst_port
        }

        # Threat Intelligence Check
        if check_ip(
            parsed_packet["src_ip"]
        ):

            threat_hits += 1

            print(
                "\nTHREAT INTELLIGENCE MATCH\n"
            )

            print(parsed_packet)

        # Detection Engine
        result = detect(
            parsed_packet
        )

        if result:

            total_alerts += 1

            generate_live_alert(
                result["attack"],
                parsed_packet
            )


print(
    "\nLIVE IDS STARTED\n"
)

sniff(
    count=100,
    prn=process_packet,
    store=False
)

print(
    "\nLIVE IDS STOPPED\n"
)

print_dashboard(
    total_packets,
    total_alerts,
    threat_hits
)
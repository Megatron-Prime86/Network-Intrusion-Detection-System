from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP


def capture_packets(count=100):

    captured = []

    packets = sniff(
        count=count
    )

    for packet in packets:

        if packet.haslayer(IP):

            dst_port = None

            if packet.haslayer(TCP):

                dst_port = packet[TCP].dport

            elif packet.haslayer(UDP):

                dst_port = packet[UDP].dport

            captured.append(
                {
                    "src_ip": packet[IP].src,
                    "dst_ip": packet[IP].dst,
                    "protocol": packet[IP].proto,
                    "dst_port": dst_port
                }
            )

    return captured
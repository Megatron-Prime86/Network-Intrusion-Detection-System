from scapy.all import rdpcap
from scapy.layers.inet import IP, TCP, UDP


def load_pcap(file_path):

    packets = rdpcap(file_path)

    parsed_packets = []

    for packet in packets:

        if packet.haslayer(IP):

            dst_port = None

            if packet.haslayer(TCP):

                dst_port = packet[TCP].dport

            elif packet.haslayer(UDP):

                dst_port = packet[UDP].dport

            parsed_packets.append(
                {
                    "src_ip": packet[IP].src,
                    "dst_ip": packet[IP].dst,
                    "protocol": packet[IP].proto,
                    "dst_port": dst_port
                }
            )

    return parsed_packets
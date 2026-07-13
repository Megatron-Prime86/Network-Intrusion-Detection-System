from data.pcap_loader import load_pcap

packets = load_pcap(
    "pcap/sample.pcap"
)

print(
    f"Packets Loaded: {len(packets)}"
)

for packet in packets[:10]:

    print(packet)
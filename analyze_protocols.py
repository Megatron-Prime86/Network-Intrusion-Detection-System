from data.pcap_loader import load_pcap

packets = load_pcap(
    "pcap/sample.pcap"
)

protocols = {}

for packet in packets:

    proto = packet["protocol"]

    protocols[proto] = (
        protocols.get(proto, 0) + 1
    )

print("\nPROTOCOL ANALYSIS\n")

for proto, count in protocols.items():

    print(
        f"{proto}: {count}"
    )
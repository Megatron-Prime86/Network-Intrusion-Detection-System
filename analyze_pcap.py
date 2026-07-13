from data.pcap_loader import load_pcap

packets = load_pcap(
    "pcap/sample.pcap"
)

ports = {}

for packet in packets:

    port = packet["dst_port"]

    if port:

        ports[port] = (
            ports.get(port, 0) + 1
        )

print("\nTOP PORTS\n")

for port, count in sorted(
    ports.items(),
    key=lambda x: x[1],
    reverse=True
)[:15]:

    print(
        f"Port {port}: {count}"
    )
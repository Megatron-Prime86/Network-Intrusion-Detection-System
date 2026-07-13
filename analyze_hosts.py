from data.pcap_loader import load_pcap

packets = load_pcap(
    "pcap/sample.pcap"
)

hosts = {}

for packet in packets:

    ip = packet["src_ip"]

    hosts[ip] = (
        hosts.get(ip, 0) + 1
    )

print("\nTOP TALKERS\n")

for ip, count in sorted(
    hosts.items(),
    key=lambda x: x[1],
    reverse=True
):

    print(
        f"{ip}: {count}"
    )
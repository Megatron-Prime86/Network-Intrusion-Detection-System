from data.live_capture import capture_packets

packets = capture_packets(
    count=20
)

print(
    f"Captured {len(packets)} packets"
)

for packet in packets:

    print(packet)
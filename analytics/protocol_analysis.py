from collections import Counter


def analyze_protocols(packets):

    protocol_counter = Counter()

    for packet in packets:

        protocol_counter[
            packet["protocol"]
        ] += 1

    return protocol_counter
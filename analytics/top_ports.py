from collections import Counter


def get_top_ports(packets):

    counter = Counter()

    for packet in packets:

        if packet["dst_port"]:

            counter[
                packet["dst_port"]
            ] += 1

    return counter.most_common(10)

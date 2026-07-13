from collections import Counter


def get_top_talkers(packets):

    counter = Counter()

    for packet in packets:

        counter[
            packet["src_ip"]
        ] += 1

    return counter.most_common(10)
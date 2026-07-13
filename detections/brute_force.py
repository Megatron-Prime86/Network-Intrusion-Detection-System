from collections import defaultdict


def detect_bruteforce(packets):

    attempts = defaultdict(int)

    alerts = []

    for packet in packets:

        key = (
            packet["src_ip"],
            packet["dst_port"]
        )

        attempts[key] += 1

    for key, count in attempts.items():

        if count >= 5:

            alerts.append(
                {
                    "src_ip": key[0],
                    "attack": "Brute Force"
                }
            )

    return alerts
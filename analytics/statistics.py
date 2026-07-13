from collections import Counter


def generate_statistics(alerts):

    attack_counter = Counter()
    ip_counter = Counter()

    for alert in alerts:

        attack_counter[
            alert["attack"]
        ] += 1

        ip_counter[
            alert["src_ip"]
        ] += 1

    return {

        "total_alerts":
        len(alerts),

        "most_common_attack":
        attack_counter.most_common(1)[0][0]
        if attack_counter else "None",

        "most_active_source":
        ip_counter.most_common(1)[0][0]
        if ip_counter else "None"
    }
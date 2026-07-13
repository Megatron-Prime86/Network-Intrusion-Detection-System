def detect(packet):

    risky_ports = [
        21,
        22,
        23,
        3389,
        5900
    ]

    if packet["dst_port"] in risky_ports:

        return {
            "attack": "Suspicious Port Access"
        }

    return None
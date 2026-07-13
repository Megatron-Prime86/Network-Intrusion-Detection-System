import json


def load_iocs():

    with open(
        "threat_intel/malicious_ips.json",
        "r"
    ) as file:

        return json.load(file)


def check_ip(ip):

    iocs = load_iocs()

    return ip in iocs
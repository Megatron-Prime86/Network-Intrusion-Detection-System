def extract_iocs(alerts):

    iocs = []

    for alert in alerts:

        iocs.append(
            {
                "src_ip":
                alert["src_ip"],

                "attack":
                alert["attack"]
            }
        )

    return iocs
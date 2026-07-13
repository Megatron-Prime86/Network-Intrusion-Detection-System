import json


def export_alerts(alerts):

    with open(
        "exports/alerts.json",
        "w"
    ) as file:

        json.dump(
            alerts,
            file,
            indent=4
        )


def export_txt_report(alerts):

    with open(
        "exports/incident_report.txt",
        "w"
    ) as file:

        for alert in alerts:

            file.write(
                f"""
================================

Attack:
{alert['attack']}

Source IP:
{alert['src_ip']}

================================

"""
            )


def export_network_report(report):

    with open(
        "exports/network_security_report.txt",
        "w"
    ) as file:

        file.write(report)
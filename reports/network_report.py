def generate_network_report(
    alerts,
    stats,
    iocs
):

    report = f"""
==================================================

NETWORK SECURITY REPORT

Total Alerts:
{stats['total_alerts']}

Most Common Attack:
{stats['most_common_attack']}

Most Active Source:
{stats['most_active_source']}

==================================================

IOC SUMMARY

"""

    for ioc in iocs:

        report += f"""
Source IP:
{ioc['src_ip']}

Attack:
{ioc['attack']}
"""

    return report
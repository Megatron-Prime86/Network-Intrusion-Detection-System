def print_dashboard(
    packets,
    alerts,
    threat_hits
):

    print("\n" + "=" * 50)

    print(
        "NETWORK SECURITY DASHBOARD"
    )

    print("=" * 50)

    print(
        f"Packets Captured: {packets}"
    )

    print(
        f"Alerts Generated: {alerts}"
    )

    print(
        f"Threat Intel Hits: {threat_hits}"
    )

    print("=" * 50)
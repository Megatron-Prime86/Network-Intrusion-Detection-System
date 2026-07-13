def print_statistics(stats):

    print("\n" + "=" * 50)

    print(
        "NETWORK SECURITY ANALYTICS"
    )

    print("=" * 50)

    print(
        f"Total Alerts: "
        f"{stats['total_alerts']}"
    )

    print(
        f"Most Common Attack: "
        f"{stats['most_common_attack']}"
    )

    print(
        f"Most Active Source: "
        f"{stats['most_active_source']}"
    )

    print("=" * 50)
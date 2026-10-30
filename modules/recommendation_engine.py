def build_recommendations(events):

    event_ids = []

    for event in events:

        event_ids.append(
            event["EventID"]
        )

    recommendations = []

    # Disk + NTFS

    if 7 in event_ids and 55 in event_ids:

        recommendations.append(
            "Backup critical data immediately."
        )

        recommendations.append(
            "Run SMART diagnostics on all disks."
        )

        recommendations.append(
            "Run CHKDSK /F and review storage logs."
        )

    # Disk only

    elif 7 in event_ids:

        recommendations.append(
            "Check SMART health immediately."
        )

        recommendations.append(
            "Schedule disk replacement planning."
        )

    # NTFS only

    elif 55 in event_ids:

        recommendations.append(
            "Run CHKDSK /F."
        )

        recommendations.append(
            "Investigate previous unexpected shutdowns."
        )

    # Power issues

    if 41 in event_ids and 6008 in event_ids:

        recommendations.append(
            "Check power supply, UPS and power stability."
        )

        recommendations.append(
            "Check system temperatures."
        )

        recommendations.append(
            "Run memory diagnostics."
        )

    elif 41 in event_ids:

        recommendations.append(
            "Check power supply and temperatures."
        )

    elif 6008 in event_ids:

        recommendations.append(
            "Investigate unexpected shutdowns."
        )

    # DCOM

    if 10016 in event_ids:

        recommendations.append(
            "DistributedCOM warnings are usually low priority."
        )

    # No findings

    if not recommendations:

        recommendations.append(
            "No critical actions recommended."
        )

    return recommendations
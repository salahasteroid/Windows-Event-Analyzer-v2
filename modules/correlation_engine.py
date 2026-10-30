def correlate_events(events):

    event_ids = []

    for event in events:

        event_ids.append(
            event["EventID"]
        )

    findings = []

    # Power failures

    if 41 in event_ids and 6008 in event_ids:

        findings.append(
            "Unexpected shutdown pattern detected. "
            "Possible power outage, PSU issue, "
            "hardware instability or system crash."
        )

    # Disk corruption chain

    if 7 in event_ids and 55 in event_ids:

        findings.append(
            "Disk errors and NTFS corruption detected. "
            "Storage subsystem failure is likely."
        )

    # Disk only

    elif 7 in event_ids:

        findings.append(
            "Disk bad sectors detected. "
            "Check SMART health immediately."
        )

    # NTFS only

    elif 55 in event_ids:

        findings.append(
            "File system corruption detected. "
            "Run CHKDSK and verify disk health."
        )

    # Common DCOM noise

    if 10016 in event_ids:

        findings.append(
            "DistributedCOM warnings detected. "
            "Usually low risk and often harmless."
        )

    # No findings

    if not findings:

        findings.append(
            "No known event correlation patterns found."
        )

    return findings
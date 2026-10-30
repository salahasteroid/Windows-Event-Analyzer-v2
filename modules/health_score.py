def calculate_health_score(events):

    score = 100

    event_counts = {}

    for event in events:

        event_id = event["EventID"]

        event_counts[event_id] = (
            event_counts.get(event_id, 0) + 1
        )

    # Power issues

    score -= min(
        event_counts.get(41, 0) * 15,
        30
    )

    score -= min(
        event_counts.get(6008, 0) * 10,
        20
    )

    # Storage issues

    score -= min(
        event_counts.get(7, 0) * 25,
        40
    )

    score -= min(
        event_counts.get(55, 0) * 20,
        30
    )

    # Windows Update failures

    score -= min(
        event_counts.get(20, 0) * 5,
        15
    )

    # DCOM warnings

    score -= min(
        event_counts.get(10016, 0),
        5
    )

    if (
        event_counts.get(7, 0) > 0
        and event_counts.get(55, 0) > 0
    ):
        score -= 10

    if (
        event_counts.get(41, 0) > 0
        and event_counts.get(6008, 0) > 0
    ):
        score -= 10

    if score < 0:
        score = 0

    return score
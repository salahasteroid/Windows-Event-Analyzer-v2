from collections import Counter


def calculate_trends(events):

    event_counter = Counter()

    for event in events:

        event_counter[
            event["EventID"]
        ] += 1

    trends = []

    for event_id, count in (
        event_counter.most_common()
    ):

        trends.append({
            "event_id": event_id,
            "count": count
        })

    return trends
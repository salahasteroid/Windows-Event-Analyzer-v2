"""Collapse repeated events into one line with a count."""

from modules.time_range import parse_event_time


def group_events(events):
    """Group by provider, Event ID and level; most frequent first.

    Each group is {"event_id", "source", "level_name", "count",
    "first_time", "last_time", "name", "known"}. Times are the earliest and
    latest event time text in the group.
    """

    groups = {}

    for event in events:

        key = (
            str(event.get("Source", "")).casefold(),
            event.get("EventID"),
            event.get("LevelName", ""),
        )

        analysis = event.get("Analysis") or {}

        group = groups.setdefault(key, {
            "event_id": event.get("EventID"),
            "source": event.get("Source", ""),
            "level_name": event.get("LevelName", ""),
            "count": 0,
            "first_time": "",
            "last_time": "",
            "name": analysis.get("name", ""),
            "known": bool(analysis.get("known")),
        })

        group["count"] += 1

        text = event.get("Time", "")
        moment = parse_event_time(text)

        if not text or moment is None:
            continue

        first = parse_event_time(group["first_time"])
        last = parse_event_time(group["last_time"])

        if first is None or moment < first:
            group["first_time"] = text

        if last is None or moment > last:
            group["last_time"] = text

    return sorted(
        groups.values(),
        key=lambda group: (-group["count"], str(group["event_id"]))
    )

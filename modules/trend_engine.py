"""Run-over-run trend analysis.

Every live or remote run is stored in a small JSON history file next to its
reports. The next run is compared with the most recent earlier run that used
the same event-level filter, and events are reported as new, increased,
decreased or no longer seen. Counts are compared as events per day, so runs
over different time ranges can still be compared.
"""

import json
import os
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


HISTORY_FILE_NAME = "history.json"
MAX_HISTORY_RUNS = 30

# A change counts as "increased"/"decreased" when the daily rate moves by
# at least this factor AND at least this many events per day.
CHANGE_FACTOR = 1.5
MIN_CHANGE = 2.0

SECONDS_PER_DAY = 86400


def calculate_trends(events):
    """Event counts, most frequent first."""

    counter = Counter(event["EventID"] for event in events)

    return [
        {"event_id": event_id, "count": count}
        for event_id, count in counter.most_common()
    ]


def _key(source, event_id):

    return f"{source}|{event_id}"


def _split_key(key):

    source, _, event_id = key.rpartition("|")

    return source, event_id


def summarize_run(events):
    """Counts per (provider, Event ID)."""

    counts = Counter(
        _key(event.get("Source", "Unknown"), event.get("EventID"))
        for event in events
    )

    return dict(counts)


def load_history(history_path):
    """Saved runs, oldest first. A missing or damaged file gives []."""

    try:
        with open(history_path, "r", encoding="utf-8") as file:
            data = json.load(file)
    except FileNotFoundError:
        return []
    except (OSError, ValueError):
        print(
            f"Warning: could not read trend history {history_path}; "
            "starting a new history."
        )
        return []

    runs = data.get("runs") if isinstance(data, dict) else None

    if not isinstance(runs, list):
        return []

    return [
        run for run in runs
        if isinstance(run, dict)
        and isinstance(run.get("counts"), dict)
        and isinstance(run.get("window_seconds"), (int, float))
        and run["window_seconds"] > 0
    ]


def _entry(key, count, previous_count):

    source, event_id = _split_key(key)

    return {
        "source": source,
        "event_id": event_id,
        "count": count,
        "previous_count": previous_count,
    }


def compare_with_history(
    events,
    window_seconds,
    history_path,
    levels=None
):
    """Compare this run with the last comparable saved run.

    Does not change the history file; call record_run() for that.
    """

    unavailable = {
        "available": False,
        "previous_run": None,
        "new": [],
        "increased": [],
        "decreased": [],
        "resolved": [],
    }

    if window_seconds <= 0:
        return {**unavailable, "message": "No time range to compare."}

    levels_key = sorted(levels) if levels is not None else None

    previous = None

    for run in reversed(load_history(history_path)):
        if run.get("levels") == levels_key:
            previous = run
            break

    if previous is None:
        return {
            **unavailable,
            "message": (
                "No earlier run with the same level filter to compare "
                "with. This run will be the starting point."
            ),
        }

    current = summarize_run(events)
    scale_now = SECONDS_PER_DAY / window_seconds
    scale_before = SECONDS_PER_DAY / previous["window_seconds"]

    result = {
        **unavailable,
        "available": True,
        "previous_run": previous.get("time"),
    }

    for key, count in sorted(current.items()):

        before = previous["counts"].get(key)

        if before is None:
            result["new"].append(_entry(key, count, 0))
            continue

        rate_now = count * scale_now
        rate_before = before * scale_before
        change = rate_now - rate_before

        if rate_now >= rate_before * CHANGE_FACTOR and change >= MIN_CHANGE:
            result["increased"].append(_entry(key, count, before))
        elif (
            rate_now * CHANGE_FACTOR <= rate_before
            and -change >= MIN_CHANGE
        ):
            result["decreased"].append(_entry(key, count, before))

    for key, before in sorted(previous["counts"].items()):

        if key not in current:
            result["resolved"].append(_entry(key, 0, before))

    result["message"] = (
        f"Compared with the run on {previous.get('time', 'unknown date')}: "
        f"{len(result['new'])} new, {len(result['increased'])} increased, "
        f"{len(result['decreased'])} decreased, "
        f"{len(result['resolved'])} no longer seen."
    )

    return result


def record_run(
    events,
    window_seconds,
    history_path,
    levels=None,
    now=None
):
    """Append this run to the history file. Returns True when saved."""

    history_path = Path(history_path)
    runs = load_history(history_path)

    moment = now or datetime.now(timezone.utc)

    runs.append({
        "time": moment.strftime("%Y-%m-%d %H:%M UTC"),
        "window_seconds": window_seconds,
        "levels": sorted(levels) if levels is not None else None,
        "counts": summarize_run(events),
    })

    runs = runs[-MAX_HISTORY_RUNS:]

    temporary_path = history_path.with_suffix(".tmp")

    try:
        history_path.parent.mkdir(parents=True, exist_ok=True)

        with open(temporary_path, "w", encoding="utf-8") as file:
            json.dump({"runs": runs}, file, indent=1)

        os.replace(temporary_path, history_path)

    except OSError as ex:

        print(f"Warning: could not save trend history: {ex}")

        try:
            temporary_path.unlink(missing_ok=True)
        except OSError:
            pass

        return False

    return True

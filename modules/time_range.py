from datetime import datetime, timedelta, timezone


def _to_utc(value):
    if value.tzinfo is None:
        return value.astimezone(timezone.utc)
    return value.astimezone(timezone.utc)


def resolve_time_range(start_time=None, end_time=None):
    if end_time is None:
        end_time = datetime.now(timezone.utc)
    else:
        end_time = _to_utc(end_time)

    if start_time is None:
        start_time = end_time - timedelta(hours=24)
    else:
        start_time = _to_utc(start_time)

    if start_time > end_time:
        raise ValueError("Start time must be earlier than or equal to end time.")

    return start_time, end_time


def parse_event_time(value):
    if not value:
        return None

    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    return parsed.astimezone(timezone.utc)


def format_event_log_time(value):
    return value.astimezone(timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%S.%fZ"
    )

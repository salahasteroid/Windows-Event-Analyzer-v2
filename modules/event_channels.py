"""Which Windows event logs can be read, and which events are selected.

System and Application are selected by event level (Critical, Error and
Warning by default). The Security log records audit events at the
Information level, so a level filter would hide all of them; it is selected
by a list of security-relevant Event IDs instead.
"""

from modules.time_range import format_event_log_time


DEFAULT_LOGS = ("System",)

SUPPORTED_LOGS = ("System", "Application", "Security")

# Security events worth collecting (account, group, policy and persistence
# changes, failed logons). Successful logons (4624) and similar high-volume
# events are left out on purpose.
SECURITY_EVENT_IDS = (
    1102,
    4625,
    4697,
    4698,
    4719,
    4720,
    4722,
    4724,
    4725,
    4726,
    4728,
    4732,
    4740,
    4756,
    4771,
)


def normalize_logs(logs=None):
    """Validated, de-duplicated log names in canonical spelling."""

    if logs is None:
        return DEFAULT_LOGS

    if isinstance(logs, str):
        logs = [part for part in logs.replace(";", ",").split(",")]

    by_name = {name.casefold(): name for name in SUPPORTED_LOGS}
    normalized = []

    for log in logs:

        key = str(log).strip().casefold()

        if not key:
            continue

        if key not in by_name:
            raise ValueError(
                f"Unsupported log '{log}'. Choose from: "
                + ", ".join(SUPPORTED_LOGS)
                + "."
            )

        if by_name[key] not in normalized:
            normalized.append(by_name[key])

    if not normalized:
        raise ValueError("Select at least one log.")

    return tuple(normalized)


def uses_level_filter(log_name):

    return log_name != "Security"


def build_query(log_name, levels, start_time, end_time):
    """XPath query for one log and time range."""

    conditions = [
        "TimeCreated[@SystemTime >= "
        f"'{format_event_log_time(start_time)}' and @SystemTime <= "
        f"'{format_event_log_time(end_time)}']"
    ]

    if log_name == "Security":

        conditions.append(
            "("
            + " or ".join(
                f"EventID={event_id}" for event_id in SECURITY_EVENT_IDS
            )
            + ")"
        )

    elif levels is not None:

        conditions.append(
            "("
            + " or ".join(f"Level={level}" for level in levels)
            + ")"
        )

    return "*[System[" + " and ".join(conditions) + "]]"


def event_selected(channel, level, event_id, levels):
    """The same selection for records read one by one (EVTX files)."""

    if channel == "Security":
        return event_id in SECURITY_EVENT_IDS

    return levels is None or level in levels

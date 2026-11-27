"""Who failed to log on, and what changed, from Security log events."""

from collections import Counter

from modules.event_data import get_event_data_value


ACCOUNT_CHANGE_IDS = (4720, 4722, 4724, 4725, 4726)
GROUP_CHANGE_IDS = (4728, 4732, 4756)


def _field(event, *names):

    wanted = {name.casefold() for name in names}

    for item in event.get("Data", []):

        if (
            isinstance(item, dict)
            and str(item.get("name", "")).casefold() in wanted
        ):
            value = get_event_data_value(item).strip()

            if value and value != "-":
                return value

    return ""


def _is_security_event(event):

    return (
        event.get("Channel") == "Security"
        or "security-auditing" in str(event.get("Source", "")).casefold()
        or event.get("EventID") == 1102
    )


def summarize_security(events, top=5):
    """Counts and top offenders, or None when there are no security events."""

    security_events = [
        event for event in events if _is_security_event(event)
    ]

    if not security_events:
        return None

    failed = [e for e in security_events if e.get("EventID") == 4625]
    lockouts = [e for e in security_events if e.get("EventID") == 4740]

    def count(ids):
        return sum(1 for e in security_events if e.get("EventID") in ids)

    accounts = Counter(
        _field(e, "TargetUserName") or "(unknown)" for e in failed
    )
    sources = Counter(
        _field(e, "IpAddress", "WorkstationName") or "(unknown)"
        for e in failed
    )
    locked = Counter(
        _field(e, "TargetUserName") or "(unknown)" for e in lockouts
    )

    return {
        "events": len(security_events),
        "failed_logons": len(failed),
        "top_failed_accounts": accounts.most_common(top),
        "top_failed_sources": sources.most_common(top),
        "lockouts": len(lockouts),
        "locked_accounts": locked.most_common(top),
        "account_changes": count(ACCOUNT_CHANGE_IDS),
        "group_changes": count(GROUP_CHANGE_IDS),
        "log_cleared": count((1102,)),
        "audit_policy_changes": count((4719,)),
        "persistence": count((4697, 4698)),
    }

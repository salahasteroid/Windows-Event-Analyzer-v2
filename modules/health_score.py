"""System health score (0-100) built from every Critical/Error/Warning event.

How the score is calculated:

1. Events are grouped by (provider, Event ID).
2. Each group has a severity (0-100): from the event definition when the
   event is known, otherwise a default taken from the Windows level.
3. A group's penalty is  severity_factor * (severity / 100) ** 2  times a
   repeat multiplier  min(1 + log2(count), repeat_multiplier_cap).
   A repeating problem therefore costs more than a one-off, but never
   without limit.
4. The penalties of one provider are capped at per_source_cap, so a single
   noisy provider cannot take the score to zero on its own.
5. Matching correlation rules add their score_penalty.

The numbers can be tuned in the "health" section of database/rules.json.
"""

import math

from modules.database_loader import load_rules_database
from modules.event_catalog import (
    find_event_definition,
    level_default_severity,
)
from modules.rules_engine import evaluate_rules


DEFAULT_SETTINGS = {
    "severity_factor": 20.0,
    "repeat_multiplier_cap": 2.5,
    "per_source_cap": 40.0,
}

# Windows levels that count as problems: Critical, Error, Warning.
PROBLEM_LEVELS = (1, 2, 3)


def get_health_settings():

    settings = dict(DEFAULT_SETTINGS)

    configured = load_rules_database().get("health")

    if isinstance(configured, dict):

        for name in settings:

            value = configured.get(name)

            if (
                isinstance(value, (int, float))
                and not isinstance(value, bool)
                and value > 0
            ):
                settings[name] = float(value)

    return settings


def _event_severity(event):

    definition = find_event_definition(
        event.get("EventID"),
        event.get("Source")
    )

    if definition is not None:

        severity = definition.get("severity")

        if (
            isinstance(severity, (int, float))
            and not isinstance(severity, bool)
        ):
            return severity

    return level_default_severity(event.get("Level"))


def explain_health_score(events, rule_matches=None):
    """Score plus the list of what reduced it.

    Returns {"score", "total_penalty", "events", "rules"} where "events"
    and "rules" list the deductions, largest first.
    """

    settings = get_health_settings()

    if rule_matches is None:
        rule_matches = evaluate_rules(events)

    groups = {}

    for event in events:

        level = event.get("Level")

        # An event without a level is still scored from its definition.
        if level is not None and level not in PROBLEM_LEVELS:
            continue

        severity = _event_severity(event)

        if severity <= 0:
            continue

        source = str(event.get("Source") or "Unknown")
        key = (source.casefold(), event.get("EventID"))

        group = groups.setdefault(key, {
            "source": source,
            "event_id": event.get("EventID"),
            "count": 0,
            "severity": 0,
        })

        group["count"] += 1
        group["severity"] = max(group["severity"], severity)

    source_totals = {}

    for key, group in groups.items():

        base = (
            settings["severity_factor"]
            * (min(group["severity"], 100) / 100) ** 2
        )

        multiplier = min(
            1 + math.log2(group["count"]),
            settings["repeat_multiplier_cap"]
        )

        group["penalty"] = base * multiplier
        source_totals[key[0]] = (
            source_totals.get(key[0], 0) + group["penalty"]
        )

    for key, group in groups.items():

        total = source_totals[key[0]]

        if total > settings["per_source_cap"]:
            group["penalty"] *= settings["per_source_cap"] / total

    event_deductions = sorted(
        (
            {
                "source": group["source"],
                "event_id": group["event_id"],
                "count": group["count"],
                "severity": group["severity"],
                "penalty": round(group["penalty"], 1),
            }
            for group in groups.values()
            if group["penalty"] > 0
        ),
        key=lambda item: -item["penalty"]
    )

    rule_deductions = sorted(
        (
            {
                "rule_id": match["id"],
                "title": match["title"],
                "penalty": round(float(match["score_penalty"]), 1),
            }
            for match in rule_matches
            if match["score_penalty"] > 0
        ),
        key=lambda item: -item["penalty"]
    )

    total_penalty = (
        sum(group["penalty"] for group in groups.values())
        + sum(match["score_penalty"] for match in rule_matches)
    )

    score = int(math.floor(100 - total_penalty + 0.5))

    return {
        "score": max(0, min(100, score)),
        "total_penalty": round(total_penalty, 1),
        "events": event_deductions,
        "rules": rule_deductions,
    }


def calculate_health_score(events, rule_matches=None):

    return explain_health_score(events, rule_matches)["score"]

"""Data-driven correlation rules.

Rules live in database/rules.json so they can be edited without changing
code. Each rule looks like this:

    {
      "id": "disk-ntfs-chain",
      "title": "Disk errors with NTFS corruption",
      "finding": "Text shown in the report.",
      "recommendations": ["Action 1", "Action 2"],
      "all_of": [{"id": 7, "sources": ["disk"]}, 55],
      "min_count": 1,
      "window_minutes": 360,
      "severity": 95,
      "score_penalty": 20,
      "suppresses": ["disk-bad-blocks"]
    }

* Use "all_of" (every listed event must occur) or "any_of" (at least
  "min_count" events from the list). An event is an Event ID, or an object
  with "id" and optional "sources" (provider names, case-insensitive).
* "min_count": for all_of, how many times EACH event must occur; for any_of,
  how many events in total. Default 1.
* "window_minutes": the events must occur inside this window.
* "severity" (0-100) orders the findings; "score_penalty" is subtracted from
  the health score.
* "suppresses": ids of more general rules to hide when this rule matches.
"""

from collections import defaultdict
from datetime import timedelta

from modules.database_loader import load_rules_database
from modules.time_range import parse_event_time


NO_FINDINGS_TEXT = "No known event correlation patterns found."
NO_RECOMMENDATIONS_TEXT = "No critical actions recommended."


def _is_int(value):

    return isinstance(value, int) and not isinstance(value, bool)


def _normalize_spec(spec):

    if _is_int(spec):
        return {"id": spec, "sources": None}

    if isinstance(spec, dict) and _is_int(spec.get("id")):

        sources = spec.get("sources")

        if sources is None:
            return {"id": spec["id"], "sources": None}

        if (
            isinstance(sources, list)
            and sources
            and all(isinstance(item, str) for item in sources)
        ):
            return {
                "id": spec["id"],
                "sources": frozenset(item.casefold() for item in sources),
            }

    raise ValueError(f"invalid event specification: {spec!r}")


def _normalize_rule(raw, order):

    if not isinstance(raw, dict):
        raise ValueError("a rule must be a JSON object")

    rule_id = raw.get("id")

    if not isinstance(rule_id, str) or not rule_id.strip():
        raise ValueError("a rule needs a text 'id'")

    finding = raw.get("finding")

    if not isinstance(finding, str) or not finding.strip():
        raise ValueError("a rule needs a text 'finding'")

    all_of = raw.get("all_of") or []
    any_of = raw.get("any_of") or []

    if bool(all_of) == bool(any_of):
        raise ValueError("use exactly one of 'all_of' or 'any_of'")

    specs = all_of if all_of else any_of

    if not isinstance(specs, list):
        raise ValueError("'all_of'/'any_of' must be a list")

    recommendations = raw.get("recommendations", [])

    if not isinstance(recommendations, list) or not all(
        isinstance(item, str) for item in recommendations
    ):
        raise ValueError("'recommendations' must be a list of text")

    min_count = raw.get("min_count", 1)

    if not _is_int(min_count) or min_count < 1:
        raise ValueError("'min_count' must be a whole number of at least 1")

    window = raw.get("window_minutes")

    if window is not None and (
        not isinstance(window, (int, float))
        or isinstance(window, bool)
        or window <= 0
    ):
        raise ValueError("'window_minutes' must be a positive number")

    severity = raw.get("severity", 50)
    penalty = raw.get("score_penalty", 0)

    for name, value in (("severity", severity), ("score_penalty", penalty)):
        if (
            not isinstance(value, (int, float))
            or isinstance(value, bool)
            or value < 0
        ):
            raise ValueError(f"'{name}' must be a number, 0 or more")

    suppresses = raw.get("suppresses", [])

    if not isinstance(suppresses, list) or not all(
        isinstance(item, str) for item in suppresses
    ):
        raise ValueError("'suppresses' must be a list of rule ids")

    return {
        "id": rule_id.strip(),
        "title": str(raw.get("title") or rule_id).strip(),
        "finding": finding.strip(),
        "recommendations": [item.strip() for item in recommendations],
        "mode": "all_of" if all_of else "any_of",
        "specs": [_normalize_spec(spec) for spec in specs],
        "min_count": min_count,
        "window": (
            timedelta(minutes=window) if window is not None else None
        ),
        "severity": severity,
        "score_penalty": penalty,
        "suppresses": suppresses,
        "order": order,
    }


def compile_rules(data):
    """Validate the rules file content. Returns (rules, errors)."""

    rules = []
    errors = []
    seen = set()

    raw_rules = data.get("rules") if isinstance(data, dict) else None

    if not isinstance(raw_rules, list):
        return [], ["rules.json needs a 'rules' list."]

    for order, raw in enumerate(raw_rules):

        try:
            rule = _normalize_rule(raw, order)
        except ValueError as ex:
            label = raw.get("id") if isinstance(raw, dict) else order + 1
            errors.append(f"rule {label}: {ex}")
            continue

        if rule["id"] in seen:
            errors.append(f"rule {rule['id']}: duplicate id, ignored")
            continue

        seen.add(rule["id"])
        rules.append(rule)

    return rules, errors


_compiled = {"source": None, "rules": []}


def load_rules():
    """Compiled rules from rules.json (cached until the file is reloaded)."""

    data = load_rules_database()

    if _compiled["source"] is not data:

        rules, errors = compile_rules(data)

        for error in errors:
            print(f"Rules Warning: {error}")

        _compiled["source"] = data
        _compiled["rules"] = rules

    return _compiled["rules"]


def _spec_matches(spec, event):

    if event.get("EventID") != spec["id"]:
        return False

    if spec["sources"] is None:
        return True

    return str(event.get("Source", "")).casefold() in spec["sources"]


def _times(events):
    """Parsed times of the events, or None if any time is missing."""

    parsed = [parse_event_time(event.get("Time")) for event in events]

    if any(value is None for value in parsed):
        return None

    return parsed


def _all_within_window(groups, minimum, window):
    """True if one window holds at least `minimum` events from every group."""

    tagged = sorted(
        (moment, index)
        for index, group in enumerate(groups)
        for moment in group
    )

    counts = [0] * len(groups)
    left = 0

    for right in range(len(tagged)):

        counts[tagged[right][1]] += 1

        while tagged[right][0] - tagged[left][0] > window:
            counts[tagged[left][1]] -= 1
            left += 1

        if all(count >= minimum for count in counts):
            return True

    return False


def _any_within_window(moments, minimum, window):

    ordered = sorted(moments)
    left = 0

    for right in range(len(ordered)):

        while ordered[right] - ordered[left] > window:
            left += 1

        if right - left + 1 >= minimum:
            return True

    return False


def _evaluate_rule(rule, by_id):

    matches_per_spec = []

    for spec in rule["specs"]:

        matches_per_spec.append([
            event
            for event in by_id.get(spec["id"], ())
            if _spec_matches(spec, event)
        ])

    if rule["mode"] == "all_of":

        if any(
            len(matches) < rule["min_count"]
            for matches in matches_per_spec
        ):
            return None

        matched = {
            id(event): event
            for matches in matches_per_spec
            for event in matches
        }

        if rule["window"] is not None:

            groups = [_times(matches) for matches in matches_per_spec]

            # Events without a usable timestamp: the window cannot be
            # checked, so the rule is applied as if there were no window.
            if all(group is not None for group in groups):
                if not _all_within_window(
                    groups,
                    rule["min_count"],
                    rule["window"]
                ):
                    return None

    else:

        matched = {
            id(event): event
            for matches in matches_per_spec
            for event in matches
        }

        if len(matched) < rule["min_count"]:
            return None

        if rule["window"] is not None:

            moments = _times(list(matched.values()))

            if moments is not None and not _any_within_window(
                moments,
                rule["min_count"],
                rule["window"]
            ):
                return None

    return {
        "id": rule["id"],
        "title": rule["title"],
        "finding": rule["finding"],
        "recommendations": list(rule["recommendations"]),
        "severity": rule["severity"],
        "score_penalty": rule["score_penalty"],
        "count": len(matched),
        "suppresses": list(rule["suppresses"]),
        "order": rule["order"],
    }


def evaluate_rules(events, rules=None):
    """Return the rules that match these events, most severe first."""

    if rules is None:
        rules = load_rules()

    by_id = defaultdict(list)

    for event in events:
        by_id[event.get("EventID")].append(event)

    matches = []

    for rule in rules:

        result = _evaluate_rule(rule, by_id)

        if result is not None:
            matches.append(result)

    suppressed = {
        rule_id
        for match in matches
        for rule_id in match["suppresses"]
    }

    matches = [
        match for match in matches
        if match["id"] not in suppressed
    ]

    matches.sort(key=lambda match: (-match["severity"], match["order"]))

    return matches


def findings_from(matches):

    if not matches:
        return [NO_FINDINGS_TEXT]

    return [match["finding"] for match in matches]


def recommendations_from(matches):

    recommendations = []

    for match in matches:
        for item in match["recommendations"]:
            if item not in recommendations:
                recommendations.append(item)

    if not recommendations:
        return [NO_RECOMMENDATIONS_TEXT]

    return recommendations

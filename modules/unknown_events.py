"""A fill-in template for events that have no local definition."""

import json
from pathlib import Path

from modules.event_catalog import level_default_severity


TEMPLATE_FILE_NAME = "unknown_events_template.json"

_LEVEL_NUMBERS = {
    "Critical": 1,
    "Error": 2,
    "Warning": 3,
}


def build_unknown_template(report_events):
    """Definitions skeleton for every unknown (provider, Event ID).

    Same format as event_definitions.json. Fill in name, cause and solutions,
    then copy the entries into your custom database folder. Entries with an
    empty name or cause are ignored until they are completed. The fields
    starting with "_" are only hints and are ignored by the application.
    """

    seen = {}

    for event in report_events:

        analysis = event.get("Analysis") or {}

        if analysis.get("known", True):
            continue

        key = (event.get("EventID"), event.get("Source", ""))

        if key not in seen:
            message = " ".join(str(event.get("Message", "")).split())
            seen[key] = {
                "name": "",
                "sources": [key[1]],
                "cause": "",
                "severity": level_default_severity(
                    _LEVEL_NUMBERS.get(event.get("LevelName"))
                ),
                "solutions": [],
                "_times_seen": 0,
                "_level": event.get("LevelName", ""),
                "_example_message": message[:300],
            }

        seen[key]["_times_seen"] += 1

    template = {}

    for (event_id, _), definition in sorted(
        seen.items(),
        key=lambda item: (-item[1]["_times_seen"], str(item[0][0]))
    ):
        entry = template.setdefault(str(event_id), [])
        entry.append(definition)

    return {
        event_id: entries[0] if len(entries) == 1 else entries
        for event_id, entries in template.items()
    }


def write_unknown_template(report_events, output_dir):
    """Write the template file. Returns its path, or None if nothing to do."""

    template = build_unknown_template(report_events)

    if not template:
        return None

    path = Path(output_dir) / TEMPLATE_FILE_NAME
    path.parent.mkdir(parents=True, exist_ok=True)

    with open(path, "w", encoding="utf-8") as file:
        json.dump(template, file, indent=4, ensure_ascii=False)

    return path

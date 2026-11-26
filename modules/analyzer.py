import copy
import re

from modules.event_catalog import (
    find_event_definition,
    level_default_severity,
)
from database.error_code_lookup import get_error_info
from modules.internet_lookup import lookup_event
from modules.event_data import get_event_data_value


_HEX_START = re.compile(r"^0[xX][0-9a-fA-F]+")


def get_level_name(level):

    levels = {
        0: "Log Always",
        1: "Critical",
        2: "Error",
        3: "Warning",
        4: "Information",
        5: "Verbose"
    }

    return levels.get(
        level,
        "Unknown"
    )


def get_severity_text(score):

    if score >= 90:
        return "CRITICAL"

    elif score >= 70:
        return "HIGH"

    elif score >= 40:
        return "MEDIUM"

    return "LOW"


def _candidate_error_values(item):
    """Values of one Event Data item that may hold an error code."""

    value = get_event_data_value(item).strip()

    candidates = []

    if _HEX_START.match(value):
        candidates.append(value)

    # Bugcheck events can carry the stop code as a plain decimal number.
    name = (
        str(item.get("name", "")).casefold()
        if isinstance(item, dict)
        else ""
    )

    if name == "bugcheckcode" and value.isdigit():
        candidates.append(f"0x{int(value):08x}")

    return candidates


def find_error_codes(event):
    """Every known error code found in the event's data, in order.

    Returns a list of {"code", "description", "recommendation"}. Codes
    that are not in the error-code database are skipped.
    """

    found = []
    seen = set()

    for item in event.get("Data", []):

        for value in _candidate_error_values(item):

            info = get_error_info(
                value,
                event_id=event.get("EventID")
            )

            if info is None:
                continue

            code = value.split()[0].split("(")[0]

            if code.casefold() in seen:
                continue

            seen.add(code.casefold())

            found.append({
                "code": code,
                "description": info.get("description", ""),
                "recommendation": info.get("recommendation", ""),
            })

    return found


def analyze_event(event, online_lookup=None):

    event_id = event["EventID"]
    source = event.get("Source", "")

    if online_lookup is None:
        online_lookup = lookup_event(
            event_id,
            source
        )

    definition = find_event_definition(
        event_id,
        source
    )

    if definition is not None:

        # The databases are cached, so never hand out the cached lists.
        result = copy.deepcopy(definition)

        result["severity_text"] = (
            get_severity_text(
                result["severity"]
            )
        )

        result["known"] = True

    else:

        # No local definition: estimate the severity from the Windows
        # level so a Critical event is not shown as LOW.
        severity = level_default_severity(
            event.get("Level")
        )

        result = {
            "known": False,
            "name": "Unknown Event",
            "cause": (
                "No local definition is available; see the online "
                "explanation below."
            ),
            "severity": severity,
            "severity_text": get_severity_text(severity),
            "severity_basis": (
                "Windows event level; triage estimate, not diagnosis"
            ),
            "search_url": (
                online_lookup.get("url")
                or online_lookup.get("search_url", "")
            ),
            "solutions": [
                "Review the event data and nearby events.",
                "Use the Microsoft Learn reference below if one matched."
            ]
        }

    result["online_lookup"] = online_lookup

    error_codes = find_error_codes(event)

    if error_codes:

        result["error_codes"] = error_codes

        # First match, for reports and callers that show a single code.
        result["error_code"] = error_codes[0]["code"]
        result["error_description"] = error_codes[0]["description"]
        result["error_recommendation"] = (
            error_codes[0]["recommendation"]
        )

    return result

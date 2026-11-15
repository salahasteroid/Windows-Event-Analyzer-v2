from modules.database_loader import (
    load_event_database
)
from database.error_code_lookup import get_error_info
from modules.internet_lookup import lookup_event
from modules.event_data import get_event_data_value


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


def analyze_event(event, online_lookup=None):

    event_database = (
        load_event_database()
    )

    event_id = event["EventID"]

    error_code = None
    error_info = None
    if online_lookup is None:
        online_lookup = lookup_event(
            event_id,
            event["Source"]
        )

    for item in event.get("Data", []):
        item_value = get_event_data_value(item)

        if (
            item_value.startswith("0x")
        ):

            error_code = item_value

            error_info = get_error_info(
                error_code
            )

            break

    if str(event_id) in event_database:

        result = event_database[
            str(event_id)
        ].copy()

        result["severity_text"] = (
            get_severity_text(
                result["severity"]
            )
        )

        result["known"] = True

    else:

        result = {
            "known": False,
            "name": "Unknown Event",
            "cause": (
                "No local definition is available; see the online "
                "explanation below."
            ),
            "severity": 10,
            "severity_text": "LOW",
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

    if error_info:

        result["error_code"] = (
            error_code
        )

        result["error_description"] = (
            error_info.get(
                "description",
                ""
            )
        )

        result["error_recommendation"] = (
            error_info.get(
                "recommendation",
                ""
            )
        )

    return result
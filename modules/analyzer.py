from modules.database_loader import (
    load_event_database
)

try:
    from modules.error_code_lookup import (
        get_error_info
    )
except ImportError:

    def get_error_info(error_code):
        return None

try:
    from modules.internet_lookup import (
        lookup_event
    )
except ImportError:

    def lookup_event(
        event_id,
        source
    ):
        return {
            "search_url":
            f"https://www.google.com/search?q={source}+Event+ID+{event_id}"
        }


def get_level_name(level):

    levels = {
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


def analyze_event(event):

    event_database = (
        load_event_database()
    )

    event_id = event["EventID"]

    error_code = None
    error_info = None

    for item in event.get(
        "Data",
        []
    ):

        if (
            isinstance(item, str)
            and item.startswith("0x")
        ):

            error_code = item

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

        lookup = lookup_event(
            event_id,
            event["Source"]
        )

        result = {
            "known": False,
            "name": "Unknown Event",
            "cause": "No analysis available",
            "severity": 10,
            "severity_text": "LOW",
            "search_url": lookup[
                "search_url"
            ],
            "solutions": [
                "Review Event Viewer details",
                "Check Microsoft Learn",
                "Search EventID.net"
            ]
        }

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
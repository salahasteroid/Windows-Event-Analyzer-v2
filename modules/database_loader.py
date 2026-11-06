import json
from modules.paths import resource_path


def load_event_database():

    database_path = resource_path(
        "database",
        "event_definitions.json"
    )

    if not database_path.exists():
        print(
            f"Warning: {database_path} not found."
        )

        return {}

    try:

        with open(
            database_path,
            "r",
            encoding="utf-8"
        ) as file:

            return json.load(file)

    except Exception as ex:

        print(
            f"Database Error: {ex}"
        )

        return {}
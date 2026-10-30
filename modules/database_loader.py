import json
import os


def load_event_database():

    database_path = (
        "database/event_definitions.json"
    )

    if not os.path.exists(
        database_path
    ):

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
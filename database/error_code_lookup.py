import json
import os


def get_error_info(error_code):

    file_path = (
        "database/error_codes.json"
    )

    if not os.path.exists(
        file_path
    ):
        return None

    try:

        with open(
            file_path,
            "r",
            encoding="utf-8"
        ) as file:

            database = json.load(file)

        return database.get(
            error_code,
            None
        )

    except Exception:

        return None
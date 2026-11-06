import json
from modules.paths import resource_path


def get_error_info(error_code):

    file_path = resource_path(
        "database",
        "error_codes.json"
    )

    if not file_path.exists():
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
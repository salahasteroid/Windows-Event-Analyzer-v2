from modules.database_loader import (
    load_error_code_database,
    normalize_error_code,
)


def get_error_info(error_code, event_id=None):
    """Look up an error code (any hex spelling) in the error-code database.

    An entry may carry an "event_ids" list; such an entry is only returned
    for those Event IDs (for example bugcheck codes that only make sense in
    Event 1001).
    """

    code = normalize_error_code(error_code)

    if code is None:
        return None

    info = load_error_code_database().get(code)

    if info is None:
        return None

    allowed_events = info.get("event_ids")

    if allowed_events and event_id not in allowed_events:
        return None

    return info

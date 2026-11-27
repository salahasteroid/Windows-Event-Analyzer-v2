import json
import re
import threading

from modules.paths import get_custom_database_dir, resource_path


_cache = {}
_cache_lock = threading.Lock()

_HEX_CODE = re.compile(r"0[xX]([0-9a-fA-F]{1,16})(?=$|[\s(,;])")


def normalize_error_code(value):
    """Return a code like 0x80070005 in a single canonical form.

    Accepts upper/lower case hex, short forms (0x5) and values followed by
    extra text such as "0x00000133 (0x1, 0x2)". Returns None for anything
    that is not a 32-bit hex code.
    """

    match = _HEX_CODE.match(str(value).strip())

    if match is None:
        return None

    number = int(match.group(1), 16)

    if number > 0xFFFFFFFF:
        return None

    return f"0x{number:08x}"


def _read_json_file(path, label):

    try:

        with open(
            path,
            "r",
            encoding="utf-8"
        ) as file:

            data = json.load(file)

    except Exception as ex:

        print(
            f"Database Error ({label}): {ex}"
        )

        return None

    if not isinstance(data, dict):

        print(
            f"Database Error ({label}): expected a JSON object."
        )

        return None

    return data


def _read_json(file_name):
    """The built-in database file, or {} if it cannot be read."""

    database_path = resource_path(
        "database",
        file_name
    )

    if not database_path.exists():
        print(
            f"Warning: {database_path} not found."
        )

        return {}

    return _read_json_file(database_path, file_name) or {}


def _read_custom_json(file_name):
    """The user's own version of a database file, or None."""

    folder = get_custom_database_dir()

    if folder is None:
        return None

    path = folder / file_name

    if not path.exists():
        return None

    data = _read_json_file(path, f"custom {file_name}")

    if data is not None:
        print(f"Using custom database file: {path}")

    return data


def _is_number(value):

    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _valid_definition(definition):

    return (
        isinstance(definition, dict)
        and isinstance(definition.get("name"), str)
        and definition["name"].strip() != ""
        and isinstance(definition.get("cause"), str)
        and definition["cause"].strip() != ""
        and _is_number(definition.get("severity"))
        and isinstance(definition.get("solutions"), list)
        and (
            definition.get("sources") is None
            or isinstance(definition.get("sources"), list)
        )
    )


def _clean_event_definitions(database):
    """Keep only complete definitions so a typo cannot break an analysis."""

    cleaned = {}

    for event_id, entry in database.items():

        entries = entry if isinstance(entry, list) else [entry]
        valid = [item for item in entries if _valid_definition(item)]

        if len(valid) != len(entries):
            print(
                f"Warning: ignoring incomplete definition for Event ID "
                f"{event_id} (needs a name, a cause, severity and solutions)."
            )

        if not str(event_id).isdigit() or not valid:
            continue

        cleaned[str(event_id)] = (
            valid if isinstance(entry, list) else valid[0]
        )

    return cleaned


def _normalize_error_codes(database):

    normalized = {}

    for code, info in database.items():

        key = normalize_error_code(code)

        if (
            key is None
            or not isinstance(info, dict)
            or not isinstance(info.get("description"), str)
        ):
            print(
                f"Warning: ignoring invalid error code entry {code!r}."
            )
            continue

        normalized[key] = info

    return normalized


def _merge_rules(builtin, custom):
    """Custom rules replace built-in rules with the same id and add new
    ones. A custom rule with "disabled": true removes that rule."""

    merged = dict(builtin)

    rules = [
        rule for rule in builtin.get("rules", [])
        if isinstance(rule, dict)
    ]

    for rule in custom.get("rules", []):

        if not isinstance(rule, dict):
            continue

        position = next(
            (
                index for index, existing in enumerate(rules)
                if existing.get("id") == rule.get("id")
            ),
            None
        )

        if rule.get("disabled") is True:

            if position is not None:
                del rules[position]

        elif position is not None:
            rules[position] = rule

        else:
            rules.append(rule)

    merged["rules"] = rules

    if isinstance(custom.get("health"), dict):
        merged["health"] = {
            **(builtin.get("health") or {}),
            **custom["health"],
        }

    return merged


def _load_cached(name, loader):

    with _cache_lock:

        if name not in _cache:
            _cache[name] = loader()

        return _cache[name]


def load_event_database():
    """Event definitions keyed by Event ID. Loaded once and cached.

    Entries in the custom database folder replace built-in entries with
    the same Event ID.
    """

    def load():

        database = dict(_read_json("event_definitions.json"))

        custom = _read_custom_json("event_definitions.json")

        if custom:
            database.update(custom)

        return _clean_event_definitions(database)

    return _load_cached("events", load)


def load_error_code_database():
    """Error codes keyed by normalized code (0x%08x). Loaded once."""

    def load():

        database = _normalize_error_codes(_read_json("error_codes.json"))

        custom = _read_custom_json("error_codes.json")

        if custom:
            database.update(_normalize_error_codes(custom))

        return database

    return _load_cached("error_codes", load)


def load_rules_database():
    """Correlation rules and health-score settings. Loaded once."""

    def load():

        database = _read_json("rules.json")

        custom = _read_custom_json("rules.json")

        if custom:
            database = _merge_rules(database, custom)

        return database

    return _load_cached("rules", load)


def clear_database_cache():
    """Forget cached databases so the next call re-reads the files."""

    with _cache_lock:
        _cache.clear()

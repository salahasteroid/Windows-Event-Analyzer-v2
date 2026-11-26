from modules.database_loader import load_event_database


# Used when an event has no local definition: a rough severity taken from
# the Windows event level (1 Critical, 2 Error, 3 Warning).
LEVEL_DEFAULT_SEVERITY = {
    1: 75,
    2: 45,
    3: 20,
}


def level_default_severity(level):

    return LEVEL_DEFAULT_SEVERITY.get(level, 10)


def _definitions_for(event_id):

    database = load_event_database()

    entry = database.get(str(event_id))

    if entry is None:
        return []

    if isinstance(entry, dict):
        return [entry]

    if isinstance(entry, list):
        return [item for item in entry if isinstance(item, dict)]

    return []


def find_event_definition(event_id, source=None):
    """Return the definition for an Event ID, honouring its providers.

    Event IDs are only unique per provider (ID 19 is a Windows Update
    success and also a WHEA hardware error), so a definition that lists
    "sources" only matches events from one of those providers. A definition
    without "sources" matches any provider. A provider-specific match is
    preferred over a generic one.
    """

    source_key = str(source or "").casefold()

    generic = None

    for definition in _definitions_for(event_id):

        sources = definition.get("sources")

        if not sources:

            if generic is None:
                generic = definition

            continue

        if source_key in {str(item).casefold() for item in sources}:
            return definition

    return generic

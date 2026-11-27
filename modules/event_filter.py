"""Narrow a collection to the events you care about before analysis."""

import re

from modules.event_data import get_event_data_value


def split_list(value):
    """"a, b; c" -> ["a", "b", "c"]; lists pass through; None -> []"""

    if value is None:
        return []

    if isinstance(value, str):
        value = re.split(r"[,;\n]+", value)

    return [str(item).strip() for item in value if str(item).strip()]


def parse_event_ids(value):
    """"41, 6008, 7000-7040" -> frozenset of ints. Empty -> empty set."""

    if isinstance(value, (set, frozenset, list, tuple)) and all(
        isinstance(item, int) for item in value
    ):
        return frozenset(value)

    event_ids = set()

    for part in split_list(value):

        match = re.fullmatch(r"(\d+)(?:\s*-\s*(\d+))?", part)

        if match is None:
            raise ValueError(
                f"'{part}' is not an Event ID or a range like 7000-7040."
            )

        first = int(match.group(1))
        last = int(match.group(2) or first)

        if last < first or last - first > 100000:
            raise ValueError(f"'{part}' is not a valid Event ID range.")

        event_ids.update(range(first, last + 1))

    return frozenset(event_ids)


def _haystack(event):

    parts = [str(event.get("Source", "")), str(event.get("Message", ""))]
    parts.extend(get_event_data_value(item) for item in event.get("Data", []))

    return "\n".join(parts).casefold()


def filter_events(
    events,
    event_ids=None,
    exclude_event_ids=None,
    sources=None,
    keywords=None
):
    """Keep events that match every filter that is given.

    - event_ids: only these Event IDs (see parse_event_ids)
    - exclude_event_ids: drop these Event IDs
    - sources: provider name contains any of these words (any case)
    - keywords: Source, message or event data contains any of these words
    """

    include = parse_event_ids(event_ids) if event_ids else frozenset()
    exclude = (
        parse_event_ids(exclude_event_ids)
        if exclude_event_ids
        else frozenset()
    )
    source_terms = [term.casefold() for term in split_list(sources)]
    keyword_terms = [term.casefold() for term in split_list(keywords)]

    if not (include or exclude or source_terms or keyword_terms):
        return list(events)

    selected = []

    for event in events:

        event_id = event.get("EventID")

        if include and event_id not in include:
            continue

        if event_id in exclude:
            continue

        if source_terms and not any(
            term in str(event.get("Source", "")).casefold()
            for term in source_terms
        ):
            continue

        if keyword_terms:

            text = _haystack(event)

            if not any(term in text for term in keyword_terms):
                continue

        selected.append(event)

    return selected

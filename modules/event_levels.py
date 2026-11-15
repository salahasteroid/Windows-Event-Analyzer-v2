EVENT_LEVEL_NAMES = {
    0: "Log Always / Other",
    1: "Critical",
    2: "Error",
    3: "Warning",
    4: "Information",
    5: "Verbose",
}

DEFAULT_EVENT_LEVELS = (1, 2, 3)


def normalize_event_levels(levels=None):
    if levels is None:
        return DEFAULT_EVENT_LEVELS

    normalized = tuple(sorted(set(int(level) for level in levels)))
    if not normalized:
        raise ValueError("Select at least one event level.")

    invalid_levels = set(normalized) - set(EVENT_LEVEL_NAMES)
    if invalid_levels:
        raise ValueError(
            "Unsupported Windows event level: "
            + ", ".join(str(level) for level in sorted(invalid_levels))
        )

    return normalized

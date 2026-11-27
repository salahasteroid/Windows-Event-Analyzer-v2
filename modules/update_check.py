"""Optional check for a newer release on GitHub.

Only runs when the user asks for it (the --check-update option). Sends a
single anonymous request to the GitHub releases API; nothing about the
computer or its logs is transmitted.
"""

import json
import re
import urllib.request

from modules.version import __version__

RELEASES_URL = (
    "https://api.github.com/repos/salahasteroid/"
    "Windows-Event-Analyzer-v2/releases/latest"
)


def parse_version(text):
    """'v2.10.1' -> (2, 10, 1); None when it does not look like a version."""

    match = re.match(r"^\s*v?(\d+(?:\.\d+){0,3})", str(text))

    if match is None:
        return None

    return tuple(int(part) for part in match.group(1).split("."))


def is_newer(latest, current=__version__):

    latest_parts = parse_version(latest)
    current_parts = parse_version(current)

    if latest_parts is None or current_parts is None:
        return False

    width = max(len(latest_parts), len(current_parts))
    pad = lambda parts: parts + (0,) * (width - len(parts))

    return pad(latest_parts) > pad(current_parts)


def check_for_update(fetch=None, timeout=10):
    """Returns {"current", "latest", "newer", "url"} or {"error": text}."""

    def default_fetch():
        request = urllib.request.Request(
            RELEASES_URL,
            headers={
                "Accept": "application/vnd.github+json",
                "User-Agent": f"WindowsEventAnalyzer/{__version__}",
            },
        )
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.load(response)

    try:
        release = (fetch or default_fetch)()
        tag = release.get("tag_name", "")
    except Exception as error:
        return {"error": str(error)}

    if parse_version(tag) is None:
        return {"error": "No release version was found."}

    return {
        "current": __version__,
        "latest": tag,
        "newer": is_newer(tag),
        "url": release.get("html_url", ""),
    }

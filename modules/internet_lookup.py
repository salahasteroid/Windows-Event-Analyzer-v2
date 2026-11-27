import json
import os
import re
import threading
from collections import Counter
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from datetime import datetime, timedelta, timezone
from html.parser import HTMLParser
from pathlib import Path
from urllib.error import URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import Request, urlopen

from modules.paths import get_user_data_dir


_SEARCH_API = "https://learn.microsoft.com/api/search"
_SEARCH_PAGE = "https://learn.microsoft.com/en-us/search/"
_MAX_SUMMARY_LENGTH = 900
_MAX_LOOKUPS_PER_RUN = 20
_MAX_WORKERS = 8
_TIMEOUT_SECONDS = 3
CACHE_TTL = timedelta(days=30)


class _ArticleSectionParser(HTMLParser):

    def __init__(self):
        super().__init__()
        self.in_main = False
        self.skip_depth = 0
        self.heading = ""
        self.heading_text = []
        self.reading_heading = False
        self.block_tag = None
        self.block_text = []
        self.sections = {}
        self.description = ""

    def handle_starttag(self, tag, attrs):
        if tag == "meta":
            metadata = dict(attrs)
            if metadata.get("name", "").lower() == "description":
                self.description = metadata.get("content", "")

        if tag == "main":
            self.in_main = True

        if not self.in_main:
            return

        if tag in ("nav", "script", "style"):
            self.skip_depth += 1
            return

        if self.skip_depth:
            return

        if tag == "h2":
            self._finish_block()
            self.heading = ""
            self.heading_text = []
            self.reading_heading = True
        elif tag in ("p", "li") and self.heading:
            self.block_tag = tag
            self.block_text = []

    def handle_endtag(self, tag):
        if not self.in_main:
            return

        if tag in ("nav", "script", "style") and self.skip_depth:
            self.skip_depth -= 1
            return

        if self.skip_depth:
            return

        if tag == "h2" and self.reading_heading:
            self.heading = " ".join(
                "".join(self.heading_text).split()
            ).lower()
            self.reading_heading = False
        elif tag == self.block_tag:
            self._finish_block()

        if tag == "main":
            self.in_main = False

    def handle_data(self, data):
        if not self.in_main or self.skip_depth:
            return

        if self.reading_heading:
            self.heading_text.append(data)
        elif self.block_tag:
            self.block_text.append(data)

    def _finish_block(self):
        if self.block_tag:
            text = " ".join("".join(self.block_text).split())
            if text:
                self.sections.setdefault(self.heading, []).append(text)
        self.block_tag = None
        self.block_text = []


def _build_query(event_id, source):
    return f'"{source}" "{event_id}"'


def get_search_url(event_id, source):
    query = _build_query(event_id, source)
    return f"{_SEARCH_PAGE}?{urlencode({'terms': query})}"


def _is_event_match(result, event_id):
    title = str(result.get("title", ""))
    return re.search(
        rf"\bevent\s+(?:id\s+)?0*{re.escape(str(event_id))}\b",
        title,
        re.IGNORECASE
    ) is not None


def _get_official_url(value):
    if not isinstance(value, str):
        return ""

    try:
        parsed_url = urlsplit(value)
    except ValueError:
        return ""

    if (
        parsed_url.scheme.lower() == "https"
        and parsed_url.hostname == "learn.microsoft.com"
    ):
        return value

    return ""


def _read_article_guidance(url):
    request = Request(
        url,
        headers={"User-Agent": "WindowsEventAnalyzer/1.0"}
    )

    try:
        with urlopen(request, timeout=_TIMEOUT_SECONDS) as response:
            article = response.read(2_000_000).decode(
                "utf-8",
                errors="replace"
            )
    except (OSError, URLError, TimeoutError, ValueError) as error:
        return {
            "article_error": str(error)
        }

    parser = _ArticleSectionParser()
    parser.feed(article)

    guidance = {
        "article_description": parser.description.strip()
    }
    for key, headings in (
        ("cause", ("cause", "reason")),
        ("resolution", ("resolution", "solution", "workaround"))
    ):
        blocks = [
            block
            for heading in headings
            for block in parser.sections.get(heading, [])
        ]
        if blocks:
            guidance[key] = " ".join(blocks)

    return guidance


def lookup_event(event_id, source):
    query = _build_query(event_id, source)
    search_url = get_search_url(event_id, source)
    api_url = (
        f"{_SEARCH_API}?"
        f"{urlencode({'search': query, 'locale': 'en-us', '$top': 5})}"
    )
    request = Request(
        api_url,
        headers={"User-Agent": "WindowsEventAnalyzer/1.0"}
    )

    try:
        with urlopen(request, timeout=_TIMEOUT_SECONDS) as response:
            payload = json.load(response)
    except (OSError, URLError, TimeoutError, ValueError) as error:
        return {
            "status": "error",
            "error": str(error),
            "search_url": search_url
        }

    if not isinstance(payload, dict):
        return {
            "status": "error",
            "error": "Microsoft Learn returned an unexpected response.",
            "search_url": search_url
        }

    results = payload.get("results", [])
    if not isinstance(results, list):
        results = []

    matching_results = [
        result
        for result in results
        if isinstance(result, dict)
        and _is_event_match(result, event_id)
        and _get_official_url(result.get("url"))
    ]

    if not matching_results:
        return {
            "status": "no_match",
            "search_url": search_url
        }

    result = matching_results[0]
    summary = str(result.get("description", "")).strip()
    summary = re.split(
        r"\s+Summarize this article for me\b",
        summary,
        maxsplit=1,
        flags=re.IGNORECASE
    )[0].strip()
    summary = re.split(
        r"\s+In this article\b",
        summary,
        maxsplit=1,
        flags=re.IGNORECASE
    )[0].strip()

    if len(summary) > _MAX_SUMMARY_LENGTH:
        summary = summary[:_MAX_SUMMARY_LENGTH].rsplit(" ", 1)[0] + "..."

    article_url = _get_official_url(result.get("url"))
    article_guidance = _read_article_guidance(article_url)
    if article_guidance.get("article_description"):
        summary = article_guidance["article_description"]

    return {
        "status": "found",
        "title": str(result.get("title", "")).strip(),
        "summary": summary,
        "url": article_url,
        "search_url": search_url,
        "provider": "Microsoft Learn",
        **article_guidance
    }


def get_cache_path():

    return get_user_data_dir() / "cache" / "learn_lookup.json"


def load_lookup_cache(path=None):
    """Saved Microsoft Learn answers; a missing or damaged file gives {}."""

    try:
        with open(path or get_cache_path(), "r", encoding="utf-8") as file:
            data = json.load(file)
    except (OSError, ValueError):
        return {}

    return data if isinstance(data, dict) else {}


def save_lookup_cache(cache, path=None):
    """Write the cache. Failure is ignored: the cache is only a speed-up."""

    path = Path(path or get_cache_path())
    temporary_path = path.with_suffix(".tmp")

    try:
        path.parent.mkdir(parents=True, exist_ok=True)

        with open(temporary_path, "w", encoding="utf-8") as file:
            json.dump(cache, file)

        os.replace(temporary_path, path)

    except OSError:
        return False

    return True


def _cache_key(event_id, source):

    return f"{event_id}|{str(source).casefold()}"


def lookup_event_cached(event_id, source, cache, now=None):
    """lookup_event with a 30-day on-disk memory.

    Found and no-match answers are reused while fresh. If Microsoft Learn
    cannot be reached, an older saved answer is still used, so the analysis
    keeps working offline.
    """

    now = now or datetime.now(timezone.utc)
    key = _cache_key(event_id, source)
    entry = cache.get(key)
    saved_result = None
    fresh = False

    if isinstance(entry, dict) and isinstance(entry.get("result"), dict):

        saved_result = entry["result"]

        try:
            saved_at = datetime.fromisoformat(entry["time"])
            fresh = now - saved_at < CACHE_TTL
        except (KeyError, TypeError, ValueError):
            fresh = False

    if fresh:
        return {**saved_result, "from_cache": True}

    result = lookup_event(event_id, source)

    if result.get("status") in ("found", "no_match"):
        cache[key] = {"time": now.isoformat(), "result": result}
        return result

    if saved_result is not None:
        return {**saved_result, "from_cache": True, "stale": True}

    return result


def lookup_events(events, cancellation_event=None, use_cache=True):
    if cancellation_event is not None and cancellation_event.is_set():
        return {}

    event_counts = Counter(
        (event["EventID"], event["Source"])
        for event in events
    )

    if not event_counts:
        return {}

    ordered_keys = sorted(
        event_counts,
        key=lambda key: (
            -event_counts[key],
            str(key[0]),
            key[1]
        )
    )
    selected_keys = ordered_keys[:_MAX_LOOKUPS_PER_RUN]
    results = {
        key: {
            "status": "skipped",
            "search_url": get_search_url(*key)
        }
        for key in ordered_keys[_MAX_LOOKUPS_PER_RUN:]
    }

    cache = load_lookup_cache() if use_cache else None

    executor = ThreadPoolExecutor(
        max_workers=min(_MAX_WORKERS, len(selected_keys))
    )

    def lookup(event_id, source):
        if cache is None:
            return lookup_event(event_id, source)
        return lookup_event_cached(event_id, source, cache)

    pending = {
        executor.submit(lookup, event_id, source): (
            event_id,
            source
        )
        for event_id, source in selected_keys
    }

    try:
        while pending:
            if (
                cancellation_event is not None
                and cancellation_event.is_set()
            ):
                break

            completed, _ = wait(
                pending,
                timeout=0.1,
                return_when=FIRST_COMPLETED,
            )
            for future in completed:
                results[pending.pop(future)] = future.result()
    finally:
        cancelled = (
            cancellation_event is not None
            and cancellation_event.is_set()
        )
        if cancelled:
            for future in pending:
                future.cancel()
        executor.shutdown(wait=not cancelled)

    if cache is not None and not cancelled:
        save_lookup_cache(cache)

    return results

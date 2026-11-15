import json
import re
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from html.parser import HTMLParser
from urllib.error import URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import Request, urlopen


_SEARCH_API = "https://learn.microsoft.com/api/search"
_SEARCH_PAGE = "https://learn.microsoft.com/en-us/search/"
_MAX_SUMMARY_LENGTH = 900
_MAX_LOOKUPS_PER_RUN = 20
_MAX_WORKERS = 8
_TIMEOUT_SECONDS = 3


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


def lookup_events(events):
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

    with ThreadPoolExecutor(
        max_workers=min(_MAX_WORKERS, len(selected_keys))
    ) as executor:
        pending = {
            executor.submit(lookup_event, event_id, source): (
                event_id,
                source
            )
            for event_id, source in selected_keys
        }

        for future in as_completed(pending):
            results[pending[future]] = future.result()

    return results

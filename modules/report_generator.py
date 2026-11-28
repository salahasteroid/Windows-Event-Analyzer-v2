from html import escape
from pathlib import Path
from urllib.parse import urlsplit

from modules.event_data import format_event_data_item
from modules.paths import get_reports_dir
from modules.time_range import parse_event_time

SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW")

CONFIDENCE_LABELS = {
    "high": "Matches this event",
    "medium": "Related - check it fits",
    "low": "Possibly related",
}

REPORT_STYLE = """
:root { color-scheme: light dark; --bg:#f6f7f9; --card:#fff; --fg:#1f2328;
  --muted:#59636e; --line:#d8dee4; --critical:#b42318; --high:#c4570c;
  --medium:#a16207; --low:#2f6f3e; --link:#0a58ca; --soft:#f1f3f5; }
@media (prefers-color-scheme: dark) { :root { --bg:#14161a; --card:#1d2025;
  --fg:#e6e8eb; --muted:#9aa4af; --line:#343a42; --critical:#ff8a80;
  --high:#ffb074; --medium:#f2cc60; --low:#7fd18b; --link:#7db4ff;
  --soft:#262a31; } }
* { box-sizing:border-box; }
body { font-family:"Segoe UI",Arial,sans-serif; margin:0; padding:24px 16px;
  background:var(--bg); color:var(--fg); line-height:1.5; }
main { max-width:960px; margin:0 auto; }
h1 { margin:0 0 4px; font-size:1.6rem; }
h2 { font-size:1.15rem; margin:28px 0 10px; }
.sub { color:var(--muted); margin:0 0 18px; }
a { color:var(--link); }
.chips { display:flex; flex-wrap:wrap; gap:8px; margin:12px 0; }
.chip { border:1px solid var(--line); background:var(--card); border-radius:999px;
  padding:4px 12px; font-size:.9rem; }
.start { background:var(--card); border:1px solid var(--line); border-radius:10px;
  padding:12px 18px; }
.start ol { margin:6px 0 0; padding-left:22px; }
.card { background:var(--card); border:1px solid var(--line);
  border-left:6px solid var(--line); border-radius:10px; margin:14px 0;
  padding:14px 18px; }
.card.sev-critical { border-left-color:var(--critical); }
.card.sev-high { border-left-color:var(--high); }
.card.sev-medium { border-left-color:var(--medium); }
.card.sev-low { border-left-color:var(--low); }
.card header { display:flex; flex-wrap:wrap; align-items:center; gap:8px 12px; }
.card h3 { margin:0; font-size:1.1rem; flex:1 1 280px; }
.badge { font-size:.75rem; font-weight:700; letter-spacing:.04em; color:#fff;
  padding:2px 10px; border-radius:999px; background:var(--muted); }
.badge.critical { background:var(--critical); } .badge.high { background:var(--high); }
.badge.medium { background:var(--medium); } .badge.low { background:var(--low); }
@media (prefers-color-scheme: dark) { .badge { color:#14161a; } }
.meta { color:var(--muted); font-size:.88rem; margin:4px 0 0; }
.card h4 { margin:14px 0 4px; font-size:.82rem; text-transform:uppercase;
  letter-spacing:.05em; color:var(--muted); }
.card p { margin:4px 0; }
.card ol, .card ul { margin:4px 0; padding-left:22px; }
.card li { margin:3px 0; }
.learn { background:var(--soft); border-radius:8px; padding:10px 14px; }
.note { color:var(--muted); font-size:.88rem; }
.pill { display:inline-block; font-size:.75rem; border:1px solid var(--line);
  border-radius:999px; padding:1px 8px; margin-left:6px; }
details { margin-top:12px; } summary { cursor:pointer; color:var(--muted); }
table { border-collapse:collapse; margin:8px 0; }
th, td { border:1px solid var(--line); padding:4px 10px; text-align:left;
  vertical-align:top; }
pre { white-space:pre-wrap; word-break:break-word; background:var(--soft);
  padding:8px 10px; border-radius:6px; margin:6px 0; }
@media print { body { background:#fff; padding:0; } .card { break-inside:avoid; }
  details::details-content { content-visibility:visible; } }
"""


def _text(value):

    return escape(str(value), quote=True)


def _safe_link(url, label):

    if not isinstance(url, str) or not url:
        return ""

    try:
        parsed_url = urlsplit(url)
    except ValueError:
        return ""

    if parsed_url.scheme.lower() not in ("http", "https") or not parsed_url.netloc:
        return ""

    return (
        f'<a href="{_text(url)}" target="_blank" rel="noopener noreferrer">'
        f"{_text(label)}</a>"
    )


def _severity_class(severity_text):

    severity = str(severity_text)

    return severity.lower() if severity in SEVERITY_ORDER else "low"


def _moment(event):

    return parse_event_time(event.get("Time", ""))


def group_for_report(events):
    """One entry per (provider, Event ID, level): the problems, worst first.

    Each group is {"events", "latest", "count", "first_time", "last_time"}.
    """

    groups = {}

    for event in events:

        key = (
            str(event.get("Source", "")).casefold(),
            event.get("EventID"),
            event.get("LevelName", ""),
        )
        groups.setdefault(key, []).append(event)

    result = []

    for members in groups.values():

        stamped = [
            (moment, event)
            for event in members
            if (moment := _moment(event)) is not None
        ]
        stamped.sort(key=lambda item: item[0])

        latest = stamped[-1][1] if stamped else members[0]

        result.append({
            "events": members,
            "latest": latest,
            "count": len(members),
            "first_time": stamped[0][1].get("Time", "") if stamped else "",
            "last_time": stamped[-1][1].get("Time", "") if stamped else "",
        })

    def sort_key(group):
        analysis = group["latest"].get("Analysis") or {}
        severity = analysis.get("severity")
        severity = severity if isinstance(severity, (int, float)) else 0
        return (-severity, -group["count"], str(group["latest"].get("EventID")))

    result.sort(key=sort_key)

    return result


def _online_html(online_lookup):

    status = online_lookup.get("status")

    if status == "found":

        confidence = online_lookup.get("confidence", "medium")
        label = CONFIDENCE_LABELS.get(confidence, CONFIDENCE_LABELS["medium"])
        note = online_lookup.get("confidence_note") or ""

        title = online_lookup.get("title", "")
        link = _safe_link(online_lookup.get("url"), title) or _text(title)

        html = (
            f"<p><strong>{link}</strong>"
            f'<span class="pill">{_text(label)}</span></p>'
        )

        if online_lookup.get("summary"):
            html += f"<p>{_text(online_lookup['summary'])}</p>"

        if online_lookup.get("cause"):
            html += (
                "<p><strong>Main reason:</strong> "
                f"{_text(online_lookup['cause'])}</p>"
            )

        if online_lookup.get("resolution"):
            html += (
                "<p><strong>Microsoft's solution:</strong> "
                f"{_text(online_lookup['resolution'])}</p>"
            )
        elif online_lookup.get("article_error"):
            html += (
                '<p class="note">Could not load the full article: '
                f"{_text(online_lookup['article_error'])}</p>"
            )

        if note:
            html += f'<p class="note">{_text(note)}</p>'

        alternatives = [
            _safe_link(item.get("url"), item.get("title", ""))
            for item in online_lookup.get("alternatives", [])
            if isinstance(item, dict)
        ]
        alternatives = [item for item in alternatives if item]

        if alternatives:
            html += (
                '<p class="note">Other articles: '
                + " &middot; ".join(alternatives)
                + "</p>"
            )

        return html

    if status == "error":
        return (
            '<p class="note">Could not reach Microsoft Learn (no internet '
            "connection, or it is blocked). The advice above comes from the "
            "built-in database and still applies.</p>"
            f'<p class="note">Technical reason: '
            f"{_text(online_lookup.get('error', ''))}</p>"
        )

    if status == "no_match":
        return (
            '<p class="note">No Microsoft Learn article was found for this '
            "exact event.</p>"
        )

    if status == "skipped":
        return (
            '<p class="note">Online lookup was skipped to keep the analysis '
            "fast.</p>"
        )

    return '<p class="note">No online lookup was performed.</p>'


def _error_codes_html(analysis):

    entries = analysis.get("error_codes")

    if not entries and analysis.get("error_code"):
        entries = [{
            "code": analysis.get("error_code"),
            "description": analysis.get("error_description", ""),
        }]

    if not entries:
        return ""

    rows = "".join(
        f"<tr><td>{_text(entry.get('code', ''))}</td>"
        f"<td>{_text(entry.get('description', ''))}</td></tr>"
        for entry in entries
    )

    return (
        "<h4>Error codes found</h4>"
        f"<table><tr><th>Code</th><th>Meaning</th></tr>{rows}</table>"
    )


def _details_html(event, analysis):

    parts = []

    message = event.get("Message", "")

    if message:
        parts.append(f"<h4>Message from Windows</h4><pre>{_text(message)}</pre>")

    parts.append(_error_codes_html(analysis))

    event_data = event.get("Data", [])

    if event_data:
        items = "".join(
            f"<li>{_text(format_event_data_item(item, index))}</li>"
            for index, item in enumerate(event_data, start=1)
        )
        parts.append(f"<h4>Event data</h4><ul>{items}</ul>")

        if not message:
            parts.append(
                '<p class="note">Windows did not provide a plain-language '
                "message; field meanings depend on the Event ID and source."
                "</p>"
            )

    facts = [
        ("Computer", event.get("Computer", "")),
        ("Log", event.get("Channel", "")),
        ("Level", event.get("LevelName", "")),
        ("Time (latest)", event.get("Time", "")),
    ]
    rows = "".join(
        f"<tr><th>{_text(name)}</th><td>{_text(value)}</td></tr>"
        for name, value in facts
        if value
    )
    parts.append(f"<h4>Event</h4><table>{rows}</table>")

    return "".join(parts)


def _card_html(group, number):

    event = group["latest"]
    analysis = event.get("Analysis") or {}
    severity = str(analysis.get("severity_text", "LOW"))
    css = _severity_class(severity)
    known = analysis.get("known", True)

    name = analysis.get("name") or "Unknown event"

    if not known:
        name = f"Unknown event ({event.get('Source', '')} {event.get('EventID', '')})"

    count = group["count"]
    occurrence = "once" if count == 1 else f"{count} times"
    when = ""

    if count > 1 and group["first_time"] and group["last_time"]:
        when = f" · first {group['first_time']} · last {group['last_time']}"
    elif group["last_time"]:
        when = f" · {group['last_time']}"

    solutions = analysis.get("solutions") or []
    solutions_html = (
        "<h4>What to do</h4><ol>"
        + "".join(f"<li>{_text(item)}</li>" for item in solutions)
        + "</ol>"
        if solutions else ""
    )

    online_lookup = analysis.get("online_lookup") or {}
    reference = _safe_link(
        online_lookup.get("search_url") or analysis.get("search_url"),
        "Search Microsoft Learn yourself",
    )

    insights = analysis.get("insights") or []
    insights_html = (
        "<h4>What this event says</h4><ul>"
        + "".join(f"<li>{_text(item)}</li>" for item in insights)
        + "</ul>"
        if insights else ""
    )

    basis = analysis.get("severity_basis")
    basis_html = (
        f'<p class="note">Severity: {_text(basis)}.</p>' if basis else ""
    )

    return f"""
<article class="card sev-{css}" id="problem-{number}">
  <header>
    <span class="badge {css}">{_text(severity)}</span>
    <h3>{_text(name)}</h3>
  </header>
  <p class="meta">Event {_text(event.get('EventID', ''))} ·
    {_text(event.get('Source', ''))} · {_text(event.get('LevelName', ''))} ·
    seen {occurrence}{_text(when)}</p>
  <h4>What it means</h4>
  <p>{_text(analysis.get('cause', ''))}</p>
  {basis_html}
  {insights_html}
  {solutions_html}
  <h4>What Microsoft says</h4>
  <div class="learn">{_online_html(online_lookup)}
    <p class="note">{reference}</p></div>
  <details><summary>Technical details (latest occurrence)</summary>
  {_details_html(event, analysis)}</details>
</article>
"""


def _overview_html(groups, total):

    counts = {name: 0 for name in SEVERITY_ORDER}

    for group in groups:
        analysis = group["latest"].get("Analysis") or {}
        counts[_severity_class(analysis.get("severity_text")).upper()] += group["count"]

    chips = "".join(
        f'<span class="chip"><strong>{counts[name]}</strong> {name.title()}</span>'
        for name in SEVERITY_ORDER
        if counts[name]
    )

    urgent = [
        (number, group) for number, group in enumerate(groups, start=1)
        if _severity_class(
            (group["latest"].get("Analysis") or {}).get("severity_text")
        ) in ("critical", "high", "medium")
    ][:3]

    if urgent:
        items = "".join(
            f'<li><a href="#problem-{number}">'
            f"{_text((group['latest'].get('Analysis') or {}).get('name') or 'Unknown event')}"
            f"</a> &mdash; Event {_text(group['latest'].get('EventID', ''))}, "
            f"{group['count']}&times;</li>"
            for number, group in urgent
        )
        start = (
            '<div class="start"><strong>Start here</strong>'
            f"<ol>{items}</ol></div>"
        )
    else:
        start = (
            '<div class="start"><strong>No urgent problems found.</strong> '
            "The events below are low severity.</div>"
        )

    return (
        f'<p class="sub">{total} event(s) in {len(groups)} kind(s) of problem, '
        "worst first.</p>"
        f'<div class="chips">{chips}</div>{start}'
    )


def generate_html_report(events, output_dir=None):

    output_dir = (
        get_reports_dir()
        if output_dir is None
        else Path(output_dir)
    )
    output_dir.mkdir(parents=True, exist_ok=True)

    groups = group_for_report(events)

    if groups:
        body = _overview_html(groups, len(events)) + "<h2>Problems</h2>" + "".join(
            _card_html(group, number)
            for number, group in enumerate(groups, start=1)
        )
    else:
        body = '<p class="sub">No events matched the selected filters.</p>'

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Windows Event Analyzer Report</title>
<style>{REPORT_STYLE}</style>
</head>
<body>
<main>
<h1>Windows Event Analyzer Report</h1>
{body}
</main>
</body>
</html>
"""

    with open(
        output_dir / "event_report.html",
        "w",
        encoding="utf-8"
    ) as file:

        file.write(html)

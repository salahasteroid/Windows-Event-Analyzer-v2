from html import escape
from collections import Counter
from pathlib import Path

from modules.dashboard_charts import (
    SEVERITY_ORDER,
    horizontal_bars_svg,
    score_band,
    score_bar_svg,
    severity_bars_svg,
    timeline_svg,
)
from modules.paths import get_reports_dir


def _text(value):

    return escape(str(value), quote=True)


def _breakdown_html(score_breakdown):
    """List of what lowered the health score."""

    if not score_breakdown:
        return ""

    items = []

    for item in score_breakdown.get("events", [])[:10]:
        items.append(
            f"<li>{_text(item['source'])} Event "
            f"{_text(item['event_id'])} "
            f"(x{_text(item['count'])}, severity "
            f"{_text(item['severity'])}) : "
            f"-{_text(item['penalty'])}</li>"
        )

    for item in score_breakdown.get("rules", []):
        items.append(
            f"<li>Pattern: {_text(item['title'])} : "
            f"-{_text(item['penalty'])}</li>"
        )

    if not items:
        items.append("<li>No deductions.</li>")

    return (
        '<div class="card"><h2>What lowered the score</h2><ul>'
        + "".join(items)
        + "</ul></div>"
    )


def _trend_items(entries):

    return "".join(
        f"<li>{_text(entry['source'])} Event {_text(entry['event_id'])} : "
        f"{_text(entry['previous_count'])} &rarr; "
        f"{_text(entry['count'])}</li>"
        for entry in entries
    )


def _trends_html(trends):
    """Comparison with the previous comparable run."""

    if not trends:
        return ""

    if not trends.get("available"):
        return (
            '<div class="card"><h2>Trends</h2><p>'
            + _text(trends.get("message", "No trend data."))
            + "</p></div>"
        )

    sections = []

    for key, title in (
        ("new", "New since the previous run"),
        ("increased", "Increased"),
        ("decreased", "Decreased"),
        ("resolved", "No longer seen"),
    ):
        entries = trends.get(key) or []

        if entries:
            sections.append(
                f"<h3>{title}</h3><ul>{_trend_items(entries)}</ul>"
            )

    if not sections:
        sections.append("<p>No significant change.</p>")

    return (
        '<div class="card"><h2>Trends</h2><p>'
        + _text(trends.get("message", ""))
        + "</p>"
        + "".join(sections)
        + "</div>"
    )


REPORT_STYLE = """
:root {
    --bg: #ffffff; --fg: #1d2630; --muted: #5b6673; --card: #f6f8fa;
    --line: #d0d7de; --track: #e1e6eb;
    --good: #2e7d32; --ok: #689f38; --warn: #ef8f00; --bad: #c62828;
    --sev-critical: #b71c1c; --sev-high: #e65100;
    --sev-medium: #f9a825; --sev-low: #2e7d32; --accent: #1f6feb;
}
@media (prefers-color-scheme: dark) {
    :root {
        --bg: #0f1419; --fg: #e6edf3; --muted: #9aa7b4; --card: #171d24;
        --line: #2d3742; --track: #2a333d;
        --good: #57ab5a; --ok: #8bc34a; --warn: #f2a33a; --bad: #ef5350;
        --sev-critical: #ef5350; --sev-high: #ff8a50;
        --sev-medium: #ffd54f; --sev-low: #66bb6a; --accent: #58a6ff;
    }
}
body { font-family: Segoe UI, Arial, sans-serif; margin: 0 auto;
       padding: 20px 16px; max-width: 1100px; background: var(--bg);
       color: var(--fg); line-height: 1.45; }
h1 { margin: 0 0 4px; } h2 { margin: 0 0 10px; font-size: 1.1rem; }
h3 { margin: 12px 0 4px; font-size: 1rem; }
.meta { color: var(--muted); margin-bottom: 16px; }
.grid { display: grid; gap: 16px;
        grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); }
.card { border: 1px solid var(--line); background: var(--card);
        padding: 14px 16px; border-radius: 8px; margin-bottom: 16px; }
.grid .card { margin-bottom: 0; }
.score { font-size: 2.6rem; font-weight: 700; margin: 0; }
.chart { width: 100%; max-width: 640px; height: auto; display: block; }
.chart text { fill: var(--fg); font-size: 12px; }
.chart .axis { fill: var(--muted); }
.chart .axis-line { stroke: var(--line); stroke-width: 1; }
.track { fill: var(--track); }
.band-good { fill: var(--good); } .band-ok { fill: var(--ok); }
.band-warn { fill: var(--warn); } .band-bad { fill: var(--bad); }
.sev-critical { fill: var(--sev-critical); } .sev-high { fill: var(--sev-high); }
.sev-medium { fill: var(--sev-medium); } .sev-low { fill: var(--sev-low); }
.bar-default { fill: var(--accent); }
.text-band-good { color: var(--good); } .text-band-ok { color: var(--ok); }
.text-band-warn { color: var(--warn); } .text-band-bad { color: var(--bad); }
table { border-collapse: collapse; width: 100%; max-width: 420px; }
td:last-child { text-align: right; }
th, td { text-align: left; padding: 4px 8px; border-bottom: 1px solid var(--line); }
ul { margin: 6px 0 0; padding-left: 20px; }
@media print {
    body { max-width: none; padding: 0; background: #fff; color: #000; }
    .card { break-inside: avoid; background: #fff; }
}
"""


def _security_html(summary):
    """Security activity card, or "" when there were no security events."""

    if not summary:
        return ""

    def table(title, rows):

        if not rows:
            return ""

        return (
            f"<h3>{_text(title)}</h3><table>"
            + "".join(
                f"<tr><td>{_text(name)}</td><td>{_text(count)}</td></tr>"
                for name, count in rows
            )
            + "</table>"
        )

    facts = (
        ("Failed logons", summary["failed_logons"]),
        ("Account lockouts", summary["lockouts"]),
        ("Account changes", summary["account_changes"]),
        ("Group membership changes", summary["group_changes"]),
        ("Audit policy changes", summary["audit_policy_changes"]),
        ("Services/tasks created", summary["persistence"]),
        ("Security log cleared", summary["log_cleared"]),
    )

    return (
        '<div class="card"><h2>Security activity</h2><ul>'
        + "".join(
            f"<li>{_text(label)}: {_text(value)}</li>"
            for label, value in facts
            if value
        )
        + "</ul>"
        + table("Top failed-logon accounts", summary["top_failed_accounts"])
        + table("Top failed-logon sources", summary["top_failed_sources"])
        + table("Locked-out accounts", summary["locked_accounts"])
        + "</div>"
    )


def _list_card(title, items):

    return (
        f'<div class="card"><h2>{_text(title)}</h2><ul>'
        + "".join(f"<li>{_text(item)}</li>" for item in items)
        + "</ul></div>"
    )


def generate_dashboard(
    events,
    health_score,
    correlations,
    recommendations,
    output_dir=None,
    score_breakdown=None,
    trends=None,
    security_summary=None
):

    output_dir = (
        get_reports_dir()
        if output_dir is None
        else Path(output_dir)
    )
    output_dir.mkdir(parents=True, exist_ok=True)

    event_counter = Counter()
    log_counter = Counter()
    severity_counter = {name: 0 for name in SEVERITY_ORDER}

    for event in events:

        event_counter[event["EventID"]] += 1

        if event.get("Channel"):
            log_counter[event["Channel"]] += 1

        severity_counter[event["Analysis"]["severity_text"]] += 1

    top_events = event_counter.most_common(10)

    band_name, band_css = score_band(health_score)

    timeline = timeline_svg(events)
    top_chart = horizontal_bars_svg(
        [(f"Event {event_id}", count) for event_id, count in top_events]
    )
    log_chart = (
        horizontal_bars_svg(list(log_counter.items()))
        if len(log_counter) > 1
        else ""
    )

    sections = [
        '<div class="grid">',
        '<div class="card"><h2>Health Score</h2>'
        f'<p class="score text-{band_css}">'
        f"{escape(str(health_score), quote=True)}%</p>"
        f"<p>{_text(band_name)}</p>"
        f"{score_bar_svg(health_score)}</div>",
        '<div class="card"><h2>Event Counts by Severity</h2>'
        f"{severity_bars_svg(severity_counter)}"
        "<ul>"
        + "".join(
            f"<li>{name.title()} : {severity_counter[name]}</li>"
            for name in SEVERITY_ORDER
        )
        + "</ul></div>",
        "</div>",
        '<div style="height:16px"></div>',
        _breakdown_html(score_breakdown),
    ]

    if timeline:
        sections.append(
            '<div class="card"><h2>Events over time</h2>'
            f"{timeline}</div>"
        )

    sections.append(_list_card("Correlation Findings", correlations))
    sections.append(_list_card("Recommendations", recommendations))
    sections.append(_trends_html(trends))
    sections.append(_security_html(security_summary))

    sections.append(
        '<div class="grid"><div class="card"><h2>Top 10 Event IDs</h2>'
        + top_chart
        + "<ul>"
        + "".join(
            f"<li>Event {_text(event_id)} : {_text(count)} occurrences</li>"
            for event_id, count in top_events
        )
        + "</ul></div>"
        + (
            f'<div class="card"><h2>Events by log</h2>{log_chart}</div>'
            if log_chart
            else ""
        )
        + "</div>"
    )

    html = (
        "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n"
        '<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        "<title>Windows Event Analyzer Dashboard</title>\n"
        f"<style>{REPORT_STYLE}</style>\n</head>\n<body>\n"
        "<h1>Windows Event Analyzer Dashboard</h1>\n"
        f'<p class="meta">{len(events)} event(s) analyzed</p>\n'
        + "\n".join(sections)
        + "\n</body>\n</html>\n"
    )

    with open(
        output_dir / "dashboard.html",
        "w",
        encoding="utf-8"
    ) as file:

        file.write(html)

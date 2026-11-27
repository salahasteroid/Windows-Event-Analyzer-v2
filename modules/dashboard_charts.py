"""Small inline SVG charts for the HTML reports. No scripts, no libraries."""

from datetime import timedelta
from html import escape

from modules.time_range import parse_event_time


SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW")

# Colors live in CSS variables (see dashboard_generator) so dark mode works.
SEVERITY_CLASS = {
    "CRITICAL": "sev-critical",
    "HIGH": "sev-high",
    "MEDIUM": "sev-medium",
    "LOW": "sev-low",
}


def _label(value):

    return escape(str(value), quote=True)


def score_band(score):
    """(name, css class) for a health score."""

    if score >= 100:
        return "Healthy", "band-good"

    if score >= 80:
        return "Minor issues", "band-ok"

    if score >= 50:
        return "Moderate issues", "band-warn"

    return "Critical issues", "band-bad"


def score_bar_svg(score):
    """A horizontal 0-100 bar with the current score marked."""

    score = max(0, min(100, int(score)))
    name, css = score_band(score)
    width = 400

    return (
        f'<svg class="chart" viewBox="0 0 {width + 20} 56" role="img" '
        f'aria-label="Health score {score} percent, {_label(name)}">'
        f'<rect x="10" y="12" width="{width}" height="18" rx="9" '
        f'class="track"/>'
        f'<rect x="10" y="12" width="{width * score / 100:.1f}" height="18" '
        f'rx="9" class="{css}"/>'
        f'<text x="10" y="50" class="axis">0</text>'
        f'<text x="{width + 10}" y="50" text-anchor="end" class="axis">'
        f"100</text></svg>"
    )


def horizontal_bars_svg(rows, css_classes=None, label_width=150):
    """Bars for [(label, count), ...]; the count is printed at the bar end."""

    rows = [(label, int(count)) for label, count in rows if int(count) > 0]

    if not rows:
        return ""

    bar_area = 300
    row_height = 26
    top = max(count for _, count in rows)
    height = row_height * len(rows) + 6

    parts = [
        f'<svg class="chart" viewBox="0 0 {label_width + bar_area + 70} '
        f'{height}" role="img" aria-label="Bar chart">'
    ]

    for index, (label, count) in enumerate(rows):

        y = index * row_height + 4
        css = (css_classes or {}).get(label, "bar-default")
        shown = label if len(str(label)) <= 22 else str(label)[:21] + "…"

        parts.append(
            f'<text x="{label_width - 8}" y="{y + 15}" text-anchor="end" '
            f'class="axis">{_label(shown)}</text>'
            f'<rect x="{label_width}" y="{y + 2}" '
            f'width="{max(2.0, bar_area * count / top):.1f}" height="18" '
            f'rx="3" class="{css}"/>'
            f'<text x="{label_width + max(2.0, bar_area * count / top) + 6:.1f}" '
            f'y="{y + 15}" class="axis">{count}</text>'
        )

    parts.append("</svg>")

    return "".join(parts)


def severity_bars_svg(severity_counter):

    return horizontal_bars_svg(
        [(name.title(), severity_counter.get(name, 0)) for name in SEVERITY_ORDER],
        css_classes={
            name.title(): SEVERITY_CLASS[name] for name in SEVERITY_ORDER
        },
        label_width=90
    )


def timeline_svg(events, buckets=24):
    """Events over time, stacked by severity. "" if there is no usable time."""

    stamped = []

    for event in events:

        moment = parse_event_time(event.get("Time"))

        if moment is not None:
            severity = (event.get("Analysis") or {}).get("severity_text", "LOW")
            stamped.append((moment, severity))

    if len(stamped) < 2:
        return ""

    first = min(moment for moment, _ in stamped)
    last = max(moment for moment, _ in stamped)
    span = (last - first) or timedelta(seconds=1)
    step = span / buckets

    counts = [
        {name: 0 for name in SEVERITY_ORDER} for _ in range(buckets)
    ]

    for moment, severity in stamped:

        index = min(int((moment - first) / step), buckets - 1)
        counts[index][severity if severity in SEVERITY_ORDER else "LOW"] += 1

    top = max(sum(bucket.values()) for bucket in counts) or 1
    plot_w, plot_h, left, bottom = 520, 120, 36, 24
    bar_w = plot_w / buckets

    parts = [
        f'<svg class="chart" viewBox="0 0 {left + plot_w + 10} '
        f'{plot_h + bottom + 14}" role="img" '
        f'aria-label="Events over time, from {_label(first.strftime("%Y-%m-%d %H:%M"))} '
        f'to {_label(last.strftime("%Y-%m-%d %H:%M"))}">',
        f'<text x="{left - 6}" y="14" text-anchor="end" class="axis">{top}</text>',
        f'<text x="{left - 6}" y="{plot_h + 12}" text-anchor="end" '
        f'class="axis">0</text>',
        f'<line x1="{left}" y1="{plot_h + 10}" x2="{left + plot_w}" '
        f'y2="{plot_h + 10}" class="axis-line"/>',
    ]

    for index, bucket in enumerate(counts):

        y = plot_h + 10

        for name in reversed(SEVERITY_ORDER):

            value = bucket[name]

            if not value:
                continue

            height = plot_h * value / top
            y -= height

            parts.append(
                f'<rect x="{left + index * bar_w + 1:.1f}" y="{y:.1f}" '
                f'width="{max(1.0, bar_w - 2):.1f}" height="{height:.1f}" '
                f'class="{SEVERITY_CLASS[name]}"/>'
            )

    parts.append(
        f'<text x="{left}" y="{plot_h + 28}" class="axis">'
        f'{_label(first.strftime("%m-%d %H:%M"))}</text>'
        f'<text x="{left + plot_w}" y="{plot_h + 28}" text-anchor="end" '
        f'class="axis">{_label(last.strftime("%m-%d %H:%M"))} (UTC)</text>'
        "</svg>"
    )

    return "".join(parts)

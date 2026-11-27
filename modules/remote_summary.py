"""One page comparing the computers analyzed in a single run."""

from html import escape
from pathlib import Path


def _band(score):
    if score >= 80:
        return "good"
    if score >= 50:
        return "warn"
    return "bad"


def generate_remote_summary(results, output_dir):
    """results: list of dicts {"computer", "summary", "error"}.

    "summary" is what main() returned; "error" is a message for a computer
    that could not be analyzed. Returns the path of the written page, sorted
    with the unhealthiest computers first.
    """

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    ok = [r for r in results if r.get("summary")]
    failed = [r for r in results if not r.get("summary")]
    ok.sort(key=lambda r: r["summary"]["health_score"])

    rows = ""

    for result in ok:
        summary = result["summary"]
        score = summary["health_score"]
        report = Path(summary["report_dir"]) / "dashboard.html"
        try:
            link = report.relative_to(output_dir).as_posix()
        except ValueError:
            link = report.as_posix()
        findings = ", ".join(
            str(f.get("title") or f.get("rule") or f.get("id") or "")
            for f in summary.get("findings", [])
            if isinstance(f, dict)
        )
        rows += (
            f'<tr class="{_band(score)}">'
            f"<td>{escape(str(result['computer']))}</td>"
            f"<td>{score}</td>"
            f"<td>{summary['critical']}</td>"
            f"<td>{summary['high']}</td>"
            f"<td>{summary['event_count']}</td>"
            f"<td>{escape(findings)}</td>"
            f'<td><a href="{escape(link, quote=True)}">Dashboard</a></td>'
            "</tr>"
        )

    for result in failed:
        rows += (
            '<tr class="bad">'
            f"<td>{escape(str(result['computer']))}</td>"
            f'<td colspan="6">Not analyzed: '
            f"{escape(str(result.get('error') or 'unknown error'))}</td>"
            "</tr>"
        )

    html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Computer comparison</title>
<style>
:root {{ color-scheme: light dark; --bg:#fff; --fg:#222; --line:#ccc;
  --good:#d9f2d9; --warn:#fff5b3; --bad:#ffd0d0; }}
@media (prefers-color-scheme: dark) {{ :root {{ --bg:#1b1b1b; --fg:#eee;
  --line:#444; --good:#1f3d24; --warn:#4a4219; --bad:#4d2323; }} }}
body {{ font-family: Arial, sans-serif; margin:20px; background:var(--bg);
  color:var(--fg); }}
table {{ border-collapse:collapse; width:100%; }}
th,td {{ border:1px solid var(--line); padding:8px; text-align:left;
  vertical-align:top; }}
tr.good td {{ background:var(--good); }} tr.warn td {{ background:var(--warn); }}
tr.bad td {{ background:var(--bad); }}
a {{ color:inherit; }}
@media print {{ body {{ margin:0; }} }}
</style></head><body>
<h1>Computer comparison</h1>
<p>Lowest health score first. {len(ok)} analyzed, {len(failed)} failed.</p>
<table><tr><th>Computer</th><th>Health score</th><th>Critical</th><th>High</th>
<th>Events</th><th>Findings</th><th>Report</th></tr>{rows}</table>
</body></html>"""

    path = output_dir / "summary.html"
    path.write_text(html, encoding="utf-8")
    return path

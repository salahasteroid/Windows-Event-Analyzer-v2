from html import escape
from pathlib import Path
from urllib.parse import urlsplit

from modules.paths import get_reports_dir


def _format_reference(search_url):

    if not isinstance(search_url, str) or not search_url:
        return "Known Event"

    try:
        parsed_url = urlsplit(search_url)
    except ValueError:
        return "Invalid reference"

    if (
        parsed_url.scheme.lower() not in ("http", "https")
        or not parsed_url.netloc
    ):
        return "Invalid reference"

    return (
        f'<a href="{escape(search_url, quote=True)}" '
        f'target="_blank" rel="noopener noreferrer">Search</a>'
    )


def generate_html_report(events, output_dir=None):

    output_dir = (
        get_reports_dir()
        if output_dir is None
        else Path(output_dir)
    )
    output_dir.mkdir(parents=True, exist_ok=True)

    html = """
    <html>
    <head>

        <title>Windows Event Analyzer Report</title>

        <style>

            body {
                font-family: Arial, sans-serif;
                margin: 20px;
            }

            h1 {
                color: #333333;
            }

            table {
                width: 100%;
                border-collapse: collapse;
            }

            th {
                background-color: #e6e6e6;
            }

            th, td {
                border: 1px solid #cccccc;
                padding: 8px;
                text-align: left;
                vertical-align: top;
            }

            .critical {
                background-color: #ffb3b3;
            }

            .high {
                background-color: #ffd9b3;
            }

            .medium {
                background-color: #fff5b3;
            }

            .low {
                background-color: #d9f2d9;
            }

            a {
                color: blue;
                text-decoration: none;
            }

        </style>

    </head>

    <body>

        <h1>Windows Event Analyzer Report</h1>

        <table>

            <tr>
                <th>Event ID</th>
                <th>Source</th>
                <th>Level</th>
                <th>Severity</th>
                <th>Cause</th>
                <th>Message</th>
                <th>Error Code</th>
                <th>Error Description</th>
                <th>Event Data</th>
                <th>Time</th>
                <th>Reference</th>
            </tr>
    """

    for event in events:

        analysis = event["Analysis"]
        severity = str(analysis["severity_text"])

        css_class = (
            severity.lower()
            if severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
            else "low"
        )

        reference = _format_reference(
            analysis.get("search_url", "")
        )

        message = event.get(
            "Message",
            ""
        )

        data = "<br>".join(
            escape(str(item), quote=True)
            for item in event.get("Data", [])
        )

        event_id = escape(str(event["EventID"]), quote=True)
        source = escape(str(event["Source"]), quote=True)
        level_name = escape(str(event["LevelName"]), quote=True)
        safe_severity = escape(severity, quote=True)
        cause = escape(str(analysis["cause"]), quote=True)
        safe_message = escape(str(message), quote=True)
        error_code = escape(
            str(analysis.get("error_code", "")),
            quote=True
        )
        error_description = escape(
            str(analysis.get("error_description", "")),
            quote=True
        )
        event_time = escape(str(event["Time"]), quote=True)

        html += f"""
        <tr class="{css_class}">
            <td>{event_id}</td>
            <td>{source}</td>
            <td>{level_name}</td>
            <td>{safe_severity}</td>
            <td>{cause}</td>
            <td>{safe_message}</td>
            <td>{error_code}</td>
            <td>{error_description}</td>
            <td>{data}</td>
            <td>{event_time}</td>
            <td>{reference}</td>
        </tr>
        """

    html += """
        </table>

    </body>
    </html>
    """

    with open(
        output_dir / "event_report.html",
        "w",
        encoding="utf-8"
    ) as file:

        file.write(html)
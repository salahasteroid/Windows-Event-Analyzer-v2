from html import escape
from pathlib import Path
from urllib.parse import urlsplit

from modules.paths import get_reports_dir
from modules.event_data import format_event_data_item


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
        f'target="_blank" rel="noopener noreferrer">'
        "Open reference"
        "</a>"
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
                <th>Local cause</th>
                <th>Online explanation</th>
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

        online_lookup = analysis.get("online_lookup", {})
        reference = _format_reference(
            online_lookup.get("url")
            or online_lookup.get("search_url")
            or analysis.get("search_url", "")
        )

        message = event.get(
            "Message",
            ""
        )

        event_data = event.get("Data", [])
        data = "<br>".join(
            escape(
                format_event_data_item(item, index),
                quote=True
            )
            for index, item in enumerate(event_data, start=1)
        )
        if event_data and not message:
            data += (
                "<br><em>Windows did not provide a plain-language "
                "message; field meanings depend on the Event ID and source."
                "</em>"
            )

        if online_lookup.get("status") == "found":
            online_explanation = (
                "<strong>"
                + escape(online_lookup.get("title", ""), quote=True)
                + "</strong><br>"
                + escape(online_lookup.get("summary", ""), quote=True)
            )
            if online_lookup.get("cause"):
                online_explanation += (
                    "<br><strong>Main reason:</strong> "
                    + escape(online_lookup["cause"], quote=True)
                )
            if online_lookup.get("resolution"):
                online_explanation += (
                    "<br><strong>Microsoft solution:</strong> "
                    + escape(online_lookup["resolution"], quote=True)
                )
            elif online_lookup.get("article_error"):
                online_explanation += (
                    "<br>Could not load full article details: "
                    + escape(online_lookup["article_error"], quote=True)
                )
            online_explanation += (
                "<br><em>The exact fix may still depend on this event's "
                "data and nearby events.</em>"
            )
        elif online_lookup.get("status") == "error":
            online_explanation = (
                "Online lookup failed: "
                + escape(online_lookup.get("error", ""), quote=True)
            )
        elif online_lookup.get("status") == "no_match":
            online_explanation = (
                "No matching Microsoft Learn article was found."
            )
        elif online_lookup.get("status") == "skipped":
            online_explanation = (
                "Lookup skipped to keep analysis responsive."
            )
        else:
            online_explanation = "No online lookup was performed."

        event_id = escape(str(event["EventID"]), quote=True)
        source = escape(str(event["Source"]), quote=True)
        level_name = escape(str(event["LevelName"]), quote=True)
        safe_severity = escape(severity, quote=True)
        cause = escape(str(analysis["cause"]), quote=True)
        safe_message = escape(str(message), quote=True)
        error_entries = analysis.get("error_codes")

        if error_entries:
            # One line per error code found in the event data.
            error_code = "<br>".join(
                escape(str(entry.get("code", "")), quote=True)
                for entry in error_entries
            )
            error_description = "<br>".join(
                escape(str(entry.get("description", "")), quote=True)
                for entry in error_entries
            )
        else:
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
            <td>{online_explanation}</td>
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
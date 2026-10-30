import os


def generate_html_report(events):

    os.makedirs(
        "reports",
        exist_ok=True
    )

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

        severity = event["Analysis"][
            "severity_text"
        ]

        css_class = severity.lower()

        search_url = event[
            "Analysis"
        ].get(
            "search_url",
            ""
        )

        if search_url:

            reference = (
                f'<a href="{search_url}" '
                f'target="_blank">Search</a>'
            )

        else:

            reference = "Known Event"

        message = event.get(
            "Message",
            ""
        )

        data = "<br>".join(
            event.get(
                "Data",
                []
            )
        )

        error_code = (
            event["Analysis"].get(
                "error_code",
                ""
            )
        )

        error_description = (
            event["Analysis"].get(
                "error_description",
                ""
            )
        )

        html += f"""
        <tr class="{css_class}">
            <td>{event['EventID']}</td>
            <td>{event['Source']}</td>
            <td>{event['LevelName']}</td>
            <td>{severity}</td>
            <td>{event['Analysis']['cause']}</td>
            <td>{message}</td>
            <td>{error_code}</td>
            <td>{error_description}</td>
            <td>{data}</td>
            <td>{event['Time']}</td>
            <td>{reference}</td>
        </tr>
        """

    html += """
        </table>

    </body>
    </html>
    """

    with open(
        "reports/event_report.html",
        "w",
        encoding="utf-8"
    ) as file:

        file.write(html)
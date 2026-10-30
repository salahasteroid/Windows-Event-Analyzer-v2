import os
from collections import Counter


def generate_dashboard(
    events,
    health_score,
    correlations,
    recommendations
):

    os.makedirs(
        "reports",
        exist_ok=True
    )

    event_counter = Counter()

    severity_counter = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0
    }

    for event in events:

        event_counter[
            event["EventID"]
        ] += 1

        severity = event[
            "Analysis"
        ][
            "severity_text"
        ]

        severity_counter[
            severity
        ] += 1

    top_events = (
        event_counter.most_common(10)
    )

    html = f"""
    <html>

    <head>

        <title>
            Windows Event Analyzer Dashboard
        </title>

        <style>

            body {{
                font-family: Arial;
                margin: 20px;
            }}

            .card {{
                border: 1px solid #ccc;
                padding: 15px;
                margin-bottom: 20px;
                border-radius: 6px;
            }}

        </style>

    </head>

    <body>

        <h1>
            Windows Event Analyzer Dashboard
        </h1>

        <div class="card">
            <h2>Health Score</h2>
            <h1>{health_score}%</h1>
        </div>

        <div class="card">
            <h2>Top 10 Event IDs</h2>
            <ul>
    """

    for event_id, count in top_events:

        html += (
            f"<li>"
            f"Event {event_id} : "
            f"{count} occurrences"
            f"</li>"
        )

    html += """
            </ul>
        </div>

        <div class="card">
            <h2>Correlation Findings</h2>
            <ul>
    """

    for item in correlations:

        html += f"<li>{item}</li>"

    html += """
            </ul>
        </div>

        <div class="card">
            <h2>Recommendations</h2>
            <ul>
    """

    for item in recommendations:

        html += f"<li>{item}</li>"

    html += f"""
            </ul>
        </div>

        <div class="card">

            <h2>
                Event Counts by Severity
            </h2>

            <ul>

                <li>
                    Critical :
                    {severity_counter['CRITICAL']}
                </li>

                <li>
                    High :
                    {severity_counter['HIGH']}
                </li>

                <li>
                    Medium :
                    {severity_counter['MEDIUM']}
                </li>

                <li>
                    Low :
                    {severity_counter['LOW']}
                </li>

            </ul>

        </div>

    </body>

    </html>
    """

    with open(
        "reports/dashboard.html",
        "w",
        encoding="utf-8"
    ) as file:

        file.write(html)
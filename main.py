import sys

from modules.event_reader import (
    get_recent_events
)

from modules.evtx_reader import (
    read_evtx
)

from modules.analyzer import (
    get_level_name,
    analyze_event
)

from modules.report_generator import (
    generate_html_report
)

from modules.dashboard_generator import (
    generate_dashboard
)

from modules.health_score import (
    calculate_health_score
)

from modules.recommendation_engine import (
    build_recommendations
)

from modules.xml_exporter import (
    export_xml
)

from modules.correlation_engine import (
    correlate_events
)

from modules.paths import get_reports_dir


def main(evtx_file=None):

    print("=" * 80)
    print("WINDOWS EVENT ANALYZER")
    print("=" * 80)

    if evtx_file is None and len(sys.argv) > 1:
        evtx_file = sys.argv[1]

    if evtx_file:

        print(
            f"\nAnalyzing EVTX file:"
            f" {evtx_file}\n"
        )

        events = read_evtx(
            evtx_file,
            500
        )

    else:

        events = get_recent_events(50)

    health_score = (
        calculate_health_score(
            events
        )
    )

    smart_recommendations = (
        build_recommendations(
            events
        )
    )

    correlation_results = (
        correlate_events(
            events
        )
    )

    print(
        f"\nRaw Events Read: "
        f"{len(events)}\n"
    )

    displayed = 0

    critical_count = 0
    high_count = 0
    medium_count = 0
    low_count = 0

    report_events = []

    for event in events:

        if event["Level"] > 3:
            continue

        analysis = analyze_event(
            event
        )

        if "RawXML" in event:
            export_xml(event)

        report_events.append({
            "EventID": event["EventID"],
            "Source": event["Source"],
            "LevelName": get_level_name(
                event["Level"]
            ),
            "Time": event["Time"],
            "Data": event.get(
                "Data",
                []
            ),
            "Message": event.get(
                "Message",
                ""
            ),
            "Analysis": analysis
        })

        if (
            analysis["severity_text"]
            == "CRITICAL"
        ):
            critical_count += 1

        elif (
            analysis["severity_text"]
            == "HIGH"
        ):
            high_count += 1

        elif (
            analysis["severity_text"]
            == "MEDIUM"
        ):
            medium_count += 1

        else:
            low_count += 1

        displayed += 1

        print("=" * 80)

        print(
            f"Event ID : "
            f"{event['EventID']}"
        )

        print(
            f"Source   : "
            f"{event['Source']}"
        )

        print(
            f"Level    : "
            f"{get_level_name(event['Level'])}"
        )

        print(
            f"Computer : "
            f"{event['Computer']}"
        )

        print(
            f"Time     : "
            f"{event['Time']}"
        )

        print()

        print("Message:")

        if event.get("Message"):

            print(
                event["Message"]
            )

        else:

            print(
                "Message not available."
            )

        print()

        print("Event Data:")

        if event.get("Data"):

            for item in event["Data"]:

                print(
                    f"  - {item}"
                )

        else:

            print(
                "  No Event Data"
            )

        print()

        print(
            f"Cause    : "
            f"{analysis['cause']}"
        )

        print()

        print(
            f"Severity : "
            f"{analysis['severity']}/100 "
            f"({analysis['severity_text']})"
        )

        print()

        print(
            "Recommendations:"
        )

        for solution in analysis[
            "solutions"
        ]:

            print(
                f"  - {solution}"
            )

        print()

    print("=" * 80)

    print(
        "\nCorrelation Analysis\n"
    )

    for item in correlation_results:

        print(f"- {item}")

    print(
        "\nSystem Health\n"
    )

    print(
        f"Overall Health Score: "
        f"{health_score}%"
    )

    print(
        "\nPriority Actions\n"
    )

    for item in smart_recommendations:

        print(f"- {item}")

    print(
        "\nSummary\n"
    )

    print(
        f"Critical : {critical_count}"
    )

    print(
        f"High     : {high_count}"
    )

    print(
        f"Medium   : {medium_count}"
    )

    print(
        f"Low      : {low_count}"
    )

    print()

    print(
        f"Displayed {displayed} "
        f"Critical/Error/Warning Events"
    )

    print("=" * 80)

    generate_html_report(
        report_events
    )

    generate_dashboard(
        report_events,
        health_score,
        correlation_results,
        smart_recommendations
    )

    print(
        "\nHTML report generated:"
    )

    print(
        str(get_reports_dir() / "event_report.html")
    )

    print(
        str(get_reports_dir() / "dashboard.html")
    )


if __name__ == "__main__":
    if getattr(sys, "frozen", False):
        from modules.app_ui import run_app

        initial_evtx = (
            sys.argv[1]
            if len(sys.argv) > 1
            else None
        )
        run_app(main, initial_evtx)
    else:
        main()
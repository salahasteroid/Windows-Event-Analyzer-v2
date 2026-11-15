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
from modules.event_data import format_event_data_item
from modules.internet_lookup import lookup_events
from modules.time_range import resolve_time_range
from modules.event_levels import normalize_event_levels


def main(
    evtx_file=None,
    start_time=None,
    end_time=None,
    selected_levels=None,
    remote_options=None,
    cancellation_event=None,
    result_level_callback=None,
    collection_finished_callback=None
):

    print("=" * 80)
    print("WINDOWS EVENT ANALYZER")
    print("=" * 80)

    if evtx_file is None and len(sys.argv) > 1:
        evtx_file = sys.argv[1]

    start_time, end_time = resolve_time_range(
        start_time,
        end_time
    )
    selected_levels = normalize_event_levels(selected_levels)
    remote_options = remote_options or {}

    if evtx_file and remote_options:
        raise ValueError(
            "Remote computer options can only be used with the live System log."
        )

    print(
        "\nTime range (UTC): "
        f"{start_time.isoformat()} to {end_time.isoformat()}\n"
    )

    if evtx_file:

        print(
            f"\nAnalyzing EVTX file:"
            f" {evtx_file}\n"
        )

        events = read_evtx(
            evtx_file,
            start_time=start_time,
            end_time=end_time,
            levels=selected_levels,
            cancellation_event=cancellation_event
        )

    else:

        events = get_recent_events(
            start_time=start_time,
            end_time=end_time,
            levels=selected_levels,
            remote_options=remote_options,
            cancellation_event=cancellation_event
        )

    if collection_finished_callback is not None:
        collection_finished_callback()

    if (
        cancellation_event is not None
        and cancellation_event.is_set()
    ):
        print(
            "\nCollection stopped. Partial results were discarded; "
            "no report was generated."
        )
        return

    if remote_options:
        print(
            "Remote System Log: "
            f"{remote_options['computer']}"
        )

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

    lookup_candidates = [
        event
        for event in events
        if event["Level"] in (1, 2, 3)
    ]
    if lookup_candidates:
        print(
            "\nSearching Microsoft Learn for event explanations...\n"
        )
        online_lookups = lookup_events(lookup_candidates)
    else:
        online_lookups = {}

    print(
        f"\nEvents Matching Selected Levels: "
        f"{len(events)}\n"
    )

    displayed = 0

    critical_count = 0
    high_count = 0
    medium_count = 0
    low_count = 0

    report_events = []

    for event in events:

        if event["Level"] not in selected_levels:
            continue

        analysis = analyze_event(
            event,
            online_lookups.get(
                (event["EventID"], event["Source"])
            )
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

        if result_level_callback is not None:
            result_level_callback(event["Level"])

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

        print("Event Data (technical details):")

        if event.get("Data"):

            for index, item in enumerate(event["Data"], start=1):

                print(
                    f"  - {format_event_data_item(item, index)}"
                )

            if not event.get("Message"):
                print(
                    "  Windows did not provide a plain-language message. "
                    "The exact meaning of these fields depends on the "
                    "Event ID and source shown above."
                )

        else:

            print(
                "  No extra details were recorded for this event."
            )

        print()

        print(
            f"Cause (local analysis): "
            f"{analysis['cause']}"
        )

        print()

        online_lookup = analysis["online_lookup"]
        print("Online lookup (Microsoft Learn):")

        if online_lookup["status"] == "found":
            print(f"  {online_lookup['title']}")
            print(f"  {online_lookup['summary']}")
            if online_lookup.get("cause"):
                print(f"  Main reason: {online_lookup['cause']}")
            if online_lookup.get("resolution"):
                print(f"  Microsoft solution: {online_lookup['resolution']}")
            elif online_lookup.get("article_error"):
                print(
                    "  Could not load the full article details: "
                    f"{online_lookup['article_error']}"
                )
            print(f"  Source: {online_lookup['url']}")
            print(
                "  Exact fix depends on this event's data and nearby "
                "events; follow the linked article's troubleshooting steps."
            )
        elif online_lookup["status"] == "no_match":
            print(
                "  No matching Microsoft Learn article was found. "
                f"Search: {online_lookup['search_url']}"
            )
        elif online_lookup["status"] == "skipped":
            print(
                "  Skipped to keep the analysis responsive. "
                f"Search: {online_lookup['search_url']}"
            )
        else:
            print(
                "  Lookup failed: "
                f"{online_lookup['error']}"
            )

        print()

        print(
            f"Severity : "
            f"{analysis['severity']}/100 "
            f"({analysis['severity_text']})"
        )

        print()

        print(
            "Suggested next steps (general guidance):"
        )

        for solution in analysis[
            "solutions"
        ]:

            print(
                f"  - {solution}"
            )

        print()

        if result_level_callback is not None:
            result_level_callback(None)

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
        f"event(s) matching the selected levels"
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
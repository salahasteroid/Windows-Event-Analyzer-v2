import sys
from pathlib import Path

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
    explain_health_score
)

from modules.recommendation_engine import (
    build_recommendations
)

from modules.rules_engine import (
    evaluate_rules
)

from modules.trend_engine import (
    HISTORY_FILE_NAME,
    compare_with_history,
    record_run
)

from modules.xml_exporter import (
    export_xml
)

from modules.correlation_engine import (
    correlate_events
)

from modules.paths import get_reports_dir
from modules.event_channels import event_selected, normalize_logs
from modules.event_data import format_event_data_item
from modules.event_filter import filter_events
from modules.exporters import (
    export_events,
    forward_syslog,
    normalize_export_formats
)
from modules.internet_lookup import get_search_url, lookup_events
from modules.security_summary import summarize_security
from modules.time_range import resolve_time_range
from modules.unknown_events import write_unknown_template
from modules.event_levels import normalize_event_levels


def main(
    evtx_file=None,
    start_time=None,
    end_time=None,
    selected_levels=None,
    remote_options=None,
    cancellation_event=None,
    result_level_callback=None,
    collection_finished_callback=None,
    collected_events=None,
    output_dir=None,
    logs=None,
    event_ids=None,
    exclude_event_ids=None,
    sources=None,
    keywords=None,
    export_formats=None,
    xml_mode="per_event",
    syslog=None,
):
    """Collect, analyze and report.

    logs: "System", "Application" and/or "Security" (default System).
    event_ids / exclude_event_ids / sources / keywords: optional filters.
    export_formats: "csv" and/or "json" files next to the reports.
    xml_mode: "per_event" (default), "combined" or "none".
    syslog: {"host": ..., "port": 514, "protocol": "udp"} to forward events.

    Returns a summary dict when reports were generated, None when stopped.
    """

    print("=" * 80)
    print("WINDOWS EVENT ANALYZER")
    print("=" * 80)

    if (
        evtx_file is None
        and len(sys.argv) > 1
        and not sys.argv[1].startswith("-")
    ):
        evtx_file = sys.argv[1]

    start_time, end_time = resolve_time_range(
        start_time,
        end_time
    )
    selected_levels = normalize_event_levels(selected_levels)
    selected_logs = normalize_logs(logs)
    formats = normalize_export_formats(export_formats)
    remote_options = remote_options or {}

    if evtx_file and remote_options:
        raise ValueError(
            "Remote computer options can only be used with the live System log."
        )

    print(
        "\nTime range (UTC): "
        f"{start_time.isoformat()} to {end_time.isoformat()}\n"
    )

    if collected_events is not None:
        events = collected_events
    elif evtx_file:

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

        print(
            "Logs: " + ", ".join(selected_logs) + "\n"
        )

        events = []

        for log_name in selected_logs:

            events.extend(
                get_recent_events(
                    start_time=start_time,
                    end_time=end_time,
                    levels=selected_levels,
                    remote_options=remote_options,
                    cancellation_event=cancellation_event,
                    **(
                        {"log_name": log_name}
                        if log_name != "System"
                        else {}
                    )
                )
            )

        if len(selected_logs) > 1:
            events.sort(key=lambda item: item.get("Time", ""), reverse=True)

    filtering = any((event_ids, exclude_event_ids, sources, keywords))

    if filtering:

        before = len(events)

        events = filter_events(
            events,
            event_ids=event_ids,
            exclude_event_ids=exclude_event_ids,
            sources=sources,
            keywords=keywords
        )

        print(
            f"Filters kept {len(events)} of {before} event(s).\n"
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

    def stop_if_cancelled():
        if (
            cancellation_event is None
            or not cancellation_event.is_set()
        ):
            return False

        if result_level_callback is not None:
            result_level_callback(None)
        print(
            "\nAnalysis stopped. Partial results were discarded; "
            "no report was generated."
        )
        return True

    if remote_options:
        print(
            "Remote System Log: "
            f"{remote_options['computer']}"
        )

    report_dir = (
        get_reports_dir()
        if output_dir is None
        else Path(output_dir)
    )

    # Rules (database/rules.json) are evaluated once and shared by the
    # health score, the findings and the recommendations.
    rule_matches = evaluate_rules(events)
    if stop_if_cancelled():
        return

    health_details = explain_health_score(
        events,
        rule_matches
    )
    health_score = health_details["score"]
    if stop_if_cancelled():
        return

    smart_recommendations = (
        build_recommendations(
            events,
            rule_matches
        )
    )
    if stop_if_cancelled():
        return

    correlation_results = (
        correlate_events(
            events,
            rule_matches
        )
    )
    if stop_if_cancelled():
        return

    # Trend comparison needs a live or remote collection; an offline EVTX
    # file is not a point in time, so it is not tracked.
    history_path = report_dir / HISTORY_FILE_NAME
    window_seconds = (end_time - start_time).total_seconds()
    trends = None

    if not evtx_file:
        trends = compare_with_history(
            events,
            window_seconds,
            history_path,
            levels=selected_levels
        )

    lookup_candidates = [
        event
        for event in events
        if event["Level"] in (1, 2, 3)
        and event.get("Channel") != "Security"
    ]
    if lookup_candidates:
        print(
            "\nSearching Microsoft Learn for event explanations...\n"
        )
        online_lookups = lookup_events(
            lookup_candidates,
            cancellation_event=cancellation_event,
        )
    else:
        online_lookups = {}
    if stop_if_cancelled():
        return

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

        if stop_if_cancelled():
            return

        if not event_selected(
            event.get("Channel", ""),
            event["Level"],
            event["EventID"],
            selected_levels
        ):
            continue

        lookup_key = (event["EventID"], event["Source"])

        analysis = analyze_event(
            event,
            # Events that were not looked up (Security audit events,
            # Information events) must not trigger one lookup each.
            online_lookups.get(lookup_key)
            or {
                "status": "skipped",
                "search_url": get_search_url(*lookup_key),
            }
        )

        if "RawXML" in event and xml_mode == "per_event":
            export_xml(event, output_dir=output_dir)

        report_events.append({
            "EventID": event["EventID"],
            "Source": event["Source"],
            "Channel": event.get("Channel", ""),
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

    deductions = health_details["events"][:5]

    if deductions or health_details["rules"]:

        print("Score deductions (largest first):")

        for item in deductions:
            print(
                f"  - {item['source']} Event {item['event_id']} "
                f"x{item['count']}: -{item['penalty']}"
            )

        for item in health_details["rules"]:
            print(
                f"  - Pattern '{item['title']}': -{item['penalty']}"
            )

    if trends is not None:

        print(
            "\nTrend Analysis\n"
        )

        print(trends["message"])

        for key, title in (
            ("new", "New"),
            ("increased", "Increased"),
            ("decreased", "Decreased"),
            ("resolved", "No longer seen"),
        ):
            for entry in trends.get(key, []):
                print(
                    f"  - {title}: {entry['source']} "
                    f"Event {entry['event_id']} "
                    f"({entry['previous_count']} -> {entry['count']})"
                )

    security_for_console = summarize_security(events)

    if security_for_console is not None:

        print(
            "\nSecurity Summary\n"
        )

        print(
            f"Failed logons: {security_for_console['failed_logons']}, "
            f"lockouts: {security_for_console['lockouts']}, "
            f"account changes: {security_for_console['account_changes']}, "
            f"group changes: {security_for_console['group_changes']}, "
            f"log cleared: {security_for_console['log_cleared']}"
        )

        for label, key in (
            ("Top failed accounts", "top_failed_accounts"),
            ("Top failed sources", "top_failed_sources"),
        ):
            if security_for_console[key]:
                print(
                    f"{label}: "
                    + ", ".join(
                        f"{name} ({count})"
                        for name, count in security_for_console[key]
                    )
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

    if stop_if_cancelled():
        return

    security = summarize_security(events)

    generate_html_report(
        report_events,
        output_dir=report_dir,
    )

    generate_dashboard(
        report_events,
        health_score,
        correlation_results,
        smart_recommendations,
        output_dir=report_dir,
        score_breakdown=health_details,
        trends=trends,
        security_summary=security,
    )

    exported = export_events(
        report_events,
        events,
        report_dir,
        formats=formats,
        xml_mode=xml_mode,
        summary={
            "health_score": health_score,
            "findings": correlation_results,
            "recommendations": smart_recommendations,
            "logs": list(selected_logs),
            "start_time": start_time.isoformat(),
            "end_time": end_time.isoformat(),
        },
    )

    template_path = write_unknown_template(report_events, report_dir)

    syslog_sent = 0

    if syslog:
        try:
            syslog_sent = forward_syslog(
                report_events,
                syslog["host"],
                port=syslog.get("port", 514),
                protocol=syslog.get("protocol", "udp"),
            )
        except (OSError, ValueError) as error:
            print(f"\nSyslog forwarding failed: {error}")

    if not evtx_file:
        record_run(
            events,
            window_seconds,
            history_path,
            levels=selected_levels
        )

    print(
        "\nHTML report generated:"
    )

    print(
        str(report_dir / "event_report.html")
    )

    print(
        str(report_dir / "dashboard.html")
    )

    for path in exported:
        print(f"Export: {path}")

    if template_path is not None:
        print(
            f"Events without a local definition: a template to fill in is "
            f"at {template_path}"
        )

    if syslog:
        print(
            f"Syslog: sent {syslog_sent} event(s) to "
            f"{syslog['host']}:{syslog.get('port', 514)}"
        )

    return {
        "computer": remote_options.get("computer") or "local",
        "logs": list(selected_logs),
        "health_score": health_score,
        "event_count": len(report_events),
        "critical": critical_count,
        "high": high_count,
        "medium": medium_count,
        "low": low_count,
        "findings": correlation_results,
        "report_dir": str(report_dir),
        "exports": [str(path) for path in exported],
        "unknown_template": (
            str(template_path) if template_path is not None else None
        ),
    }


if __name__ == "__main__":
    command_line = len(sys.argv) > 1 and sys.argv[1].startswith("-")

    if command_line:
        from modules.cli import run_cli

        sys.exit(run_cli(sys.argv[1:], main))
    elif getattr(sys, "frozen", False):
        from modules.app_ui import run_app

        initial_evtx = (
            sys.argv[1]
            if len(sys.argv) > 1
            else None
        )
        run_app(main, initial_evtx)
    else:
        main()

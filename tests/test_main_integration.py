import io
from contextlib import ExitStack, redirect_stdout
from pathlib import Path
from threading import Event
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import patch

import main
from modules import dashboard_generator, report_generator


class MainIntegrationTests(TestCase):

    def test_cancelled_collection_does_not_generate_reports(self):
        cancellation_event = Event()
        output = io.StringIO()

        def collect_events(**_kwargs):
            cancellation_event.set()
            return [{"EventID": 1, "Level": 2}]

        with ExitStack() as stack:
            stack.enter_context(
                patch.object(main, "get_recent_events", side_effect=collect_events)
            )
            generate_report = stack.enter_context(
                patch.object(main, "generate_html_report")
            )
            stack.enter_context(
                patch.object(main.sys, "argv", ["main.py"])
            )
            stack.enter_context(redirect_stdout(output))

            main.main(cancellation_event=cancellation_event)

        generate_report.assert_not_called()
        self.assertIn("Partial results were discarded", output.getvalue())

    def test_cancel_during_processing_does_not_generate_reports(self):
        cancellation_event = Event()
        event = {
            "EventID": 41,
            "Level": 2,
            "Source": "Microsoft-Windows-Kernel-Power",
            "Computer": "TEST-PC",
            "Time": "2026-11-14T20:00:00Z",
            "Data": [],
            "Message": "",
        }
        output = io.StringIO()

        def finish_lookup(*_args, **_kwargs):
            cancellation_event.set()
            return {}

        with ExitStack() as stack:
            stack.enter_context(
                patch.object(main, "read_evtx", return_value=[event])
            )
            lookup = stack.enter_context(
                patch.object(main, "lookup_events", side_effect=finish_lookup)
            )
            generate_report = stack.enter_context(
                patch.object(main, "generate_html_report")
            )
            generate_dashboard = stack.enter_context(
                patch.object(main, "generate_dashboard")
            )
            stack.enter_context(redirect_stdout(output))

            main.main(
                "sample.evtx",
                selected_levels=(2,),
                cancellation_event=cancellation_event,
            )

        lookup.assert_called_once_with(
            [event],
            cancellation_event=cancellation_event,
        )
        generate_report.assert_not_called()
        generate_dashboard.assert_not_called()
        self.assertIn("Analysis stopped", output.getvalue())

    def test_analysis_creates_reports_with_online_explanation(self):
        source = "Microsoft-Windows-Kernel-Power"
        event = {
            "EventID": 41,
            "Level": 2,
            "Source": source,
            "Computer": "TEST-PC",
            "Time": "2026-11-14T20:00:00Z",
            "Data": [
                {"name": "BugcheckCode", "value": "0"}
            ],
            "Message": "The system rebooted unexpectedly."
        }
        online_lookup = {
            "status": "found",
            "title": "Event ID 41 troubleshooting",
            "summary": "The system restarted without a clean shutdown.",
            "cause": "The computer lost power unexpectedly.",
            "resolution": "Check the system power and related events.",
            "url": "https://learn.microsoft.com/en-us/example",
            "search_url": "https://learn.microsoft.com/en-us/search/"
        }
        output = io.StringIO()
        result_levels = []

        with TemporaryDirectory() as directory:
            reports_dir = Path(directory)
            with ExitStack() as stack:
                stack.enter_context(
                    patch.object(main, "read_evtx", return_value=[event])
                )
                stack.enter_context(
                    patch.object(
                        main,
                        "lookup_events",
                        return_value={(41, source): online_lookup}
                    )
                )
                stack.enter_context(
                    patch.object(
                        main,
                        "get_reports_dir",
                        return_value=reports_dir
                    )
                )
                stack.enter_context(
                    patch.object(
                        report_generator,
                        "get_reports_dir",
                        return_value=reports_dir
                    )
                )
                stack.enter_context(
                    patch.object(
                        dashboard_generator,
                        "get_reports_dir",
                        return_value=reports_dir
                    )
                )
                stack.enter_context(redirect_stdout(output))

                main.main(
                    "sample.evtx",
                    result_level_callback=result_levels.append,
                )

            self.assertTrue((reports_dir / "event_report.html").is_file())
            self.assertTrue((reports_dir / "dashboard.html").is_file())
            self.assertEqual(result_levels, [2, None])
            self.assertIn("Unexpected shutdown", output.getvalue())
            self.assertIn("Event ID 41 troubleshooting", output.getvalue())
            self.assertIn(
                "The system restarted without a clean shutdown.",
                (reports_dir / "event_report.html").read_text(
                    encoding="utf-8"
                )
            )
            self.assertIn(
                "The computer lost power unexpectedly.",
                output.getvalue()
            )
            self.assertIn(
                "Check the system power and related events.",
                (reports_dir / "event_report.html").read_text(
                    encoding="utf-8"
                )
            )

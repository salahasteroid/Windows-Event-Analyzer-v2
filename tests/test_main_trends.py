import io
from contextlib import ExitStack, redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import patch

import main
from modules.trend_engine import HISTORY_FILE_NAME, load_history


def live_events():
    return [
        {
            "EventID": 41,
            "Source": "Microsoft-Windows-Kernel-Power",
            "Level": 1,
            "Computer": "TEST-PC",
            "Time": "2026-11-14T10:00:00Z",
            "Data": [],
            "Message": "",
        },
        {
            "EventID": 6008,
            "Source": "EventLog",
            "Level": 2,
            "Computer": "TEST-PC",
            "Time": "2026-11-14T10:01:00Z",
            "Data": [],
            "Message": "",
        },
    ]


OFFLINE_LOOKUP = {
    key: {"status": "skipped", "search_url": ""}
    for key in (
        (41, "Microsoft-Windows-Kernel-Power"),
        (6008, "EventLog"),
    )
}


def run_main(directory, **kwargs):
    output = io.StringIO()

    with ExitStack() as stack:
        stack.enter_context(patch.object(main.sys, "argv", ["main.py"]))
        stack.enter_context(
            patch.object(main, "lookup_events", return_value=OFFLINE_LOOKUP)
        )
        stack.enter_context(redirect_stdout(output))

        main.main(output_dir=Path(directory), **kwargs)

    return output.getvalue()


class MainTrendTests(TestCase):

    def test_live_runs_are_recorded_and_compared(self):
        with TemporaryDirectory() as directory:
            with patch.object(main, "get_recent_events", return_value=live_events()):
                first = run_main(directory)
                second = run_main(directory)

            history = load_history(Path(directory) / HISTORY_FILE_NAME)

        self.assertIn("starting point", first)
        self.assertEqual(len(history), 2)
        self.assertIn("Compared with the run on", second)
        self.assertIn("0 new", second)

    def test_output_shows_pattern_health_and_deductions(self):
        with TemporaryDirectory() as directory:
            with patch.object(main, "get_recent_events", return_value=live_events()):
                text = run_main(directory)

            dashboard = (Path(directory) / "dashboard.html").read_text(encoding="utf-8")

        self.assertIn("Unexpected shutdown pattern detected", text)
        self.assertIn("Score deductions", text)
        self.assertIn("Pattern 'Unexpected shutdown with Kernel-Power'", text)
        self.assertIn("What lowered the score", dashboard)
        self.assertIn("<h2>Trends</h2>", dashboard)

    def test_offline_evtx_runs_are_not_tracked(self):
        with TemporaryDirectory() as directory:
            with patch.object(main, "read_evtx", return_value=live_events()):
                text = run_main(directory, evtx_file="sample.evtx")

            self.assertFalse((Path(directory) / HISTORY_FILE_NAME).exists())

        self.assertNotIn("Trend Analysis", text)

    def test_cancelled_run_is_not_recorded(self):
        from threading import Event

        cancellation_event = Event()

        def collect(**_kwargs):
            cancellation_event.set()
            return live_events()

        with TemporaryDirectory() as directory:
            with patch.object(main, "get_recent_events", side_effect=collect):
                run_main(directory, cancellation_event=cancellation_event)

            self.assertFalse((Path(directory) / HISTORY_FILE_NAME).exists())

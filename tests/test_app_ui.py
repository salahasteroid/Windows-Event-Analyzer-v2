import queue
import tempfile
import time
from pathlib import Path
from threading import Event, Lock
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import Mock, patch

from modules.app_ui import EventAnalyzerApp
from modules.remote_targets import MAX_PARALLEL_REMOTE_TARGETS


class EventAnalyzerAppTests(TestCase):

    def setUp(self):
        self.app = EventAnalyzerApp.__new__(EventAnalyzerApp)
        self.app.running = True
        self.app.cancellation_event = Event()
        self.app.collection_finished_event = Event()
        self.app.stop_button = Mock()
        self.app.status = Mock()

    def test_escape_stops_collection_and_consumes_key_event(self):
        result = self.app.stop_collection(
            SimpleNamespace(keysym="Escape")
        )

        self.assertEqual(result, "break")
        self.assertTrue(self.app.cancellation_event.is_set())
        self.app.stop_button.configure.assert_called_once_with(
            state="disabled"
        )
        self.app.status.set.assert_called_once_with(
            "Stopping analysis..."
        )

    def test_other_keys_do_not_stop_collection(self):
        self.app.stop_collection(SimpleNamespace(keysym="Return"))

        self.assertFalse(self.app.cancellation_event.is_set())
        self.app.stop_button.configure.assert_not_called()

    def test_stop_remains_available_during_processing(self):
        self.app.collection_finished_event.set()

        result = self.app.stop_collection(
            SimpleNamespace(keysym="Escape")
        )

        self.assertEqual(result, "break")
        self.assertTrue(self.app.cancellation_event.is_set())
        self.app.stop_button.configure.assert_called_once_with(
            state="disabled"
        )

    def test_collection_finished_keeps_stop_enabled_for_processing(self):
        self.app.output_queue = queue.Queue()
        self.app.output_queue.put(("collection_finished", None))
        self.app.root = Mock()

        self.app.poll_output()

        self.app.stop_button.configure.assert_not_called()
        self.app.status.set.assert_called_once_with(
            "Processing collected events..."
        )
        self.app.root.after.assert_called_once_with(
            100,
            self.app.poll_output,
        )

    def test_remote_targets_are_collected_concurrently_and_analyzed_separately(self):
        self.app.output_queue = queue.Queue()
        self.app.signal_collection_finished = Mock()
        self.app.analyze = Mock()
        targets = [
            "192.0.2.10",
            "192.0.2.11",
            "192.0.2.12",
        ]
        active = 0
        max_active = 0
        lock = Lock()

        def collect(**_kwargs):
            nonlocal active, max_active
            with lock:
                active += 1
                max_active = max(max_active, active)
            time.sleep(0.03)
            with lock:
                active -= 1
            return []

        with tempfile.TemporaryDirectory() as temp_dir:
            with (
                patch("modules.app_ui.get_recent_events", side_effect=collect),
                patch(
                    "modules.app_ui.get_reports_dir",
                    return_value=Path(temp_dir),
                ),
            ):
                self.app.run_remote_analysis(
                    None,
                    None,
                    (1, 2, 3),
                    {
                        "username": "event-reader",
                        "domain": "CONTOSO",
                        "password": "test-only-password",
                    },
                    targets,
                    Event(),
                )

        self.assertGreater(max_active, 1)
        self.assertLessEqual(max_active, MAX_PARALLEL_REMOTE_TARGETS)
        self.assertEqual(self.app.analyze.call_count, len(targets))
        self.assertEqual(
            [call.kwargs["remote_options"]["computer"]
             for call in self.app.analyze.call_args_list],
            targets,
        )
        self.assertEqual(
            [call.kwargs["output_dir"].name
             for call in self.app.analyze.call_args_list],
            [
                "host-192.0.2.10",
                "host-192.0.2.11",
                "host-192.0.2.12",
            ],
        )
        self.assertEqual(self.app.output_queue.get_nowait()[0], "dashboard")
        self.assertEqual(self.app.output_queue.get_nowait()[0], "dashboard")
        self.assertEqual(self.app.output_queue.get_nowait()[0], "dashboard")
        self.assertEqual(
            self.app.output_queue.get_nowait(),
            ("finished", "success"),
        )

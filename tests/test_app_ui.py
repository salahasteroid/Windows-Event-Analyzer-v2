import queue
from threading import Event
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import Mock

from modules.app_ui import EventAnalyzerApp


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

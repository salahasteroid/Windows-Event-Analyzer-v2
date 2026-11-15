from threading import Event
from datetime import datetime, timezone
from unittest import TestCase
from unittest.mock import patch

from modules.evtx_reader import read_evtx
from modules.event_reader import get_recent_events


EVENT_NAMESPACE = "http://schemas.microsoft.com/win/2004/08/events/event"


def make_event(event_id, timestamp, level=2):
    return (
        f'<Event xmlns="{EVENT_NAMESPACE}"><System>'
        '<Provider Name="Test-Provider"/>'
        f"<EventID>{event_id}</EventID><Level>{level}</Level>"
        f'<TimeCreated SystemTime="{timestamp}"/>'
        "<Computer>TEST-PC</Computer>"
        "</System><EventData/></Event>"
    )


class FakeRecord:

    def __init__(self, xml_data):
        self.xml_data = xml_data
        self.read_count = 0

    def xml(self):
        self.read_count += 1
        return self.xml_data


class FakeLog:

    def __init__(self, records):
        self._records = records

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def records(self):
        return iter(self._records)


class EventReaderTests(TestCase):

    def test_live_reader_stops_before_query_when_cancelled(self):
        cancellation_event = Event()
        cancellation_event.set()

        with patch("modules.event_reader.win32evtlog.EvtQuery") as query:
            events = get_recent_events(
                cancellation_event=cancellation_event
            )

        self.assertEqual(events, [])
        query.assert_not_called()

    def test_live_reader_stops_between_records_after_cancel_signal(self):
        cancellation_event = Event()
        records = [object(), object()]

        def render_event(*_args):
            cancellation_event.set()
            return make_event(42, "2026-11-14T19:30:00Z")

        with (
            patch("modules.event_reader.win32evtlog.EvtQuery"),
            patch(
                "modules.event_reader.win32evtlog.EvtNext",
                return_value=records,
            ),
            patch(
                "modules.event_reader.win32evtlog.EvtRender",
                side_effect=render_event,
            ) as render,
        ):
            events = get_recent_events(
                cancellation_event=cancellation_event
            )

        self.assertEqual([event["EventID"] for event in events], [42])
        render.assert_called_once()

    def test_evtx_reader_stops_before_reading_records_when_cancelled(self):
        cancellation_event = Event()
        cancellation_event.set()
        record = FakeRecord(make_event(1, "2026-11-14T19:30:00Z"))

        with patch(
            "modules.evtx_reader.Evtx",
            return_value=FakeLog([record]),
        ):
            events = read_evtx(
                "sample.evtx",
                cancellation_event=cancellation_event,
            )

        self.assertEqual(events, [])
        self.assertEqual(record.read_count, 0)

    def test_evtx_reader_returns_all_events_in_requested_range(self):
        start = datetime(2026, 11, 14, 19, tzinfo=timezone.utc)
        end = datetime(2026, 11, 14, 20, tzinfo=timezone.utc)
        records = [
            FakeRecord(make_event(1, "2026-11-14T18:59:59Z")),
            FakeRecord(make_event(2, "2026-11-14T19:00:00Z")),
            FakeRecord(make_event(3, "2026-11-14T19:30:00Z", level=3)),
            FakeRecord(make_event(4, "2026-11-14T20:00:00Z")),
            FakeRecord(make_event(5, "2026-11-14T20:00:01Z")),
        ]

        with patch(
            "modules.evtx_reader.Evtx",
            return_value=FakeLog(records),
        ):
            events = read_evtx(
                "sample.evtx",
                start_time=start,
                end_time=end,
                levels=(2,),
            )

        self.assertEqual(
            [event["EventID"] for event in events],
            [2, 4],
        )

    def test_live_reader_uses_time_bounded_xpath_query(self):
        start = datetime(2026, 11, 13, 20, tzinfo=timezone.utc)
        end = datetime(2026, 11, 14, 20, tzinfo=timezone.utc)
        record = object()

        with (
            patch("modules.event_reader.win32evtlog.EvtQuery") as query,
            patch(
                "modules.event_reader.win32evtlog.EvtNext",
                side_effect=[[record], []],
            ),
            patch(
                "modules.event_reader.win32evtlog.EvtRender",
                return_value=make_event(
                    42,
                    "2026-11-14T19:30:00Z",
                    level=3,
                ),
            ),
        ):
            events = get_recent_events(
                start_time=start,
                end_time=end,
                levels=(1, 3),
            )

        query.assert_called_once()
        xpath = query.call_args.args[2]
        self.assertIn("2026-11-13T20:00:00.000000Z", xpath)
        self.assertIn("2026-11-14T20:00:00.000000Z", xpath)
        self.assertIn("(Level=1 or Level=3)", xpath)
        self.assertEqual([event["EventID"] for event in events], [42])

    def test_remote_reader_uses_ephemeral_credentials_in_rpc_session(self):
        start = datetime(2026, 11, 13, 20, tzinfo=timezone.utc)
        end = datetime(2026, 11, 14, 20, tzinfo=timezone.utc)
        session = object()
        remote_options = {
            "computer": "192.0.2.10",
            "username": "event-reader",
            "domain": "CONTOSO",
            "password": "test-only-password",
        }

        with (
            patch(
                "modules.event_reader.win32evtlog.EvtOpenSession",
                return_value=session,
            ) as open_session,
            patch("modules.event_reader.win32evtlog.EvtQuery") as query,
            patch(
                "modules.event_reader.win32evtlog.EvtNext",
                return_value=[],
            ),
        ):
            get_recent_events(
                start_time=start,
                end_time=end,
                levels=(2,),
                remote_options=remote_options,
            )

        login = open_session.call_args.args[0]
        self.assertEqual(login[:4], (
            "192.0.2.10",
            "event-reader",
            "CONTOSO",
            "test-only-password",
        ))
        self.assertEqual(
            query.call_args.args[3],
            session,
        )

    def test_remote_local_account_can_leave_domain_blank(self):
        session = object()
        remote_options = {
            "computer": "192.0.2.10",
            "username": "local-reader",
            "domain": None,
            "password": "test-only-password",
        }

        with (
            patch(
                "modules.event_reader.win32evtlog.EvtOpenSession",
                return_value=session,
            ) as open_session,
            patch("modules.event_reader.win32evtlog.EvtQuery"),
            patch(
                "modules.event_reader.win32evtlog.EvtNext",
                return_value=[],
            ),
        ):
            get_recent_events(remote_options=remote_options)

        login = open_session.call_args.args[0]
        self.assertEqual(login[1], "local-reader")
        self.assertIsNone(login[2])

    def test_remote_session_failure_never_falls_back_to_local_log(self):
        with (
            patch(
                "modules.event_reader.win32evtlog.EvtOpenSession",
                return_value=None,
            ),
            patch("modules.event_reader.win32evtlog.EvtQuery") as query,
        ):
            with self.assertRaisesRegex(
                RuntimeError,
                "Could not open the remote Event Log session",
            ):
                get_recent_events(
                    remote_options={
                        "computer": "192.0.2.10",
                        "username": "event-reader",
                        "password": "test-only-password",
                    }
                )

        query.assert_not_called()

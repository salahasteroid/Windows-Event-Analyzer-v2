from datetime import datetime, timedelta, timezone
from unittest import TestCase

from modules.time_range import parse_event_time, resolve_time_range


class TimeRangeTests(TestCase):

    def test_default_range_covers_previous_24_hours(self):
        fixed_end = datetime(2026, 11, 14, 20, tzinfo=timezone.utc)

        start, end = resolve_time_range(end_time=fixed_end)

        self.assertEqual(end, fixed_end)
        self.assertEqual(end - start, timedelta(hours=24))

    def test_rejects_start_after_end(self):
        with self.assertRaises(ValueError):
            resolve_time_range(
                datetime(2026, 11, 14, 20, tzinfo=timezone.utc),
                datetime(2026, 11, 14, 19, tzinfo=timezone.utc),
            )

    def test_parses_windows_timestamp_with_seven_fractional_digits(self):
        event_time = parse_event_time(
            "2026-11-14T19:50:51.7531445Z"
        )

        self.assertEqual(
            event_time,
            datetime(
                2026,
                11,
                14,
                19,
                50,
                51,
                753144,
                tzinfo=timezone.utc,
            ),
        )

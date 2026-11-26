import json
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase

from modules.trend_engine import (
    MAX_HISTORY_RUNS,
    compare_with_history,
    load_history,
    record_run,
)


DAY = 86400


def events(*pairs):
    """pairs of (source, event_id, count)"""
    return [
        {"EventID": event_id, "Source": source}
        for source, event_id, count in pairs
        for _ in range(count)
    ]


def moment(day):
    return datetime(2026, 11, day, 8, 0, tzinfo=timezone.utc)


class TrendEngineTests(TestCase):

    def setUp(self):
        self.directory = TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.history = Path(self.directory.name) / "history.json"

    def test_first_run_has_nothing_to_compare(self):
        result = compare_with_history(events(("A", 1, 3)), DAY, self.history, levels=[1, 2, 3])

        self.assertFalse(result["available"])
        self.assertIn("starting point", result["message"])

    def test_new_resolved_increased_and_decreased(self):
        record_run(
            events(("A", 1, 2), ("B", 2, 10), ("C", 3, 10), ("D", 4, 4)),
            DAY, self.history, levels=[1, 2], now=moment(1)
        )

        result = compare_with_history(
            events(("A", 1, 2), ("B", 2, 30), ("C", 3, 2), ("E", 5, 1)),
            DAY, self.history, levels=[1, 2]
        )

        self.assertTrue(result["available"])
        self.assertEqual([e["event_id"] for e in result["new"]], ["5"])
        self.assertEqual([e["event_id"] for e in result["increased"]], ["2"])
        self.assertEqual([e["event_id"] for e in result["decreased"]], ["3"])
        self.assertEqual([e["event_id"] for e in result["resolved"]], ["4"])
        self.assertEqual(result["previous_run"], "2026-11-01 08:00 UTC")

    def test_small_changes_are_not_reported(self):
        record_run(events(("A", 1, 10)), DAY, self.history, levels=[2], now=moment(1))

        result = compare_with_history(events(("A", 1, 11)), DAY, self.history, levels=[2])

        self.assertEqual(result["increased"], [])
        self.assertEqual(result["decreased"], [])

    def test_counts_are_compared_per_day(self):
        record_run(events(("A", 1, 10)), DAY, self.history, levels=[2], now=moment(1))

        # 10 events in a 2-day window is the same rate as 5 in one day
        result = compare_with_history(events(("A", 1, 10)), 2 * DAY, self.history, levels=[2])
        self.assertEqual(result["decreased"][0]["event_id"], "1")

        # 10 events in 12 hours is double the earlier rate
        result = compare_with_history(events(("A", 1, 10)), DAY / 2, self.history, levels=[2])
        self.assertEqual(result["increased"][0]["event_id"], "1")

    def test_runs_with_other_level_filters_are_not_compared(self):
        record_run(events(("A", 1, 5)), DAY, self.history, levels=[1], now=moment(1))

        result = compare_with_history(events(("A", 1, 5)), DAY, self.history, levels=[1, 2, 3])

        self.assertFalse(result["available"])

    def test_most_recent_comparable_run_is_used(self):
        record_run(events(("A", 1, 1)), DAY, self.history, levels=[2], now=moment(1))
        record_run(events(("A", 1, 1), ("B", 2, 1)), DAY, self.history, levels=[2], now=moment(2))
        record_run(events(("Z", 9, 1)), DAY, self.history, levels=[1], now=moment(3))

        result = compare_with_history(events(("A", 1, 1), ("B", 2, 1)), DAY, self.history, levels=[2])

        self.assertEqual(result["previous_run"], "2026-11-02 08:00 UTC")
        self.assertEqual(result["new"], [])

    def test_source_names_containing_a_bar_survive(self):
        record_run(events(("Odd|Name", 7, 1)), DAY, self.history, levels=[2], now=moment(1))

        result = compare_with_history([], DAY, self.history, levels=[2])

        self.assertEqual(result["resolved"][0]["source"], "Odd|Name")
        self.assertEqual(result["resolved"][0]["event_id"], "7")

    def test_history_is_trimmed(self):
        for index in range(MAX_HISTORY_RUNS + 5):
            record_run(events(("A", 1, 1)), DAY, self.history, levels=[2], now=moment(1))

        self.assertEqual(len(load_history(self.history)), MAX_HISTORY_RUNS)

    def test_damaged_history_file_starts_over(self):
        self.history.write_text("{not json", encoding="utf-8")

        self.assertEqual(load_history(self.history), [])
        self.assertTrue(record_run(events(("A", 1, 1)), DAY, self.history, levels=[2]))
        self.assertEqual(len(load_history(self.history)), 1)

    def test_invalid_runs_in_the_file_are_ignored(self):
        self.history.write_text(
            json.dumps({"runs": [{"counts": "bad"}, {"counts": {}, "window_seconds": 0}]}),
            encoding="utf-8"
        )

        self.assertEqual(load_history(self.history), [])

    def test_unwritable_location_does_not_raise(self):
        blocked = Path(self.directory.name) / "file"
        blocked.write_text("x")

        saved = record_run(events(("A", 1, 1)), DAY, blocked / "history.json", levels=[2])

        self.assertFalse(saved)

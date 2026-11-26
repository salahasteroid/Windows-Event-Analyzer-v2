from unittest import TestCase

from modules import rules_engine
from modules.database_loader import load_rules_database
from modules.rules_engine import (
    NO_FINDINGS_TEXT,
    NO_RECOMMENDATIONS_TEXT,
    compile_rules,
    evaluate_rules,
    findings_from,
    recommendations_from,
)


KERNEL_POWER = "Microsoft-Windows-Kernel-Power"


def event(event_id, source, time="2026-11-14T10:00:00Z", level=2):
    return {
        "EventID": event_id,
        "Source": source,
        "Time": time,
        "Level": level,
    }


def ids(matches):
    return [match["id"] for match in matches]


class RulesFileTests(TestCase):

    def test_shipped_rules_are_all_valid(self):
        rules, errors = compile_rules(load_rules_database())

        self.assertEqual(errors, [])
        self.assertGreaterEqual(len(rules), 20)

    def test_suppressed_rule_ids_exist(self):
        rules, _ = compile_rules(load_rules_database())
        known = {rule["id"] for rule in rules}

        for rule in rules:
            for suppressed in rule["suppresses"]:
                self.assertIn(suppressed, known, rule["id"])

    def test_invalid_rules_are_reported_and_skipped(self):
        data = {"rules": [
            {"id": "ok", "finding": "x", "any_of": [1]},
            {"id": "no-events", "finding": "x"},
            {"id": "both", "finding": "x", "any_of": [1], "all_of": [2]},
            {"id": "bad-count", "finding": "x", "any_of": [1], "min_count": 0},
            {"id": "ok", "finding": "duplicate", "any_of": [1]},
            {"finding": "no id", "any_of": [1]},
            {"id": "bad-spec", "finding": "x", "any_of": ["41"]},
        ]}

        rules, errors = compile_rules(data)

        self.assertEqual([rule["id"] for rule in rules], ["ok"])
        self.assertEqual(len(errors), 6)

    def test_missing_rules_list_is_an_error(self):
        rules, errors = compile_rules({})

        self.assertEqual(rules, [])
        self.assertEqual(len(errors), 1)


class EvaluateRulesTests(TestCase):

    def test_no_events_gives_default_texts(self):
        matches = evaluate_rules([])

        self.assertEqual(matches, [])
        self.assertEqual(findings_from(matches), [NO_FINDINGS_TEXT])
        self.assertEqual(
            recommendations_from(matches),
            [NO_RECOMMENDATIONS_TEXT]
        )

    def test_power_pair_inside_window_hides_the_single_rules(self):
        matches = evaluate_rules([
            event(41, KERNEL_POWER, "2026-11-14T10:00:00Z"),
            event(6008, "EventLog", "2026-11-14T10:05:00Z"),
        ])

        self.assertEqual(ids(matches), ["power-loss-pattern"])

    def test_power_events_far_apart_are_reported_separately(self):
        matches = evaluate_rules([
            event(41, KERNEL_POWER, "2026-11-14T01:00:00Z"),
            event(6008, "EventLog", "2026-11-14T20:00:00Z"),
        ])

        self.assertEqual(
            sorted(ids(matches)),
            ["kernel-power-only", "unexpected-shutdown-only"]
        )

    def test_same_id_from_another_provider_does_not_match(self):
        matches = evaluate_rules([event(41, "Some-Other-Provider")])

        self.assertEqual(matches, [])

    def test_source_match_ignores_case(self):
        matches = evaluate_rules([event(7, "DISK")])

        self.assertEqual(ids(matches), ["disk-bad-blocks"])

    def test_disk_and_ntfs_together_beat_the_single_rules(self):
        matches = evaluate_rules([
            event(7, "disk", "2026-11-14T10:00:00Z"),
            event(55, "Ntfs", "2026-11-14T10:30:00Z"),
        ])

        self.assertEqual(ids(matches), ["disk-ntfs-chain"])
        self.assertEqual(matches[0]["score_penalty"], 20)

    def test_disk_only_and_ntfs_only(self):
        self.assertEqual(
            ids(evaluate_rules([event(7, "disk")])),
            ["disk-bad-blocks"]
        )
        self.assertEqual(
            ids(evaluate_rules([event(55, "Ntfs")])),
            ["ntfs-corruption"]
        )

    def test_any_of_needs_min_count(self):
        sources = "Service Control Manager"

        two = [event(7034, sources), event(7031, sources)]
        three = two + [event(7034, sources)]

        self.assertNotIn("service-crashes", ids(evaluate_rules(two)))
        self.assertIn("service-crashes", ids(evaluate_rules(three)))

    def test_events_without_time_ignore_the_window(self):
        matches = evaluate_rules([
            {"EventID": 41, "Source": KERNEL_POWER},
            {"EventID": 6008, "Source": "EventLog"},
        ])

        self.assertEqual(ids(matches), ["power-loss-pattern"])

    def test_results_are_ordered_by_severity(self):
        matches = evaluate_rules([
            event(10016, "Microsoft-Windows-DistributedCOM", level=3),
            event(52, "disk"),
        ])

        self.assertEqual(ids(matches), ["smart-failure-predicted", "dcom-noise"])

    def test_recommendations_are_not_repeated(self):
        rules, _ = compile_rules({"rules": [
            {"id": "a", "finding": "A", "any_of": [1], "recommendations": ["Do X", "Do Y"]},
            {"id": "b", "finding": "B", "any_of": [1], "recommendations": ["Do Y", "Do Z"]},
        ]})

        matches = evaluate_rules([{"EventID": 1}], rules=rules)

        self.assertEqual(
            recommendations_from(matches),
            ["Do X", "Do Y", "Do Z"]
        )

    def test_all_of_with_min_count_inside_window(self):
        rules, _ = compile_rules({"rules": [
            {"id": "r", "finding": "R", "all_of": [1, 2], "min_count": 2, "window_minutes": 10},
        ]})

        inside = [
            event(1, "s", "2026-11-14T10:00:00Z"),
            event(1, "s", "2026-11-14T10:02:00Z"),
            event(2, "s", "2026-11-14T10:03:00Z"),
            event(2, "s", "2026-11-14T10:04:00Z"),
        ]
        spread = [
            event(1, "s", "2026-11-14T10:00:00Z"),
            event(1, "s", "2026-11-14T10:02:00Z"),
            event(2, "s", "2026-11-14T12:03:00Z"),
            event(2, "s", "2026-11-14T12:04:00Z"),
        ]

        self.assertEqual(ids(evaluate_rules(inside, rules=rules)), ["r"])
        self.assertEqual(evaluate_rules(spread, rules=rules), [])

    def test_load_rules_reads_the_shipped_file_once(self):
        first = rules_engine.load_rules()
        second = rules_engine.load_rules()

        self.assertIs(first, second)

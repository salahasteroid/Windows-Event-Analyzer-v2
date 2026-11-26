from unittest import TestCase

from modules.health_score import (
    calculate_health_score,
    explain_health_score,
    get_health_settings,
)


def event(event_id, source, level=2, count=1):
    return [
        {
            "EventID": event_id,
            "Source": source,
            "Level": level,
            "Time": "2026-11-14T10:00:00Z",
        }
        for _ in range(count)
    ]


class HealthScoreTests(TestCase):

    def test_no_events_is_perfect(self):
        self.assertEqual(calculate_health_score([]), 100)

    def test_information_events_do_not_lower_the_score(self):
        events = event(19, "Microsoft-Windows-WindowsUpdateClient", level=4, count=50)

        self.assertEqual(calculate_health_score(events), 100)

    def test_unknown_critical_events_lower_the_score(self):
        # The old score ignored every event outside a handful of IDs.
        events = event(9999, "Some-Vendor-Service", level=1, count=20)

        self.assertLess(calculate_health_score(events), 100)

    def test_a_repeating_problem_costs_more_than_a_single_one(self):
        single = calculate_health_score(event(41, "Microsoft-Windows-Kernel-Power", 1))
        repeated = calculate_health_score(event(41, "Microsoft-Windows-Kernel-Power", 1, count=3))

        self.assertLess(repeated, single)

    def test_repeats_are_capped(self):
        three = calculate_health_score(event(41, "Microsoft-Windows-Kernel-Power", 1, count=3))
        many = calculate_health_score(event(41, "Microsoft-Windows-Kernel-Power", 1, count=500))

        self.assertEqual(three, many)

    def test_one_noisy_provider_cannot_zero_the_score(self):
        events = []

        for event_id in range(1000, 1040):
            events += event(event_id, "Noisy-Provider", level=1, count=30)

        score = calculate_health_score(events)
        cap = get_health_settings()["per_source_cap"]

        self.assertEqual(score, round(100 - cap))

    def test_two_different_providers_add_up(self):
        one = calculate_health_score(event(9001, "Provider-A", 1))
        two = calculate_health_score(
            event(9001, "Provider-A", 1) + event(9002, "Provider-B", 1)
        )

        self.assertLess(two, one)

    def test_disk_failure_chain_is_critical(self):
        events = event(7, "disk") + event(55, "Ntfs")

        self.assertLess(calculate_health_score(events), 50)

    def test_single_unexpected_reboot_is_moderate(self):
        events = (
            event(41, "Microsoft-Windows-Kernel-Power", 1)
            + event(6008, "EventLog")
        )

        self.assertTrue(50 <= calculate_health_score(events) < 80)

    def test_score_stays_between_0_and_100(self):
        events = []

        for event_id in range(2000, 2200):
            events += event(event_id, f"Provider-{event_id}", level=1, count=5)

        self.assertEqual(calculate_health_score(events), 0)

    def test_explanation_lists_the_largest_deduction_first(self):
        events = (
            event(52, "disk")
            + event(10016, "Microsoft-Windows-DistributedCOM", 3)
        )

        details = explain_health_score(events)

        self.assertEqual(details["events"][0]["event_id"], 52)
        self.assertEqual(details["rules"][0]["rule_id"], "smart-failure-predicted")
        self.assertEqual(details["score"], calculate_health_score(events))

    def test_events_without_level_are_scored_from_their_definition(self):
        events = [{"EventID": 7, "Source": "disk"}]

        self.assertLess(calculate_health_score(events), 100)

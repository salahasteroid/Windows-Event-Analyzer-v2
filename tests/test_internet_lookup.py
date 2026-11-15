import json
from io import BytesIO
from unittest import TestCase
from unittest.mock import patch

from modules.internet_lookup import lookup_event, lookup_events


class InternetLookupTests(TestCase):

    @patch("modules.internet_lookup.urlopen")
    def test_returns_matching_microsoft_learn_result(self, urlopen):
        api_response = BytesIO(json.dumps({
            "results": [{
                "title": (
                    "Event ID 41 The system has rebooted unexpectedly"
                ),
                "description": "Windows restarted without a clean shutdown.",
                "url": (
                    "https://learn.microsoft.com/en-us/"
                    "troubleshoot/windows-client/event-41"
                )
            }]
        }).encode("utf-8"))
        article_response = BytesIO(
            b"<html><head><meta name='description' "
            b"content='A clean event summary.'></head>"
            b"<main><h2>Cause</h2><p>It restarted unexpectedly.</p>"
            b"<h2>Resolution</h2><p>Check the shutdown history.</p></main>"
            b"</html>"
        )
        urlopen.side_effect = [api_response, article_response]

        result = lookup_event(41, "Microsoft-Windows-Kernel-Power")

        self.assertEqual(result["status"], "found")
        self.assertIn("Event ID 41", result["title"])
        self.assertEqual(result["summary"], "A clean event summary.")
        self.assertEqual(result["cause"], "It restarted unexpectedly.")
        self.assertEqual(result["resolution"], "Check the shutdown history.")
        self.assertTrue(result["url"].startswith("https://learn.microsoft.com/"))

    @patch("modules.internet_lookup.urlopen")
    def test_matches_event_title_without_the_id_word(self, urlopen):
        api_response = BytesIO(json.dumps({
            "results": [{
                "title": "Event 10317 when turning on mobile broadband",
                "description": "A network miniport event.",
                "url": (
                    "https://learn.microsoft.com/en-us/"
                    "troubleshoot/windows-client/event-10317"
                )
            }]
        }).encode("utf-8"))
        article_response = BytesIO(
            b"<main>"
            b"<h2>Cause</h2><p>The device did not respond within 400 ms.</p>"
            b"<h2>Resolution</h2>"
            b"<p>Ignore these errors when the device starts or resumes.</p>"
            b"</main>"
        )
        urlopen.side_effect = [api_response, article_response]

        result = lookup_event(10317, "Microsoft-Windows-NDIS")

        self.assertEqual(result["status"], "found")
        self.assertIn("400 ms", result["cause"])
        self.assertIn("when the device starts", result["resolution"])

    @patch("modules.internet_lookup.urlopen")
    def test_rejects_result_for_a_different_event_id(self, urlopen):
        response = BytesIO(json.dumps({
            "results": [{
                "title": "Event ID 42 unrelated event",
                "description": "This result is for another event.",
                "url": "https://learn.microsoft.com/en-us/unrelated"
            }]
        }).encode("utf-8"))
        urlopen.return_value.__enter__.return_value = response

        result = lookup_event(41, "Test-Provider")

        self.assertEqual(result["status"], "no_match")

    @patch("modules.internet_lookup.lookup_event")
    def test_looks_up_each_unique_event_once(self, lookup):
        lookup.return_value = {"status": "no_match"}
        events = [
            {"EventID": 41, "Source": "Kernel-Power"},
            {"EventID": 41, "Source": "Kernel-Power"},
            {"EventID": 6008, "Source": "EventLog"}
        ]

        results = lookup_events(events)

        self.assertEqual(lookup.call_count, 2)
        self.assertEqual(
            results[(41, "Kernel-Power")]["status"],
            "no_match"
        )

    @patch("modules.internet_lookup.lookup_event")
    def test_limits_online_requests_for_large_logs(self, lookup):
        lookup.return_value = {"status": "no_match"}
        events = [
            {"EventID": event_id, "Source": "Test-Provider"}
            for event_id in range(25)
        ]

        results = lookup_events(events)

        self.assertEqual(lookup.call_count, 20)
        self.assertEqual(
            sum(result["status"] == "skipped" for result in results.values()),
            5
        )

from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase

from modules.dashboard_generator import generate_dashboard
from modules.report_generator import generate_html_report


def report_event(analysis):
    return {
        "EventID": 20,
        "Source": "Microsoft-Windows-WindowsUpdateClient",
        "LevelName": "Error",
        "Time": "2026-11-14T10:00:00Z",
        "Data": [],
        "Message": "",
        "Analysis": analysis,
    }


BASE_ANALYSIS = {
    "severity_text": "MEDIUM",
    "cause": "cause",
    "online_lookup": {"status": "skipped", "search_url": ""},
}


class ReportTests(TestCase):

    def test_report_lists_every_error_code(self):
        analysis = dict(BASE_ANALYSIS, error_codes=[
            {"code": "0x80070005", "description": "Access denied"},
            {"code": "0x80070002", "description": "File not found"},
        ])

        with TemporaryDirectory() as directory:
            generate_html_report([report_event(analysis)], output_dir=directory)
            html = (Path(directory) / "event_report.html").read_text(encoding="utf-8")

        for text in ("0x80070005", "Access denied", "0x80070002", "File not found"):
            self.assertIn(text, html)

    def test_report_still_supports_a_single_error_code(self):
        analysis = dict(BASE_ANALYSIS, error_code="0xC0000005", error_description="Access violation")

        with TemporaryDirectory() as directory:
            generate_html_report([report_event(analysis)], output_dir=directory)
            html = (Path(directory) / "event_report.html").read_text(encoding="utf-8")

        self.assertIn("0xC0000005", html)

    def test_report_escapes_error_text(self):
        analysis = dict(BASE_ANALYSIS, error_codes=[
            {"code": "<b>x</b>", "description": "<script>alert(1)</script>"},
        ])

        with TemporaryDirectory() as directory:
            generate_html_report([report_event(analysis)], output_dir=directory)
            html = (Path(directory) / "event_report.html").read_text(encoding="utf-8")

        self.assertNotIn("<script>", html)
        self.assertNotIn("<b>x</b>", html)


class DashboardTests(TestCase):

    def build(self, **kwargs):
        with TemporaryDirectory() as directory:
            generate_dashboard(
                [report_event(BASE_ANALYSIS)],
                80,
                ["finding"],
                ["action"],
                output_dir=directory,
                **kwargs
            )
            return (Path(directory) / "dashboard.html").read_text(encoding="utf-8")

    def test_works_without_the_new_sections(self):
        html = self.build()

        self.assertIn("80%", html)
        self.assertNotIn("What lowered the score", html)
        self.assertNotIn("<h2>Trends</h2>", html)

    def test_shows_score_breakdown(self):
        html = self.build(score_breakdown={
            "events": [{"source": "disk", "event_id": 7, "count": 2, "severity": 95, "penalty": 36.2}],
            "rules": [{"rule_id": "r", "title": "Disk chain", "penalty": 20.0}],
        })

        self.assertIn("What lowered the score", html)
        self.assertIn("disk Event 7", html)
        self.assertIn("Disk chain", html)

    def test_shows_trends_and_escapes_them(self):
        html = self.build(trends={
            "available": True,
            "message": "Compared.",
            "new": [{"source": "<script>x</script>", "event_id": "5", "count": 3, "previous_count": 0}],
            "increased": [], "decreased": [], "resolved": [],
        })

        self.assertIn("New since the previous run", html)
        self.assertNotIn("<script>x</script>", html)

    def test_trends_when_nothing_to_compare(self):
        html = self.build(trends={"available": False, "message": "Starting point."})

        self.assertIn("Starting point.", html)


class ReportLayoutTests(TestCase):

    def render(self, events):
        with TemporaryDirectory() as directory:
            generate_html_report(events, output_dir=directory)
            return (Path(directory) / "event_report.html").read_text(encoding="utf-8")

    def event(self, event_id, severity, count_time, **analysis):
        event = report_event(dict(
            BASE_ANALYSIS, severity=severity, name=f"Problem {event_id}",
            severity_text="HIGH" if severity >= 70 else "LOW",
            solutions=["Do the first thing"], **analysis))
        event["EventID"] = event_id
        event["Time"] = count_time
        return event

    def test_one_card_per_problem_worst_first_with_count(self):
        events = [
            self.event(1, 10, "2026-11-14T10:00:00Z"),
            self.event(2, 90, "2026-11-14T09:00:00Z"),
            self.event(1, 10, "2026-11-14T11:00:00Z"),
        ]
        html = self.render(events)

        self.assertEqual(html.count('<article class="card'), 2)
        self.assertLess(html.index("Problem 2"), html.index("Problem 1"))
        self.assertIn("seen 2 times", html)
        self.assertIn("Do the first thing", html)
        self.assertIn("Start here", html)

    def test_confidence_and_alternatives_are_shown_and_links_checked(self):
        html = self.render([self.event(
            1, 90, "2026-11-14T09:00:00Z",
            online_lookup={
                "status": "found", "title": "Article", "summary": "S",
                "url": "https://learn.microsoft.com/a", "confidence": "medium",
                "confidence_note": "Check it fits.",
                "alternatives": [
                    {"title": "Other", "url": "https://learn.microsoft.com/b"},
                    {"title": "Bad", "url": "javascript:alert(1)"},
                ],
            })])

        self.assertIn("Related - check it fits", html)
        self.assertIn("Check it fits.", html)
        self.assertIn('href="https://learn.microsoft.com/b"', html)
        self.assertNotIn("javascript:", html)

    def test_offline_message_is_friendly(self):
        html = self.render([self.event(
            1, 90, "2026-11-14T09:00:00Z",
            online_lookup={"status": "error", "error": "timed out"})])

        self.assertIn("Could not reach Microsoft Learn", html)
        self.assertIn("timed out", html)

    def test_no_events_gives_a_message(self):
        self.assertIn("No events matched", self.render([]))

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

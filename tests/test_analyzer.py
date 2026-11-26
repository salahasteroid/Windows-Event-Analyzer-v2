from unittest import TestCase

from modules.analyzer import analyze_event, find_error_codes


OFFLINE = {"status": "skipped", "search_url": "https://example.test/search"}


def analyze(event):
    return analyze_event(event, OFFLINE)


class DefinitionLookupTests(TestCase):

    def test_same_id_resolves_by_provider(self):
        update = analyze({
            "EventID": 19,
            "Source": "Microsoft-Windows-WindowsUpdateClient",
            "Level": 4,
        })
        hardware = analyze({
            "EventID": 19,
            "Source": "Microsoft-Windows-WHEA-Logger",
            "Level": 3,
        })

        self.assertEqual(update["name"], "Windows Update Successful Installation")
        self.assertEqual(hardware["name"], "Corrected hardware error (WHEA)")

    def test_known_id_from_another_provider_is_unknown(self):
        result = analyze({"EventID": 41, "Source": "Other-Provider", "Level": 2})

        self.assertFalse(result["known"])

    def test_unknown_event_severity_follows_the_level(self):
        critical = analyze({"EventID": 99999, "Source": "X", "Level": 1})
        error = analyze({"EventID": 99999, "Source": "X", "Level": 2})
        warning = analyze({"EventID": 99999, "Source": "X", "Level": 3})

        self.assertEqual(critical["severity_text"], "HIGH")
        self.assertEqual(error["severity_text"], "MEDIUM")
        self.assertEqual(warning["severity_text"], "LOW")
        self.assertIn("triage estimate", critical["severity_basis"])

    def test_known_event_keeps_its_definition(self):
        result = analyze({
            "EventID": 41,
            "Source": "Microsoft-Windows-Kernel-Power",
            "Level": 1,
        })

        self.assertTrue(result["known"])
        self.assertEqual(result["severity_text"], "CRITICAL")
        self.assertEqual(result["online_lookup"], OFFLINE)

    def test_definition_is_not_shared_between_calls(self):
        event = {"EventID": 41, "Source": "Microsoft-Windows-Kernel-Power"}

        analyze(event)["solutions"].append("changed")

        self.assertNotIn("changed", analyze(event)["solutions"])


class ErrorCodeTests(TestCase):

    def test_every_known_code_in_the_event_is_reported(self):
        event = {
            "EventID": 20,
            "Source": "Microsoft-Windows-WindowsUpdateClient",
            "Data": [
                {"name": "updateTitle", "value": "Some update"},
                {"name": "errorCode", "value": "0x80070005"},
                {"name": "second", "value": "0x80070002"},
            ],
        }

        result = analyze(event)

        self.assertEqual(
            [item["code"] for item in result["error_codes"]],
            ["0x80070005", "0x80070002"]
        )
        self.assertEqual(result["error_code"], "0x80070005")
        self.assertEqual(result["error_description"], "Access denied")

    def test_hex_case_does_not_matter(self):
        codes = find_error_codes({
            "EventID": 20,
            "Data": [{"name": "c", "value": "0X8007000e"}],
        })

        self.assertEqual(codes[0]["description"], "Not enough memory")

    def test_unknown_codes_are_skipped(self):
        self.assertEqual(
            find_error_codes({"EventID": 20, "Data": [{"name": "c", "value": "0x12345678"}]}),
            []
        )

    def test_same_code_is_listed_once(self):
        codes = find_error_codes({
            "EventID": 20,
            "Data": [
                {"name": "a", "value": "0x80070005"},
                {"name": "b", "value": "0x80070005"},
            ],
        })

        self.assertEqual(len(codes), 1)

    def test_bugcheck_codes_only_apply_to_event_1001(self):
        data = [{"name": "param1", "value": "0x00000133 (0x0, 0x1, 0x2, 0x3)"}]

        crash = find_error_codes({"EventID": 1001, "Data": data})
        other = find_error_codes({"EventID": 7000, "Data": data})

        self.assertEqual(crash[0]["description"], "Bugcheck DPC_WATCHDOG_VIOLATION")
        self.assertEqual(other, [])

    def test_decimal_bugcheck_code_is_converted(self):
        codes = find_error_codes({
            "EventID": 1001,
            "Data": [{"name": "BugcheckCode", "value": "307"}],
        })

        self.assertEqual(codes[0]["code"], "0x00000133")

    def test_plain_string_data_items_are_supported(self):
        codes = find_error_codes({"EventID": 20, "Data": ["0x80070005"]})

        self.assertEqual(len(codes), 1)

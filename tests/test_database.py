import json
from unittest import TestCase
from unittest.mock import patch

from database.error_code_lookup import get_error_info
from modules import database_loader
from modules.database_loader import (
    clear_database_cache,
    load_error_code_database,
    load_event_database,
    normalize_error_code,
)
from modules.event_catalog import find_event_definition
from modules.paths import resource_path


class EventDefinitionFileTests(TestCase):

    def setUp(self):
        with open(
            resource_path("database", "event_definitions.json"),
            encoding="utf-8"
        ) as file:
            self.raw = json.load(file)

    def definitions(self):
        for event_id, entry in self.raw.items():
            for definition in (entry if isinstance(entry, list) else [entry]):
                yield event_id, definition

    def test_every_definition_is_complete(self):
        for event_id, definition in self.definitions():
            label = f"event {event_id}"

            self.assertTrue(event_id.isdigit(), label)
            self.assertTrue(definition["name"].strip(), label)
            self.assertTrue(definition["cause"].strip(), label)
            self.assertTrue(0 <= definition["severity"] <= 100, label)
            self.assertTrue(definition["solutions"], label)
            self.assertTrue(definition["sources"], label)

    def test_no_provider_is_defined_twice_for_one_id(self):
        seen = set()

        for event_id, definition in self.definitions():
            for source in definition["sources"]:
                key = (event_id, source.casefold())
                self.assertNotIn(key, seen)
                seen.add(key)

    def test_ids_shared_by_providers_are_stored_as_lists(self):
        for event_id in ("19", "36", "129"):
            self.assertIsInstance(self.raw[event_id], list)

    def test_catalog_covers_a_broad_set_of_events(self):
        self.assertGreaterEqual(len(self.raw), 50)


class ErrorCodeFileTests(TestCase):

    def test_every_entry_is_complete_and_normalized(self):
        with open(
            resource_path("database", "error_codes.json"),
            encoding="utf-8"
        ) as file:
            raw = json.load(file)

        for code, info in raw.items():
            self.assertEqual(normalize_error_code(code), code)
            self.assertTrue(info["description"].strip(), code)
            self.assertTrue(info["recommendation"].strip(), code)

    def test_original_entries_are_kept(self):
        self.assertEqual(
            get_error_info("0x80073D02")["description"],
            "Application currently in use"
        )


class NormalizeErrorCodeTests(TestCase):

    def test_spellings(self):
        for value in ("0x80070005", "0X80070005", " 0x80070005 ", "0x80070005 (extra)"):
            self.assertEqual(normalize_error_code(value), "0x80070005")

        self.assertEqual(normalize_error_code("0x5"), "0x00000005")

    def test_non_codes(self):
        for value in ("", "80070005", "0x", "0xZZ", "hello", "0x1ffffffff", None):
            self.assertIsNone(normalize_error_code(value))


class CacheTests(TestCase):

    def test_database_files_are_read_once(self):
        clear_database_cache()

        with patch.object(
            database_loader,
            "_read_json",
            return_value={"41": {}}
        ) as read:
            first = load_event_database()
            second = load_event_database()

        self.assertIs(first, second)
        read.assert_called_once()

        clear_database_cache()

    def test_clear_cache_forces_a_reload(self):
        clear_database_cache()
        first = load_error_code_database()
        clear_database_cache()
        second = load_error_code_database()

        self.assertIsNot(first, second)
        self.assertEqual(first, second)

    def test_damaged_file_gives_empty_database_and_a_message(self):
        clear_database_cache()

        with (
            patch("builtins.open", side_effect=ValueError("bad json")),
            patch("builtins.print") as printed,
        ):
            self.assertEqual(load_event_database(), {})

        self.assertIn("Database Error", printed.call_args.args[0])

        clear_database_cache()

    def test_find_event_definition_without_a_source_uses_generic_entries_only(self):
        self.assertIsNone(find_event_definition(41, None))


class CustomDatabaseTests(TestCase):
    """A user folder extends and overrides the built-in files."""

    def setUp(self):
        from tempfile import TemporaryDirectory

        self.directory = TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.addCleanup(clear_database_cache)

        patcher = patch.dict(
            "os.environ",
            {"WINDOWS_EVENT_ANALYZER_DATABASE_DIR": self.directory.name}
        )
        patcher.start()
        self.addCleanup(patcher.stop)

        clear_database_cache()

    def write(self, name, data):
        from pathlib import Path

        Path(self.directory.name, name).write_text(
            json.dumps(data),
            encoding="utf-8"
        )

    def test_custom_event_definition_is_added_and_overrides(self):
        self.write("event_definitions.json", {
            "99999": {"name": "Mine", "cause": "c", "severity": 50, "solutions": ["s"]},
            "7": {"name": "Disk (custom)", "cause": "c", "severity": 10, "solutions": ["s"], "sources": ["disk"]},
        })

        with patch("builtins.print"):
            database = load_event_database()

        self.assertEqual(database["99999"]["name"], "Mine")
        self.assertEqual(database["7"]["name"], "Disk (custom)")
        self.assertIn("41", database)

    def test_incomplete_custom_definitions_are_ignored(self):
        self.write("event_definitions.json", {
            "88888": {"name": "No severity", "cause": "c", "solutions": ["s"]},
            "abc": {"name": "Bad id", "cause": "c", "severity": 1, "solutions": []},
        })

        with patch("builtins.print") as printed:
            database = load_event_database()

        self.assertNotIn("88888", database)
        self.assertNotIn("abc", database)
        self.assertTrue(printed.called)

    def test_custom_error_code_in_any_spelling(self):
        self.write("error_codes.json", {
            "0XC0DE0001": {"description": "My code", "recommendation": "Do this"},
        })

        with patch("builtins.print"):
            self.assertEqual(get_error_info("0xc0de0001")["description"], "My code")
            self.assertIsNotNone(get_error_info("0x80070005"))

    def test_custom_rules_add_replace_and_disable(self):
        from modules.database_loader import load_rules_database

        self.write("rules.json", {
            "health": {"per_source_cap": 25},
            "rules": [
                {"id": "dcom-noise", "disabled": True},
                {"id": "kernel-power-only", "finding": "Custom text", "any_of": [41]},
                {"id": "my-rule", "finding": "Mine", "any_of": [12345]},
            ],
        })

        with patch("builtins.print"):
            data = load_rules_database()

        rule_ids = [rule["id"] for rule in data["rules"]]
        replaced = next(r for r in data["rules"] if r["id"] == "kernel-power-only")

        self.assertNotIn("dcom-noise", rule_ids)
        self.assertEqual(rule_ids[-1], "my-rule")
        self.assertEqual(replaced["finding"], "Custom text")
        self.assertEqual(data["health"]["per_source_cap"], 25)
        self.assertEqual(data["health"]["severity_factor"], 20)

    def test_damaged_custom_file_keeps_the_built_in_data(self):
        from pathlib import Path

        Path(self.directory.name, "event_definitions.json").write_text("{oops")

        with patch("builtins.print"):
            database = load_event_database()

        self.assertIn("41", database)

    def test_no_custom_folder_when_running_from_source(self):
        from modules.paths import get_custom_database_dir

        with patch.dict("os.environ", {}, clear=False) as environment:
            environment.pop("WINDOWS_EVENT_ANALYZER_DATABASE_DIR", None)

            self.assertIsNone(get_custom_database_dir())

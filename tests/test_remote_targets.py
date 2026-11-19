import json
import tempfile
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch

from modules.remote_settings import (
    forget_remote_settings,
    load_remote_settings,
    save_remote_settings,
)
from modules.remote_targets import (
    MAX_REMOTE_TARGETS,
    parse_remote_targets,
    remote_report_dir,
)


class RemoteTargetTests(TestCase):

    def test_parses_and_deduplicates_ip_addresses(self):
        targets = parse_remote_targets(
            "192.0.2.10\n192.0.2.10, 2001:db8::1"
        )

        self.assertEqual(
            targets,
            ["192.0.2.10", "2001:db8::1"],
        )

    def test_rejects_non_ip_target(self):
        with self.assertRaisesRegex(ValueError, "not a valid"):
            parse_remote_targets("pc-name")

    def test_limits_remote_target_count(self):
        targets = [
            f"192.0.{index // 256}.{index % 256}"
            for index in range(1, MAX_REMOTE_TARGETS + 2)
        ]

        with self.assertRaisesRegex(ValueError, "no more than"):
            parse_remote_targets("\n".join(targets))

    def test_ipv6_report_directory_uses_windows_safe_name(self):
        report_dir = remote_report_dir(
            Path("reports"),
            "2001:db8::1",
        )

        self.assertEqual(
            report_dir,
            Path("reports") / "remote" / "host-2001_db8__1",
        )


class RemoteSettingsTests(TestCase):

    def test_saves_only_selected_preferences_and_forgets_them(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch(
                "modules.remote_settings.get_user_data_dir",
                return_value=Path(temp_dir),
            ):
                save_remote_settings(
                    ["192.0.2.10"],
                    "CONTOSO",
                    remember_targets=True,
                    remember_domain=True,
                )

                settings_path = (
                    Path(temp_dir) / "remote_targets.json"
                )
                stored = json.loads(
                    settings_path.read_text(encoding="utf-8")
                )
                self.assertEqual(stored["targets"], ["192.0.2.10"])
                self.assertEqual(stored["domain"], "CONTOSO")
                self.assertNotIn("password", stored)
                self.assertEqual(
                    load_remote_settings(),
                    {
                        "targets": ["192.0.2.10"],
                        "domain": "CONTOSO",
                        "remember_targets": True,
                        "remember_domain": True,
                    },
                )

                forget_remote_settings()
                self.assertFalse(settings_path.exists())

    def test_unchecked_preferences_are_not_retained(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch(
                "modules.remote_settings.get_user_data_dir",
                return_value=Path(temp_dir),
            ):
                save_remote_settings(
                    ["192.0.2.10"],
                    "CONTOSO",
                    remember_targets=False,
                    remember_domain=True,
                )

                self.assertEqual(
                    load_remote_settings()["targets"],
                    [],
                )
                self.assertEqual(
                    load_remote_settings()["domain"],
                    "CONTOSO",
                )

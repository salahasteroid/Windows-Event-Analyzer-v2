import re
from pathlib import Path
from unittest import TestCase

from modules.version import __version__


ROOT = Path(__file__).resolve().parents[1]


class BuildFilesTests(TestCase):

    def test_every_database_file_is_bundled_in_the_executable(self):
        spec = (ROOT / "WindowsEventAnalyzer.spec").read_text(encoding="utf-8")

        for path in (ROOT / "database").glob("*.json"):
            self.assertIn(
                f'"{path.name}"',
                spec,
                f"{path.name} is missing from datas in the .spec file"
            )

    def test_upx_is_off(self):
        spec = (ROOT / "WindowsEventAnalyzer.spec").read_text(encoding="utf-8")

        self.assertRegex(spec, r"(?m)^\s*upx=False,")

    def test_version_info_matches_the_code_version(self):
        info = (ROOT / "version_info.txt").read_text(encoding="utf-8")
        numbers = ", ".join(__version__.split(".") + ["0"])

        self.assertIn(f"filevers=({numbers})", info)
        self.assertIn(f"'FileVersion', '{__version__}.0'", info)

    def test_spec_points_at_the_version_file(self):
        spec = (ROOT / "WindowsEventAnalyzer.spec").read_text(encoding="utf-8")

        self.assertIn("version_info.txt", spec)
        self.assertTrue((ROOT / "version_info.txt").is_file())

    def test_requirements_have_upper_bounds(self):
        for name in ("requirements.txt", "requirements-build.txt"):
            for line in (ROOT / name).read_text(encoding="utf-8").splitlines():
                if line.strip() and not line.startswith("-r"):
                    self.assertIn("<", line, f"{name}: {line}")

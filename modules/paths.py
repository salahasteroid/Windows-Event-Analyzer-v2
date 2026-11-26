import os
import sys
from pathlib import Path


def resource_path(*parts):

    if getattr(sys, "frozen", False):
        root = Path(sys._MEIPASS)
    else:
        root = Path(__file__).resolve().parents[1]

    return root.joinpath(*parts)


def get_user_data_dir():

    local_app_data = os.environ.get("LOCALAPPDATA")

    if local_app_data:
        root = Path(local_app_data)
    else:
        root = Path.home() / "AppData" / "Local"

    return root / "WindowsEventAnalyzer"


def get_custom_database_dir():
    """Folder with the user's own database files, or None.

    In the packaged .exe the built-in databases are inside the executable, so
    additions and changes go in %LOCALAPPDATA%\\WindowsEventAnalyzer\\database.
    When running from source, edit the files in the project's database folder
    instead; set WINDOWS_EVENT_ANALYZER_DATABASE_DIR to use a custom folder
    there as well.
    """

    override = os.environ.get("WINDOWS_EVENT_ANALYZER_DATABASE_DIR")

    if override:
        return Path(override)

    if getattr(sys, "frozen", False):
        return get_user_data_dir() / "database"

    return None


def get_reports_dir():

    if not getattr(sys, "frozen", False):
        return Path("reports")

    return get_user_data_dir() / "reports"

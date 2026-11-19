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


def get_reports_dir():

    if not getattr(sys, "frozen", False):
        return Path("reports")

    return get_user_data_dir() / "reports"

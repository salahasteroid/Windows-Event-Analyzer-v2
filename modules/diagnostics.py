"""A support file describing the failure, safe to send to someone else.

It holds the error, versions and the environment; it never contains
passwords, IP lists or event contents.
"""

import platform
import sys
from datetime import datetime, timezone
from pathlib import Path

from modules.database_loader import (
    load_error_code_database,
    load_event_database,
    load_rules_database,
)
from modules.paths import get_custom_database_dir, get_reports_dir
from modules.version import __version__


def short_error(error_text):
    """The last line of a traceback: 'ValueError: message'."""

    lines = [line for line in str(error_text).strip().splitlines() if line.strip()]

    return lines[-1].strip() if lines else "Unknown error"


def _module_status(name):

    try:
        module = __import__(name)
    except Exception as error:
        return f"NOT available ({type(error).__name__}: {error})"

    return f"available ({getattr(module, '__version__', 'version unknown')})"


def build_diagnostics(error_text="", context=None):

    lines = [
        "Windows Event Analyzer diagnostics",
        f"Created: {datetime.now(timezone.utc).isoformat(timespec='seconds')}",
        f"Version: {__version__}",
        f"Packaged .exe: {bool(getattr(sys, 'frozen', False))}",
        f"Python: {sys.version.split()[0]}",
        f"Windows: {platform.platform()}",
        f"win32evtlog (pywin32): {_module_status('win32evtlog')}",
        f"Evtx (python-evtx): {_module_status('Evtx')}",
        f"Reports folder: {get_reports_dir()}",
        f"Custom database folder: {get_custom_database_dir()}",
    ]

    try:
        lines.append(
            f"Database: {len(load_event_database())} event IDs, "
            f"{len(load_error_code_database())} error codes, "
            f"{len(load_rules_database().get('rules', []))} rules"
        )
    except Exception as error:
        lines.append(f"Database: could not be loaded ({error})")

    for name, value in (context or {}).items():
        lines.append(f"{name}: {value}")

    if error_text:
        lines += ["", "Error:", str(error_text).rstrip()]

    return "\n".join(lines) + "\n"


def write_diagnostics(output_dir, error_text="", context=None):
    """Write diagnostics.txt and return its path."""

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / "diagnostics.txt"
    path.write_text(build_diagnostics(error_text, context), encoding="utf-8")

    return path

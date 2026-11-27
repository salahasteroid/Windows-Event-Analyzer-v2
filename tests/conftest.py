"""Shared test setup.

The application talks to Windows-only libraries (pywin32) and to the
python-evtx package. When they are not installed (for example on Linux CI),
small stand-ins are registered so the rest of the code can be imported and
tested. On a real Windows PC with the libraries installed nothing is faked.
"""

import sys
import types

import pytest


def _missing(name):
    try:
        __import__(name)
        return False
    except ImportError:
        return True


if _missing("win32evtlog"):

    def _unavailable(*_args, **_kwargs):
        raise OSError("win32evtlog is not available on this platform")

    fake_win32evtlog = types.ModuleType("win32evtlog")

    for _name in (
        "EvtQuery",
        "EvtNext",
        "EvtRender",
        "EvtOpenSession",
        "EvtOpenPublisherMetadata",
        "EvtFormatMessage",
    ):
        setattr(fake_win32evtlog, _name, _unavailable)

    for _name, _value in (
        ("EvtQueryReverseDirection", 2),
        ("EvtRenderEventXml", 1),
        ("EvtRpcLogin", 1),
        ("EvtRpcLoginAuthNegotiate", 0),
        ("EvtFormatMessageEvent", 1),
    ):
        setattr(fake_win32evtlog, _name, _value)

    sys.modules["win32evtlog"] = fake_win32evtlog


if _missing("Evtx.Evtx"):

    fake_evtx_package = types.ModuleType("Evtx")
    fake_evtx_module = types.ModuleType("Evtx.Evtx")

    class Evtx:  # replaced by tests that need it
        def __init__(self, *_args, **_kwargs):
            raise OSError("python-evtx is not installed")

    fake_evtx_module.Evtx = Evtx
    fake_evtx_package.Evtx = fake_evtx_module

    sys.modules["Evtx"] = fake_evtx_package
    sys.modules["Evtx.Evtx"] = fake_evtx_module


@pytest.fixture(autouse=True)
def _isolated_working_directory(tmp_path, monkeypatch):
    """Tests that use the default "reports" folder write into a temp dir."""

    monkeypatch.chdir(tmp_path)
    # Caches, history and saved settings go to a throw-away profile folder.
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "appdata"))


# The window tests need Tk, which some minimal Python installs lack.
collect_ignore = []

if _missing("tkinter"):
    collect_ignore.append("test_app_ui.py")

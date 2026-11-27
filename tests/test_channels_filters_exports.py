import csv
import json
import socket
import threading
from datetime import datetime, timedelta, timezone

import pytest

from modules import internet_lookup
from modules.dashboard_charts import score_band, timeline_svg
from modules.event_channels import (
    SECURITY_EVENT_IDS,
    build_query,
    event_selected,
    normalize_logs,
)
from modules.event_filter import filter_events, parse_event_ids
from modules.event_grouping import group_events
from modules.exporters import (
    export_csv,
    export_events,
    forward_syslog,
    format_syslog_message,
    normalize_export_formats,
)
from modules.security_summary import summarize_security
from modules.unknown_events import write_unknown_template

NOW = datetime(2026, 11, 27, 12, 0, tzinfo=timezone.utc)


def make_event(event_id=41, source="Kernel-Power", level="Critical",
               time=None, known=True, message="", data=None, channel="System"):
    return {
        "EventID": event_id, "Source": source, "LevelName": level,
        "Time": (time or NOW).isoformat(), "Channel": channel,
        "Computer": "PC1", "Message": message, "Data": data or [],
        "Analysis": {"name": "N", "cause": "C", "known": known,
                     "severity": 90, "severity_text": "HIGH",
                     "error_codes": []},
    }


# ---- channels
def test_normalize_logs():
    assert normalize_logs(None) == ("System",)
    assert normalize_logs("security, system,SYSTEM") == ("Security", "System")
    with pytest.raises(ValueError):
        normalize_logs(["Setup"])
    with pytest.raises(ValueError):
        normalize_logs([" "])


def test_security_query_uses_event_ids_not_levels():
    query = build_query("Security", (1, 2), NOW, NOW)
    assert "EventID=4625" in query and "Level=" not in query
    assert "Level=1" in build_query("System", (1, 2), NOW, NOW)


def test_event_selected():
    assert event_selected("Security", 0, 4625, (1,))
    assert not event_selected("Security", 0, 4624, (1,))
    assert event_selected("System", 2, 7000, (1, 2))
    assert not event_selected("Application", 4, 1, (1, 2))
    assert 1102 in SECURITY_EVENT_IDS


# ---- filters
def test_parse_event_ids_ranges_and_errors():
    assert parse_event_ids("41, 7000-7002") == {41, 7000, 7001, 7002}
    with pytest.raises(ValueError):
        parse_event_ids("abc")
    with pytest.raises(ValueError):
        parse_event_ids("9-1")


def test_filter_events():
    events = [
        make_event(41), make_event(7000, "Service Control Manager"),
        make_event(10016, "DCOM", message="Permission denied"),
    ]
    assert [e["EventID"] for e in filter_events(events, event_ids="41")] == [41]
    assert len(filter_events(events, exclude_event_ids="41")) == 2
    assert [e["EventID"] for e in filter_events(events, sources=["dcom"])] == [10016]
    assert [e["EventID"] for e in filter_events(events, keywords=["PERMISSION"])] == [10016]
    assert len(filter_events(events)) == 3


# ---- grouping
def test_group_events_counts_and_times():
    early = NOW - timedelta(hours=2)
    events = [make_event(10016, "DCOM", time=NOW), make_event(10016, "dcom", time=early),
              make_event(41)]
    groups = group_events(events)
    assert groups[0]["count"] == 2 and groups[0]["event_id"] == 10016
    assert groups[0]["first_time"] == early.isoformat()
    assert groups[0]["last_time"] == NOW.isoformat()
    assert groups[1]["count"] == 1


# ---- unknown events
def test_unknown_template_written_only_for_unknown(tmp_path):
    assert write_unknown_template([make_event()], tmp_path) is None
    path = write_unknown_template(
        [make_event(9999, "Foo", "Error", known=False, message="boom"),
         make_event(9999, "Foo", "Error", known=False)], tmp_path)
    data = json.loads(path.read_text(encoding="utf-8"))
    entry = data["9999"]
    assert entry["sources"] == ["Foo"] and entry["_times_seen"] == 2
    assert entry["name"] == "" and entry["cause"] == ""


# ---- security summary
def test_security_summary():
    assert summarize_security([make_event()]) is None
    fail = lambda user, ip: make_event(
        4625, "Microsoft-Windows-Security-Auditing", "Information",
        channel="Security",
        data=[{"name": "TargetUserName", "value": user},
              {"name": "IpAddress", "value": ip}])
    summary = summarize_security(
        [fail("bob", "10.0.0.5"), fail("bob", "10.0.0.5"), fail("amy", "-"),
         make_event(1102, "Microsoft-Windows-Eventlog", channel="Security")])
    assert summary["failed_logons"] == 3
    assert summary["top_failed_accounts"][0] == ("bob", 2)
    assert summary["top_failed_sources"][0] == ("10.0.0.5", 2)
    assert summary["log_cleared"] == 1


# ---- exports
def test_normalize_export_formats():
    assert normalize_export_formats("CSV, json,csv") == ("csv", "json")
    assert normalize_export_formats(None) == ()
    with pytest.raises(ValueError):
        normalize_export_formats("xlsx")


def test_csv_is_excel_safe(tmp_path):
    event = make_event(message="=HYPERLINK(\"http://x\")")
    path = export_csv([event], tmp_path / "e.csv")
    assert path.read_bytes().startswith(b"\xef\xbb\xbf")
    rows = list(csv.DictReader(open(path, encoding="utf-8-sig")))
    assert rows[0]["Message"].startswith("'=")
    assert rows[0]["EventID"] == "41"


def test_export_events_formats_and_xml_modes(tmp_path):
    raw = [{"RawXML": "<Event><System/></Event>"}]
    files = export_events([make_event()], raw, tmp_path,
                          formats=("csv", "json"), xml_mode="combined",
                          summary={"health_score": 90})
    names = {f.name for f in files}
    assert {"events.csv", "events.json", "events.xml"} <= names
    assert json.loads((tmp_path / "events.json").read_text("utf-8"))
    assert export_events([], [], tmp_path / "x", (), "none") == []
    with pytest.raises(ValueError):
        export_events([], [], tmp_path, (), "weird")


def test_syslog_message_format():
    message = format_syslog_message(make_event(message="a\nb"))
    assert message.startswith("<10>1 ")  # facility user (8) + Critical (2)
    assert 'eventId="41"' in message and "\n" not in message


def test_syslog_udp_and_tcp_over_localhost():
    events = [make_event(), make_event(7000, level="Error")]

    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(("127.0.0.1", 0))
    udp.settimeout(3)
    assert forward_syslog(events, "127.0.0.1", udp.getsockname()[1]) == 2
    assert b"Kernel-Power" in udp.recvfrom(4096)[0]
    udp.close()

    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    received = []

    def serve():
        connection, _ = server.accept()
        with connection:
            received.append(connection.makefile().read())

    thread = threading.Thread(target=serve)
    thread.start()
    assert forward_syslog(events, "127.0.0.1", server.getsockname()[1], "tcp") == 2
    thread.join(3)
    server.close()
    assert len(received[0].splitlines()) == 2

    assert forward_syslog([], "127.0.0.1", 1) == 0
    with pytest.raises(ValueError):
        forward_syslog(events, "127.0.0.1", protocol="icmp")


# ---- lookup cache
def test_lookup_cache_reuses_fresh_and_survives_offline(monkeypatch):
    calls = []

    def fake_lookup(event_id, source):
        calls.append(event_id)
        return {"status": "found", "title": "T"}

    monkeypatch.setattr(internet_lookup, "lookup_event", fake_lookup)
    cache = {}
    internet_lookup.lookup_event_cached(41, "Kernel-Power", cache, now=NOW)
    again = internet_lookup.lookup_event_cached(41, "kernel-power", cache,
                                                now=NOW + timedelta(days=1))
    assert calls == [41] and again["from_cache"]

    monkeypatch.setattr(internet_lookup, "lookup_event",
                        lambda *a: {"status": "error", "error": "offline"})
    stale = internet_lookup.lookup_event_cached(
        41, "Kernel-Power", cache, now=NOW + timedelta(days=90))
    assert stale["stale"] and stale["status"] == "found"
    failed = internet_lookup.lookup_event_cached(1, "X", cache, now=NOW)
    assert failed["status"] == "error" and "1|x" not in cache


def test_lookup_cache_file_roundtrip(tmp_path):
    path = tmp_path / "c.json"
    assert internet_lookup.load_lookup_cache(path) == {}
    path.write_text("not json")
    assert internet_lookup.load_lookup_cache(path) == {}
    assert internet_lookup.save_lookup_cache({"a": 1}, path)
    assert internet_lookup.load_lookup_cache(path) == {"a": 1}


# ---- charts
def test_charts():
    assert score_band(100)[0] == "Healthy"
    assert score_band(10)[0] == "Critical issues"
    assert timeline_svg([make_event()]) == ""
    svg = timeline_svg([make_event(time=NOW), make_event(time=NOW - timedelta(hours=5))])
    assert svg.startswith("<svg")

"""Export analyzed events: CSV, JSON, one combined XML file, and syslog."""

import csv
import json
import socket
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

from modules.event_data import get_event_data_value


EXPORT_FORMATS = ("csv", "json")
XML_MODES = ("none", "combined", "per_event")

_EVENT_NAMESPACE = "http://schemas.microsoft.com/win/2004/08/events/event"

CSV_COLUMNS = (
    "Time",
    "Computer",
    "Log",
    "Level",
    "EventID",
    "Source",
    "Severity",
    "SeverityText",
    "KnownEvent",
    "Name",
    "Cause",
    "ErrorCodes",
    "Message",
    "EventData",
)


def normalize_export_formats(value):
    """"csv,json" or a list -> tuple of supported formats (may be empty)."""

    if value is None:
        return ()

    if isinstance(value, str):
        value = [part for part in value.replace(";", ",").split(",")]

    formats = []

    for item in value:

        name = str(item).strip().casefold()

        if not name:
            continue

        if name not in EXPORT_FORMATS:
            raise ValueError(
                f"Unsupported export format '{item}'. Choose from: "
                + ", ".join(EXPORT_FORMATS)
                + "."
            )

        if name not in formats:
            formats.append(name)

    return tuple(formats)


def _safe_csv(value):
    """Stop spreadsheets from running event text as a formula."""

    text = str(value)

    if text[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + text

    return text


def _event_row(event):

    analysis = event.get("Analysis") or {}

    codes = "; ".join(
        f"{item.get('code', '')} {item.get('description', '')}".strip()
        for item in analysis.get("error_codes", [])
    )

    data = "; ".join(
        f"{item.get('name', '')}={get_event_data_value(item)}"
        if isinstance(item, dict)
        else str(item)
        for item in event.get("Data", [])
    )

    return {
        "Time": event.get("Time", ""),
        "Computer": event.get("Computer", ""),
        "Log": event.get("Channel", ""),
        "Level": event.get("LevelName", ""),
        "EventID": event.get("EventID", ""),
        "Source": event.get("Source", ""),
        "Severity": analysis.get("severity", ""),
        "SeverityText": analysis.get("severity_text", ""),
        "KnownEvent": "yes" if analysis.get("known") else "no",
        "Name": analysis.get("name", ""),
        "Cause": analysis.get("cause", ""),
        "ErrorCodes": codes,
        "Message": event.get("Message", ""),
        "EventData": data,
    }


def export_csv(report_events, path):
    """One row per event. UTF-8 with BOM so Excel shows all languages."""

    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with open(path, "w", encoding="utf-8-sig", newline="") as file:

        writer = csv.DictWriter(file, fieldnames=CSV_COLUMNS)
        writer.writeheader()

        for event in report_events:
            writer.writerow({
                column: _safe_csv(value)
                for column, value in _event_row(event).items()
            })

    return path


def export_json(report_events, path, summary=None):
    """Events (without raw XML) plus an optional run summary."""

    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    events = []

    for event in report_events:

        analysis = event.get("Analysis") or {}

        events.append({
            "time": event.get("Time", ""),
            "computer": event.get("Computer", ""),
            "log": event.get("Channel", ""),
            "level": event.get("LevelName", ""),
            "event_id": event.get("EventID"),
            "source": event.get("Source", ""),
            "message": event.get("Message", ""),
            "data": event.get("Data", []),
            "analysis": {
                key: analysis.get(key)
                for key in (
                    "known",
                    "name",
                    "cause",
                    "severity",
                    "severity_text",
                    "solutions",
                    "error_codes",
                )
                if key in analysis
            },
        })

    document = {
        "generated": datetime.now(timezone.utc).isoformat(),
        "summary": summary or {},
        "events": events,
    }

    with open(path, "w", encoding="utf-8") as file:
        json.dump(document, file, indent=2, ensure_ascii=False, default=str)

    return path


def export_combined_xml(events, path):
    """All raw event XML records in one file under <Events>."""

    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    ET.register_namespace("", _EVENT_NAMESPACE)
    root = ET.Element("Events")
    written = 0

    for event in events:

        raw = event.get("RawXML")

        if not raw:
            continue

        try:
            root.append(ET.fromstring(raw))
            written += 1
        except ET.ParseError:
            continue

    tree = ET.ElementTree(root)
    ET.indent(tree)
    tree.write(path, encoding="utf-8", xml_declaration=True)

    return path, written


def export_events(
    report_events,
    raw_events,
    output_dir,
    formats=(),
    xml_mode="per_event",
    summary=None
):
    """Write the requested exports. Returns the list of files written.

    xml_mode: "per_event" (one file per event, the original behavior),
    "combined" (one events.xml) or "none".
    """

    if xml_mode not in XML_MODES:
        raise ValueError(
            f"Unsupported XML mode '{xml_mode}'. Choose from: "
            + ", ".join(XML_MODES)
            + "."
        )

    output_dir = Path(output_dir)
    written = []

    if "csv" in formats:
        written.append(export_csv(report_events, output_dir / "events.csv"))

    if "json" in formats:
        written.append(
            export_json(report_events, output_dir / "events.json", summary)
        )

    if xml_mode == "combined":
        path, count = export_combined_xml(raw_events, output_dir / "events.xml")
        if count:
            written.append(path)

    return written


# ---------------------------------------------------------------- syslog

_WINDOWS_LEVEL_TO_SYSLOG = {1: 2, 2: 3, 3: 4, 4: 6, 5: 7, 0: 6}
_LEVEL_NAME_TO_NUMBER = {
    "Critical": 1,
    "Error": 2,
    "Warning": 3,
    "Information": 4,
    "Verbose": 5,
}
_FACILITY_USER = 1
_MAX_UDP_BYTES = 1400
_ENTERPRISE_ID = "32473"  # reserved for documentation (RFC 5612)


def _sd_value(value):

    return (
        str(value)
        .replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("]", "\\]")
    )


def _one_line(value, limit):

    return " ".join(str(value).split())[:limit]


def format_syslog_message(event, app_name="WindowsEventAnalyzer"):
    """RFC 5424 message for one analyzed event."""

    level = _LEVEL_NAME_TO_NUMBER.get(event.get("LevelName"), 4)
    priority = _FACILITY_USER * 8 + _WINDOWS_LEVEL_TO_SYSLOG[level]

    time_text = event.get("Time") or datetime.now(timezone.utc).isoformat()
    host = _one_line(event.get("Computer") or "-", 255).replace(" ", "_") or "-"
    analysis = event.get("Analysis") or {}

    structured = (
        f'[wea@{_ENTERPRISE_ID} eventId="{_sd_value(event.get("EventID", ""))}" '
        f'source="{_sd_value(event.get("Source", ""))}" '
        f'log="{_sd_value(event.get("Channel", ""))}" '
        f'severity="{_sd_value(analysis.get("severity", ""))}"]'
    )

    text = _one_line(
        f"{event.get('Source', '')} Event {event.get('EventID', '')} "
        f"({event.get('LevelName', '')}): "
        f"{analysis.get('name') or event.get('Message', '')}",
        500
    )

    return (
        f"<{priority}>1 {time_text} {host} {app_name} - "
        f"{_one_line(event.get('EventID', '-'), 32).replace(' ', '_')} "
        f"{structured} {text}"
    )


def forward_syslog(
    report_events,
    host,
    port=514,
    protocol="udp",
    timeout=5
):
    """Send every event to a syslog server. Returns how many were sent.

    "udp": one datagram per event. "tcp": one line per event.
    Raises OSError if the server cannot be reached.
    """

    protocol = protocol.casefold()

    if protocol not in ("udp", "tcp"):
        raise ValueError("Syslog protocol must be udp or tcp.")

    messages = [format_syslog_message(event) for event in report_events]

    if not messages:
        return 0

    if protocol == "udp":

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            for message in messages:
                sock.sendto(
                    message.encode("utf-8")[:_MAX_UDP_BYTES],
                    (host, port)
                )

        return len(messages)

    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.sendall(
            "".join(message + "\n" for message in messages).encode("utf-8")
        )

    return len(messages)

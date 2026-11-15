from Evtx.Evtx import Evtx
import xml.etree.ElementTree as ET

from modules.event_data import extract_event_data
from modules.event_levels import normalize_event_levels
from modules.time_range import parse_event_time, resolve_time_range


def extract_message(root, ns):

    try:

        rendering_info = root.find(
            ".//e:RenderingInfo",
            ns
        )

        if rendering_info is not None:

            message = rendering_info.find(
                ".//e:Message",
                ns
            )

            if message is not None and message.text:
                return message.text

    except Exception:
        pass

    return ""


def read_evtx(
    file_path,
    max_events=None,
    start_time=None,
    end_time=None,
    levels=None,
    cancellation_event=None
):

    events = []
    start_time, end_time = resolve_time_range(
        start_time,
        end_time
    )
    if levels is not None:
        levels = normalize_event_levels(levels)

    with Evtx(file_path) as log:

        for record in log.records():

            if (
                cancellation_event is not None
                and cancellation_event.is_set()
            ):
                break

            try:

                xml_data = record.xml()

                root = ET.fromstring(
                    xml_data
                )

                ns = {
                    "e": "http://schemas.microsoft.com/win/2004/08/events/event"
                }

                event_id = root.find(
                    ".//e:EventID",
                    ns
                )

                level = root.find(
                    ".//e:Level",
                    ns
                )
                event_level = (
                    int(level.text)
                    if level is not None
                    else 0
                )

                if levels is not None and event_level not in levels:
                    continue

                provider = root.find(
                    ".//e:Provider",
                    ns
                )

                computer = root.find(
                    ".//e:Computer",
                    ns
                )

                time_created = root.find(
                    ".//e:TimeCreated",
                    ns
                )
                event_time = (
                    time_created.attrib.get("SystemTime", "")
                    if time_created is not None
                    else ""
                )
                parsed_event_time = parse_event_time(event_time)

                if parsed_event_time is None:
                    print(
                        "EVTX Read Error: event has no valid timestamp; "
                        "skipping it because a time range was selected."
                    )
                    continue

                if not start_time <= parsed_event_time <= end_time:
                    continue

                events.append({

                    "EventID": (
                        int(event_id.text)
                        if event_id is not None
                        else 0
                    ),

                    "Level": (
                        event_level
                    ),

                    "Source": (
                        provider.attrib.get(
                            "Name",
                            "Unknown"
                        )
                        if provider is not None
                        else "Unknown"
                    ),

                    "Computer": (
                        computer.text
                        if computer is not None
                        else ""
                    ),

                    "Time": (
                        event_time
                    ),

                    "Data": extract_event_data(
                        root,
                        ns
                    ),

                    "Message": extract_message(
                        root,
                        ns
                    ),

                    "RawXML": xml_data
                })

                if (
                    max_events is not None
                    and len(events) >= max_events
                ):
                    break

            except Exception as ex:

                print(
                    f"EVTX Read Error: {ex}"
                )

    return events
import win32evtlog
import xml.etree.ElementTree as ET

from modules.event_data import extract_event_data
from modules.event_channels import build_query, normalize_logs
from modules.event_levels import normalize_event_levels
from modules.message_formatter import MessageResolver
from modules.time_range import format_event_log_time, resolve_time_range


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

            if message is not None:
                return message.text

    except Exception:
        pass

    return ""


def get_recent_events(
    max_events=None,
    start_time=None,
    end_time=None,
    levels=None,
    remote_options=None,
    cancellation_event=None,
    log_name="System"
):

    events = []

    log_name = normalize_logs([log_name])[0]

    start_time, end_time = resolve_time_range(
        start_time,
        end_time
    )
    if levels is not None:
        levels = normalize_event_levels(levels)

    query = build_query(
        log_name,
        levels,
        start_time,
        end_time
    )

    if cancellation_event is not None and cancellation_event.is_set():
        return events

    session = None
    if remote_options:
        computer = remote_options.get("computer")
        username = remote_options.get("username")
        password = remote_options.get("password")
        domain = remote_options.get("domain") or None

        if not computer or not username or not password:
            raise ValueError(
                "Remote log access requires a computer IP, username, "
                "and password."
            )

        login = (
            computer,
            username,
            domain,
            password,
            win32evtlog.EvtRpcLoginAuthNegotiate,
        )
        session = win32evtlog.EvtOpenSession(
            login,
            win32evtlog.EvtRpcLogin,
            0,
            0,
        )
        if session is None:
            raise RuntimeError("Could not open the remote Event Log session.")

    if cancellation_event is not None and cancellation_event.is_set():
        return events

    if session is None:
        handle = win32evtlog.EvtQuery(
            log_name,
            win32evtlog.EvtQueryReverseDirection,
            query
        )
    else:
        handle = win32evtlog.EvtQuery(
            log_name,
            win32evtlog.EvtQueryReverseDirection,
            query,
            session
        )

    message_resolver = MessageResolver(session)

    while (
        (max_events is None or len(events) < max_events)
        and not (
            cancellation_event is not None
            and cancellation_event.is_set()
        )
    ):

        records = win32evtlog.EvtNext(handle, 10, 1000)

        if not records:
            break

        for record in records:

            if (
                cancellation_event is not None
                and cancellation_event.is_set()
            ):
                break

            if max_events is not None and len(events) >= max_events:
                break

            try:

                xml_data = win32evtlog.EvtRender(
                    record,
                    win32evtlog.EvtRenderEventXml
                )

                root = ET.fromstring(xml_data)

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

                events.append({

                    "EventID": int(event_id.text)
                    if event_id is not None
                    else 0,

                    "Level": int(level.text)
                    if level is not None
                    else 0,

                    "Source": provider.attrib.get(
                        "Name",
                        "Unknown"
                    )
                    if provider is not None
                    else "Unknown",

                    "Computer": computer.text
                    if computer is not None
                    else "",

                    "Channel": log_name,

                    "Time": time_created.attrib.get(
                        "SystemTime",
                        ""
                    )
                    if time_created is not None
                    else "",

                    "Data": extract_event_data(
                        root,
                        ns
                    ),

                    # The XML only carries a message when Windows
                    # rendered one; otherwise ask the provider for it.
                    "Message": extract_message(
                        root,
                        ns
                    ) or message_resolver.format(
                        record,
                        provider.attrib.get("Name")
                        if provider is not None
                        else None
                    ),

                    "RawXML": xml_data
                })

            except Exception as ex:

                print(
                    f"Read Error: {ex}"
                )

    message_resolver.close()

    return events
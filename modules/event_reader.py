import win32evtlog
import xml.etree.ElementTree as ET


def extract_event_data(root, ns):

    data = []

    try:

        event_data = root.find(
            ".//e:EventData",
            ns
        )

        if event_data is not None:

            for item in event_data:

                if item.text:
                    data.append(item.text)

    except Exception:
        pass

    return data


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


def get_recent_events(max_events=50):

    events = []

    handle = win32evtlog.EvtQuery(
        "System",
        win32evtlog.EvtQueryReverseDirection,
        "*"
    )

    while len(events) < max_events:

        records = win32evtlog.EvtNext(
            handle,
            10
        )

        if not records:
            break

        for record in records:

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

                    "Message": extract_message(
                        root,
                        ns
                    ),

                    "RawXML": xml_data
                })

            except Exception as ex:

                print(
                    f"Read Error: {ex}"
                )

        if len(events) >= max_events:
            break

    return events
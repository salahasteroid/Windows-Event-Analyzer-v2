import win32evtlog


def format_message(event_handle):

    try:

        return win32evtlog.EvtFormatMessage(
            event_handle,
            win32evtlog.EvtFormatMessageEvent
        )

    except Exception:

        return ""
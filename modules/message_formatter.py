import win32evtlog


class MessageResolver:
    """Turns an event record into the message text Windows shows.

    Event XML rendered without a message does not contain the readable
    text. This asks the provider's own message tables for it through
    EvtFormatMessage. If the provider is not installed on the machine
    (common for remote logs) the result is an empty string, and the
    caller keeps using the Event Data fields.
    """

    def __init__(self, session=None):

        self._session = session
        self._metadata = {}

    def _get_metadata(self, provider):

        if provider not in self._metadata:

            try:
                self._metadata[provider] = (
                    win32evtlog.EvtOpenPublisherMetadata(
                        provider,
                        None,
                        self._session,
                        0,
                        0
                    )
                )
            except Exception:
                self._metadata[provider] = None

        return self._metadata[provider]

    def format(self, record, provider):

        if not provider:
            return ""

        metadata = self._get_metadata(provider)

        if metadata is None:
            return ""

        try:

            text = win32evtlog.EvtFormatMessage(
                metadata,
                record,
                0,
                None,
                win32evtlog.EvtFormatMessageEvent
            )

        except Exception:
            return ""

        return text.strip() if isinstance(text, str) else ""

    def close(self):

        for handle in self._metadata.values():

            if handle is None:
                continue

            try:
                handle.Close()
            except Exception:
                pass

        self._metadata.clear()

    def __enter__(self):

        return self

    def __exit__(self, *_):

        self.close()

        return False

from unittest import TestCase
from unittest.mock import Mock, patch

from modules import message_formatter
from modules.message_formatter import MessageResolver


class MessageResolverTests(TestCase):

    def test_returns_the_formatted_message(self):
        metadata = Mock()

        with (
            patch.object(message_formatter.win32evtlog, "EvtOpenPublisherMetadata", return_value=metadata) as opener,
            patch.object(message_formatter.win32evtlog, "EvtFormatMessage", return_value="  The system rebooted.  ") as formatter,
        ):
            resolver = MessageResolver(session="SESSION")
            text = resolver.format("RECORD", "Provider-A")

        self.assertEqual(text, "The system rebooted.")
        opener.assert_called_once_with("Provider-A", None, "SESSION", 0, 0)
        self.assertEqual(formatter.call_args.args[:2], (metadata, "RECORD"))

    def test_metadata_is_opened_once_per_provider(self):
        with (
            patch.object(message_formatter.win32evtlog, "EvtOpenPublisherMetadata", return_value=Mock()) as opener,
            patch.object(message_formatter.win32evtlog, "EvtFormatMessage", return_value="x"),
        ):
            resolver = MessageResolver()
            resolver.format("r1", "Provider-A")
            resolver.format("r2", "Provider-A")
            resolver.format("r3", "Provider-B")

        self.assertEqual(opener.call_count, 2)

    def test_missing_provider_gives_empty_text_and_is_not_retried(self):
        with (
            patch.object(message_formatter.win32evtlog, "EvtOpenPublisherMetadata", side_effect=OSError("no provider")) as opener,
            patch.object(message_formatter.win32evtlog, "EvtFormatMessage") as formatter,
        ):
            resolver = MessageResolver()

            self.assertEqual(resolver.format("r", "Provider-X"), "")
            self.assertEqual(resolver.format("r", "Provider-X"), "")

        opener.assert_called_once()
        formatter.assert_not_called()

    def test_format_failure_gives_empty_text(self):
        with (
            patch.object(message_formatter.win32evtlog, "EvtOpenPublisherMetadata", return_value=Mock()),
            patch.object(message_formatter.win32evtlog, "EvtFormatMessage", side_effect=OSError("fail")),
        ):
            self.assertEqual(MessageResolver().format("r", "P"), "")

    def test_non_text_result_is_ignored(self):
        with (
            patch.object(message_formatter.win32evtlog, "EvtOpenPublisherMetadata", return_value=Mock()),
            patch.object(message_formatter.win32evtlog, "EvtFormatMessage", return_value=None),
        ):
            self.assertEqual(MessageResolver().format("r", "P"), "")

    def test_no_provider_gives_empty_text(self):
        self.assertEqual(MessageResolver().format("r", None), "")

    def test_close_releases_all_handles(self):
        first, second = Mock(), Mock()

        with (
            patch.object(message_formatter.win32evtlog, "EvtOpenPublisherMetadata", side_effect=[first, second]),
            patch.object(message_formatter.win32evtlog, "EvtFormatMessage", return_value="x"),
        ):
            with MessageResolver() as resolver:
                resolver.format("r", "A")
                resolver.format("r", "B")

        first.Close.assert_called_once()
        second.Close.assert_called_once()

from datetime import datetime, timezone
from html.parser import HTMLParser
import unittest
from unittest.mock import patch

from alert_format import format_alert
import vps_monitor as monitor


class TelegramMarkup(HTMLParser):
    def __init__(self):
        super().__init__()
        self.stack = []
        self.text = ''

    def handle_starttag(self, tag, attributes):
        if tag not in ('b', 'code', 'pre', 'i') or attributes:
            raise AssertionError('Unexpected markup')
        self.stack.append(tag)

    def handle_endtag(self, tag):
        if not self.stack or self.stack.pop() != tag:
            raise AssertionError('Unbalanced markup')

    def handle_data(self, data):
        self.text += data


class AlertFormatTests(unittest.TestCase):
    def test_resource_card_has_clear_title_grouped_metrics_and_local_time(self):
        text = format_alert({'name': 'ubuntu-flandre'},
            '⚠️ HIGH — CPU\n\nCPU: 100.0 %\nRAM: 5.7 %\nDisk: 2.1 %\nIncoming traffic: 0.4 Kbps\nThreshold: 90.0 %',
            now=datetime(2026, 10, 29, 7, 46, tzinfo=timezone.utc))
        self.assertIn('<b>⚠️ CPU usage is high</b>', text)
        self.assertIn('<pre>CPU', text)
        self.assertIn('100.0%', text)
        self.assertIn('Network in', text)
        self.assertIn('14:46 Cambodia', text)

    def test_untrusted_server_process_and_package_values_are_escaped(self):
        text = format_alert({'name': '<b>fake</b>&'}, '⚠️ Alert\nProcess: <a href="bad">test</a>\nexample: 1<2 → 3&4')
        parser = TelegramMarkup()
        parser.feed(text)
        self.assertEqual(parser.stack, [])
        self.assertIn('<a href="bad">test</a>', parser.text)
        self.assertNotIn('<a href=', text)

    def test_long_payload_keeps_valid_markup_and_visible_text_under_limit(self):
        text = format_alert({'name': 'vps'}, '⚠️ Alert\n' + '<&>' * 2000)
        parser = TelegramMarkup()
        parser.feed(text)
        self.assertEqual(parser.stack, [])
        self.assertLess(len(parser.text), 4096)

    def test_recovery_wording_and_version_details(self):
        text = format_alert({'name': 'vps'}, '✅ RECOVERED — RAM\nexample: 1.0 → 2.0')
        self.assertIn('Memory usage recovered', text)
        self.assertIn('<b>• example</b>', text)
        self.assertIn('<code>1.0 → 2.0</code>', text)

    def test_send_enables_html_and_disables_link_previews(self):
        with patch.object(monitor, 'api') as api, patch.object(monitor.time, 'sleep'):
            monitor.send({'name': 'vps', 'token': 'private', 'chat_id': 123}, '✅ Test')
        self.assertEqual(api.call_args.kwargs['parse_mode'], 'HTML')
        self.assertIn('"is_disabled": true', api.call_args.kwargs['link_preview_options'])


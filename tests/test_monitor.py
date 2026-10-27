import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import urllib.error
import socket
import ssl

import vps_monitor as monitor


class MonitorTests(unittest.TestCase):
    def test_pairing_recovers_from_network_failure(self):
        updates = [{'update_id': 7, 'message': {'text': 'pair-test', 'chat': {'type': 'private', 'id': 123}}}]
        with patch.object(monitor, 'api', side_effect=[monitor.TelegramConnectionError('Telegram: request timed out'), updates]) as api:
            with patch.object(monitor.time, 'sleep'), patch('builtins.print'):
                self.assertEqual(monitor.wait_for_pairing('secret', 'pair-test'), 123)
        self.assertEqual(api.call_count, 2)
        self.assertEqual(api.call_args.kwargs['timeout'], 0)

    def test_pairing_does_not_retry_bad_credentials(self):
        with patch.object(monitor, 'api', side_effect=RuntimeError('Telegram HTTP 401')) as api:
            with self.assertRaisesRegex(RuntimeError, '401'):
                monitor.wait_for_pairing('secret', 'pair-test')
        self.assertEqual(api.call_count, 1)

    def test_transport_diagnostics(self):
        for reason, expected in [(socket.gaierror('secret'), 'DNS'), (TimeoutError('secret'), 'timed out'), (ConnectionResetError('secret'), 'reset')]:
            with self.subTest(reason=type(reason).__name__):
                error = monitor.connection_error(reason)
                self.assertIsInstance(error, monitor.TelegramConnectionError)
                self.assertIn(expected, str(error))
                self.assertNotIn('secret', str(error))
        error = monitor.connection_error(ssl.SSLCertVerificationError('secret'))
        self.assertNotIsInstance(error, monitor.TelegramConnectionError)
        self.assertIn('certificate', str(error))

    def test_sustained_alert_reminder_and_recovery(self):
        alert = monitor.Alert()
        self.assertIsNone(alert.check(95, 90, 0, 120, 1800))
        self.assertIsNone(alert.check(95, 90, 119, 120, 1800))
        self.assertEqual(alert.check(95, 90, 120, 120, 1800), '⚠️ HIGH')
        alert.delivered('⚠️ HIGH', 120)
        self.assertIsNone(alert.check(95, 90, 121, 120, 1800))
        self.assertEqual(alert.check(95, 90, 1920, 120, 1800), '⚠️ STILL HIGH')
        self.assertIsNone(alert.check(88, 90, 1930, 120, 1800))
        self.assertEqual(alert.check(80, 90, 1940, 120, 1800), '✅ RECOVERED')
        alert.delivered('✅ RECOVERED', 1940)
        self.assertIsNone(alert.check(95, 90, 2000, 120, 1800))
        self.assertEqual(alert.check(95, 90, 2120, 120, 1800), '⚠️ HIGH')

    def test_short_spikes_do_not_trigger(self):
        alert = monitor.Alert()
        alert.check(95, 90, 0, 120, 1800)
        alert.check(40, 90, 100, 120, 1800)
        self.assertIsNone(alert.check(95, 90, 120, 120, 1800))
        self.assertIsNone(alert.check(95, 90, 230, 120, 1800))

    def test_failed_delivery_is_retried(self):
        alert = monitor.Alert()
        alert.check(95, 90, 0, 120, 1800)
        self.assertEqual(alert.check(95, 90, 120, 120, 1800), '⚠️ HIGH')
        self.assertEqual(alert.check(95, 90, 135, 120, 1800), '⚠️ HIGH')

    def test_metric_calculation(self):
        with patch.object(monitor.Path, 'read_text', return_value='MemTotal: 8000000 kB\nMemAvailable: 2000000 kB\n'):
            values = monitor.metrics((100, 50, 0, 0, 0), (200, 60, 125000000, 25000000, 10), '/')
        self.assertEqual(values['CPU'], 90)
        self.assertEqual(values['RAM'], 75)
        self.assertEqual(values['Incoming traffic'], 100)
        self.assertEqual(values['Outgoing traffic'], 20)

    def test_token_is_not_in_network_errors(self):
        with patch.object(monitor.urllib.request, 'urlopen', side_effect=urllib.error.URLError('secret-token')):
            with self.assertRaises(RuntimeError) as error:
                monitor.api('secret-token', 'getMe')
        self.assertNotIn('secret-token', str(error.exception))

    def test_env_defaults_and_quoted_values(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / '.env'
            path.write_text('# Config\nTELEGRAM_BOT_TOKEN=123:example\nTELEGRAM_CHAT_ID=123\nSERVER_NAME="My VPS"\n')
            config = monitor.load(path)
            self.assertEqual(config['name'], 'My VPS')
            self.assertEqual(config['cpu_percent'], 90)

    def test_invalid_settings_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / '.env'
            path.write_text('TELEGRAM_BOT_TOKEN=123:example\nTELEGRAM_CHAT_ID=123\nCPU_THRESHOLD=101\n')
            with self.assertRaises(RuntimeError):
                monitor.load(path)


if __name__ == '__main__':
    unittest.main()

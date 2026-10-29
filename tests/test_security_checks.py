import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
from datetime import date
from unittest.mock import patch

import security_checks as security
import vps_monitor as monitor


class SecurityTests(unittest.TestCase):


    def test_tailscale_reminder_checkpoints_and_invalid_date(self):
        self.assertIsNone(security.tailscale_reminder('2027-04-26', date(2027, 3, 26)))
        for today, stage in [(date(2027, 3, 27), '30'), (date(2027, 4, 12), '14'),
                             (date(2027, 4, 19), '7'), (date(2027, 4, 23), '3'),
                             (date(2027, 4, 25), '1'), (date(2027, 4, 26), '0'),
                             (date(2027, 4, 27), 'passed')]:
            with self.subTest(today=today):
                self.assertEqual(security.tailscale_reminder('2027-04-26', today)[0], stage)
        with self.assertRaises(ValueError):
            security.tailscale_reminder('2027-02-29')

    def test_tailscale_reminder_does_not_repeat_after_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            config = {'state_directory': directory, 'tailscale_key_expiry': '2027-04-26'}
            sent = []
            for _ in range(2):
                checker = security.Maintenance(config, lambda config, text: sent.append(text))
                with patch.object(security, 'tailscale_reminder', return_value=('14', 'Expiry reminder')):
                    checker.tailscale_expiry()
            self.assertEqual(sum(text.startswith('Expiry reminder') for text in sent), 1)

    def test_auto_update_reports_changes_once_and_quiet_empty_runs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sent = []
            checker = security.Maintenance({'state_directory': str(root / 'monitor')}, lambda config, text: sent.append(text))
            (root / 'configuration.json').write_text(json.dumps({'schedule': 'Daily 03:00 Cambodia', 'enabled_at': time.time()}))
            report = {'run_id': '1', 'status': 'completed', 'finished_at': time.time(), 'changes': [{'package': 'example', 'before': '1', 'after': '2'}]}
            (root / 'status.json').write_text(json.dumps(report))
            checker.automatic_updates(root)
            checker.automatic_updates(root)
            self.assertEqual(sum('example: 1 → 2' in text for text in sent), 1)
            sent.clear()
            report.update(run_id='2', changes=[])
            (root / 'status.json').write_text(json.dumps(report))
            checker.automatic_updates(root)
            self.assertEqual(sent, [])


    def test_ipv4_ipv6_and_udp_listeners(self):
        parsed = security.parse_listeners('''tcp LISTEN 0 128 127.0.0.1:8080 0.0.0.0:* users:(("python3",pid=42,fd=3))
tcp LISTEN 0 128 [::]:22 [::]:*
udp UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:*
''')
        self.assertEqual(parsed['tcp|127.0.0.1|8080']['scope'], 'localhost')
        self.assertEqual(parsed['tcp|127.0.0.1|8080']['process'], 'python3')
        self.assertEqual(parsed['tcp|::|22']['scope'], 'non-loopback')
        self.assertEqual(parsed['udp|127.0.0.53%lo|53']['scope'], 'localhost')

    def test_public_binding_change_alerts_even_for_expected_port(self):
        previous = security.parse_listeners('tcp LISTEN 0 128 127.0.0.1:22 0.0.0.0:*')
        current = security.parse_listeners('tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*')
        messages = security.port_changes(previous, current, 'tcp:22')
        self.assertTrue(any('New listener' in message for message in messages))
        self.assertTrue(any('stopped' in message for message in messages))

    def test_expected_new_ports_suppressed(self):
        current = security.parse_listeners('tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*')
        self.assertEqual(security.port_changes({}, current, 'tcp:22'), [])

    def test_state_deduplicates_across_restart_and_retries_failed_send(self):
        with tempfile.TemporaryDirectory() as directory:
            config = {'state_directory': directory}
            sent = []
            checker = security.Maintenance(config, lambda config, text: sent.append(text))
            checker.notify('test', 1, ['First alert'])
            checker = security.Maintenance(config, lambda config, text: sent.append(text))
            checker.notify('test', 1, ['Duplicate'])
            self.assertEqual(sent, ['First alert'])
            def fail(config, text):
                raise RuntimeError('offline')
            checker.send = fail
            with self.assertRaises(RuntimeError):
                checker.notify('test', 2, ['New alert'])
            self.assertEqual(json.loads(checker.path.read_text())['test'], 1)

    def test_security_update_origin(self):
        from types import SimpleNamespace as S
        package = S(name='example', is_installed=True, is_upgradable=True,
                    installed=S(version='1'), candidate=S(version='2', origins=[S(origin='Ubuntu', archive='noble-security')]))
        with patch.dict('sys.modules', {'apt': S(Cache=lambda: [package])}):
            self.assertTrue(security.package_updates()[0]['security'])


    def test_self_update_uses_remote_ref_and_ancestry(self):
        from io import BytesIO
        local, remote = 'a' * 40, 'b' * 40
        with patch.object(security.Path, 'exists', return_value=True), patch.object(security.Path, 'read_text', return_value=json.dumps({'commit': local})):
            with patch.object(security.urllib.request, 'urlopen', side_effect=[BytesIO(json.dumps({'object': {'sha': remote}}).encode()), BytesIO(b'{"status":"ahead"}')]):
                self.assertEqual(security.reimu_update(), remote)

    def test_reinstall_from_installed_env_keeps_credentials(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'etc').mkdir()
            path = root / 'etc/reimu-vps.env'
            path.write_text('TELEGRAM_BOT_TOKEN=123:example\nTELEGRAM_CHAT_ID=123\nCVE_ALERTS=true\nCVE_INTERVAL_SECONDS=86400\n')
            def run(args, **kwargs):
                return subprocess.CompletedProcess(args, 0, stdout='a' * 40 + '\n')
            with patch.object(monitor.os, 'geteuid', return_value=0), patch.object(monitor.os, 'chown'), patch.object(monitor.subprocess, 'run', side_effect=run), patch('builtins.print'):
                monitor.install(path, root=root, tailscale_key_expiry='2027-04-26')
            self.assertIn('TELEGRAM_BOT_TOKEN=123:example', path.read_text())
            self.assertNotIn('CVE_ALERTS', path.read_text())
            self.assertNotIn('CVE_INTERVAL_SECONDS', path.read_text())
            self.assertEqual(monitor.read_env(path)['TAILSCALE_KEY_EXPIRY'], '2027-04-26')
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertTrue((root / 'opt/reimu-vps/security_checks.py').exists())
            self.assertTrue((root / 'opt/reimu-vps/alert_format.py').exists())


    def test_invalid_maintenance_settings(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / '.env'
            path.write_text('TELEGRAM_BOT_TOKEN=123:example\nTELEGRAM_CHAT_ID=123\nPORT_INTERVAL_SECONDS=0\n')
            with self.assertRaises(RuntimeError):
                monitor.load(path)


if __name__ == '__main__':
    unittest.main()

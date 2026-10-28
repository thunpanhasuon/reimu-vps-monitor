import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import security_updater as updater


class UpdaterTests(unittest.TestCase):
    def test_unsafe_policy_never_starts_upgrade(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            with patch.object(updater, 'effective_policy_is_safe', return_value=False), patch.object(updater.subprocess, 'run') as run:
                result = updater.run_update(directory=path)
            report = json.loads((path / 'status.json').read_text())
            self.assertEqual(result, 1)
            self.assertEqual(report['status'], 'failed')
            run.assert_not_called()

    def test_success_reports_actual_version_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            with patch.object(updater, 'effective_policy_is_safe', return_value=True), patch.object(updater, 'installed_packages', side_effect=[{'example': '1'}, {'example': '2'}]), patch.object(updater.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0)) as run, patch.object(Path, 'mkdir'), patch.object(Path, 'touch'), patch('security_checks.package_updates', return_value=[]):
                result = updater.run_update(directory=path)
            report = json.loads((path / 'status.json').read_text())
            self.assertEqual(result, 0)
            self.assertEqual(report['changes'], [{'package': 'example', 'before': '1', 'after': '2'}])
            self.assertEqual(run.call_args.args[0], ['/usr/bin/unattended-upgrade'])
            self.assertEqual((path / 'status.json').stat().st_mode & 0o777, 0o644)
            self.assertEqual((path / 'last-run.log').stat().st_mode & 0o777, 0o600)

    def test_partial_failure_keeps_installed_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            results = [subprocess.CompletedProcess([], 0), subprocess.CompletedProcess([], 1)]
            with patch.object(updater, 'effective_policy_is_safe', return_value=True), patch.object(updater, 'installed_packages', side_effect=[{'example': '1'}, {'example': '2'}]), patch.object(updater.subprocess, 'run', side_effect=results), patch.object(Path, 'mkdir'), patch.object(Path, 'touch'), patch('security_checks.package_updates', return_value=[]):
                result = updater.run_update(directory=path)
            report = json.loads((path / 'status.json').read_text())
            self.assertEqual(result, 1)
            self.assertEqual(report['status'], 'failed')
            self.assertEqual(len(report['changes']), 1)

    def test_dry_run_never_refreshes_or_installs(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            with patch.object(updater, 'effective_policy_is_safe', return_value=True), patch.object(updater, 'installed_packages', return_value={'example': '1'}), patch.object(updater.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0)) as run, patch('security_checks.package_updates', return_value=[]):
                result = updater.run_update(dry_run=True, directory=path)
            self.assertEqual(result, 0)
            run.assert_called_once()
            self.assertEqual(run.call_args.args[0], ['/usr/bin/unattended-upgrade', '--dry-run'])
            self.assertTrue((path / 'dry-run.json').exists())
            self.assertFalse((path / 'status.json').exists())

    def test_configuration_never_enables_feature_updates_or_reboots(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = root / 'var/lib/reimu-security-updates'
            original_stat = Path.stat
            def root_stat(path, *args, **kwargs):
                result = original_stat(path, *args, **kwargs)
                if path == state:
                    fields = list(result)
                    fields[4] = 0
                    return os.stat_result(fields)
                return result
            with patch.object(updater.os, 'geteuid', return_value=0), patch.object(Path, 'stat', root_stat), patch.object(updater.subprocess, 'run') as run:
                updater.configure(root)
            policy = (root / 'etc/apt/apt.conf.d/99zz-reimu-security-updates').read_text()
            self.assertNotIn('${distro_codename}-updates', policy)
            self.assertIn('Automatic-Reboot "false"', policy)
            self.assertIn('#clear Unattended-Upgrade::Origins-Pattern', policy)
            timer = (root / 'etc/systemd/system/reimu-security-updates.timer').read_text()
            self.assertIn('Asia/Phnom_Penh', timer)
            self.assertTrue((state / 'configuration.json').exists())
            self.assertFalse((state / 'status.json').exists())
            self.assertIn(['systemctl', 'disable', '--now', 'apt-daily-upgrade.timer'], [call.args[0] for call in run.call_args_list])


if __name__ == '__main__':
    unittest.main()

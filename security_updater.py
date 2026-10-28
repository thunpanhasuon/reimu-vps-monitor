"""Root-only scheduled security updater; Telegram monitor remains unprivileged."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time

DIRECTORY = Path('/var/lib/reimu-security-updates')
ORIGINS = (
    '${distro_id}:${distro_codename}-security',
    'UbuntuESMApps:${distro_codename}-apps-security',
    'UbuntuESM:${distro_codename}-infra-security',
)
POLICY = '''// Managed by Reimu: security pockets only, manual reboots.
#clear Unattended-Upgrade::Allowed-Origins;
#clear Unattended-Upgrade::Origins-Pattern;
Unattended-Upgrade::Allowed-Origins {
''' + ''.join('    "' + origin + '";\n' for origin in ORIGINS) + '''};
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Automatic-Reboot-WithUsers "false";
Unattended-Upgrade::Remove-Unused-Dependencies "false";
Unattended-Upgrade::Remove-New-Unused-Dependencies "false";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "false";
'''


def save_report(report, directory=DIRECTORY, filename='status.json'):
    descriptor, temporary = tempfile.mkstemp(dir=directory, prefix='.report-')
    try:
        with os.fdopen(descriptor, 'w') as output:
            json.dump(report, output, sort_keys=True)
        os.chmod(temporary, 0o644)  # Package versions are already locally readable via dpkg.
        os.replace(temporary, directory / filename)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def effective_policy_is_safe():
    import apt_pkg
    apt_pkg.init_config()
    config = apt_pkg.config
    return (set(config.value_list('Unattended-Upgrade::Allowed-Origins')) == set(ORIGINS)
            and not config.value_list('Unattended-Upgrade::Origins-Pattern')
            and not config.find_b('Unattended-Upgrade::Automatic-Reboot', False))


def installed_packages():
    result = subprocess.run(['/usr/bin/dpkg-query', '-W', '-f=${binary:Package}\t${Version}\t${db:Status-Status}\n'],
                            capture_output=True, text=True, check=True)
    packages = {}
    for line in result.stdout.splitlines():
        fields = line.split('\t')
        if len(fields) == 3 and fields[2] == 'installed':
            packages[fields[0]] = fields[1]
    return packages


def changes(before, after):
    return [{'package': name, 'before': before.get(name, '(new)'), 'after': version}
            for name, version in sorted(after.items()) if before.get(name) != version]


def run_update(dry_run=False, directory=DIRECTORY):
    report = {'run_id': str(time.time_ns()), 'started_at': time.time(),
              'status': 'running', 'dry_run': dry_run, 'stage': 'policy validation', 'changes': []}
    def persist():
        save_report(report, directory, filename='dry-run.json' if dry_run else 'status.json')
    persist()
    before = None
    exit_code = 1
    try:
        if not effective_policy_is_safe():
            raise RuntimeError('Effective APT policy differs from security-only/manual-reboot settings')
        before = installed_packages()
        environment = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C.UTF-8',
                       'DEBIAN_FRONTEND': 'noninteractive'}
        descriptor = os.open(str(directory / 'last-run.log'), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, 'w') as log:
            if not dry_run:
                report['stage'] = 'refreshing package lists'
                persist()
                refreshed = subprocess.run(['/usr/bin/apt-get', '-o', 'APT::Update::Error-Mode=any', 'update'],
                                           stdout=log, stderr=log, env=environment, timeout=300)
                if refreshed.returncode:
                    raise RuntimeError('APT metadata refresh failed; no upgrade was started')
                Path('/var/lib/apt/periodic').mkdir(parents=True, exist_ok=True)
                Path('/var/lib/apt/periodic/update-success-stamp').touch()
            report['stage'] = 'applying security updates' if not dry_run else 'security update dry run'
            persist()
            args = ['/usr/bin/unattended-upgrade']
            if dry_run:
                args.append('--dry-run')
            # Let dpkg finish; never forcibly time out a package installation.
            result = subprocess.run(args, stdout=log, stderr=log, env=environment)
            if result.returncode:
                raise RuntimeError('unattended-upgrade failed (exit %s)' % result.returncode)
        report['status'] = 'dry-run-complete' if dry_run else 'completed'
        exit_code = 0
    except (RuntimeError, OSError, ImportError, subprocess.SubprocessError) as exc:
        report['status'] = 'failed'
        report['error'] = str(exc) if isinstance(exc, RuntimeError) else type(exc).__name__
    finally:
        if before is not None:
            try:
                report['changes'] = changes(before, installed_packages())
            except (OSError, subprocess.SubprocessError):
                report['inventory_warning'] = 'Could not verify installed package versions after the run'
        report['reboot_required'] = Path('/var/run/reboot-required').exists()
        try:
            from security_checks import package_updates
            pending = [item['package'] for item in package_updates() if item['security']]
            report['pending_security'] = pending
        except Exception:
            report['pending_check_unavailable'] = True
        report['finished_at'] = time.time()
        persist()
    return exit_code


def configure(root=Path('/')):
    """Called only by the explicit installer --enable-security-updates option."""
    if os.geteuid() != 0:
        raise RuntimeError('Security-update configuration requires sudo')
    directory = root / 'var/lib/reimu-security-updates'
    directory.mkdir(parents=True, exist_ok=True, mode=0o755)
    if directory.is_symlink() or directory.stat().st_uid != 0:
        raise RuntimeError('Security-update state directory must be root-owned and not a symlink')
    os.chmod(directory, 0o755)
    policy = root / 'etc/apt/apt.conf.d/99zz-reimu-security-updates'
    policy.parent.mkdir(parents=True, exist_ok=True)
    if policy.exists() and policy.read_text() != POLICY:
        raise RuntimeError('Managed security-update policy was edited; review it before enabling')
    policy.write_text(POLICY)
    os.chmod(policy, 0o644)
    units = root / 'etc/systemd/system'
    units.mkdir(parents=True, exist_ok=True)
    (units / 'reimu-security-updates.service').write_text('''[Unit]
Description=Reimu automatic Ubuntu security updates (manual reboot)
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /opt/reimu-vps/security_updater.py
TimeoutStartSec=infinity
Nice=10
UMask=0077
''')
    (units / 'reimu-security-updates.timer').write_text('''[Unit]
Description=Daily Ubuntu security updates for Reimu

[Timer]
OnCalendar=*-*-* 03:00:00 Asia/Phnom_Penh
RandomizedDelaySec=1800
Persistent=true

[Install]
WantedBy=timers.target
''')
    # One scheduler owns installation. Do not interrupt an already-running update.
    subprocess.run(['systemctl', 'disable', '--now', 'apt-daily-upgrade.timer'], check=True)
    subprocess.run(['systemctl', 'daemon-reload'], check=True)
    subprocess.run(['systemctl', 'enable', '--now', 'reimu-security-updates.timer'], check=True)
    save_report({'enabled': True, 'schedule': 'Daily 03:00–03:30 Asia/Phnom_Penh',
                 'scope': 'Ubuntu security updates', 'automatic_reboot': False,
                 'enabled_at': time.time()}, directory, filename='configuration.json')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dry-run', action='store_true')
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('Run through the installed root-owned service, or use sudo for a dry run')
    if not DIRECTORY.exists() or DIRECTORY.is_symlink() or DIRECTORY.stat().st_uid != 0:
        parser.error('Run the installer with --enable-security-updates first')
    return run_update(args.dry_run)


if __name__ == '__main__':
    raise SystemExit(main())

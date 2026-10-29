"""Read-only maintenance checks. No upgrades, reboots, or firewall changes."""
from concurrent.futures import ThreadPoolExecutor
from datetime import date, datetime, timedelta, timezone
import ipaddress
import json
import logging
import os
from pathlib import Path
import re
import subprocess
import tempfile
import threading
import time
import urllib.request

LOG = logging.getLogger("reimu-maintenance")
REPOSITORY = "thunpanhasuon/reimu-vps-monitor"


def boolean(value):
    if value.lower() not in ("true", "false", "1", "0", "yes", "no"):
        raise ValueError("Expected true or false")
    return value.lower() in ("true", "1", "yes")


ENV_FIELDS = {
    "UPDATE_ALERTS": ("update_alerts", boolean, "true"),
    "REIMU_UPDATE_ALERTS": ("reimu_update_alerts", boolean, "true"),
    "PORT_ALERTS": ("port_alerts", boolean, "true"),
    "MAINTENANCE_INTERVAL_SECONDS": ("maintenance_interval", int, "21600"),
    "PORT_INTERVAL_SECONDS": ("port_interval", int, "60"),
    "EXPECTED_PORTS": ("expected_ports", str, "tcp:22"),
    "STATE_DIRECTORY": ("state_directory", str, ""),
    "TAILSCALE_KEY_EXPIRY": ("tailscale_key_expiry", str, ""),
}


def tailscale_reminder(expiry, today=None):
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", expiry):
        raise ValueError('TAILSCALE_KEY_EXPIRY must use YYYY-MM-DD')
    expires = date.fromisoformat(expiry)
    today = today or datetime.now(timezone(timedelta(hours=7))).date()
    days = (expires - today).days
    if days > 30:
        return None
    if days < 0:
        return 'passed', '⚠️ Tailscale expiry date has passed\nExpiry: %s\nNext step: Verify access and renew/re-authenticate the device.' % expiry
    stage = next(str(limit) for limit in (0, 1, 3, 7, 14, 30) if days <= limit)
    when = 'today' if days == 0 else 'in %s day(s)' % days
    return stage, '🔑 Tailscale key expires %s\nExpiry: %s\nNext step: Renew/re-authenticate before expiry to preserve remote access.' % (when, expiry)


def command(args, timeout=60):
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=timeout,
                                env={**os.environ, "LC_ALL": "C"})
    except FileNotFoundError:
        raise RuntimeError("Required tool is missing: " + args[0]) from None
    except subprocess.TimeoutExpired:
        raise RuntimeError(args[0] + " timed out") from None
    if result.returncode:
        raise RuntimeError(args[0] + " failed (exit %s)" % result.returncode)
    return result.stdout


def atomic_json(path, value):
    descriptor, temporary = tempfile.mkstemp(dir=path.parent, prefix=".state-")
    try:
        with os.fdopen(descriptor, "w") as output:
            json.dump(value, output, sort_keys=True)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def package_updates():
    try:
        import apt
    except ImportError:
        raise RuntimeError("Install python3-apt and use /usr/bin/python3 for package checks") from None
    cache = apt.Cache()
    changes = []
    for package in cache:
        if not package.is_installed or not package.is_upgradable or package.candidate is None:
            continue
        candidate = package.candidate
        security = any(origin.origin.startswith("Ubuntu") and "security" in origin.archive.lower()
                       for origin in candidate.origins)
        changes.append({"package": package.name, "installed": package.installed.version,
                        "candidate": candidate.version, "security": security})
    changes.sort(key=lambda item: item["package"])
    return changes


def apt_cache_age():
    stamp = Path("/var/lib/apt/periodic/update-success-stamp")
    if not stamp.exists():
        return None
    return max(0, time.time() - stamp.stat().st_mtime)


def reboot_required():
    if not Path("/var/run/reboot-required").exists():
        return []
    path = Path("/var/run/reboot-required.pkgs")
    packages = sorted(set(path.read_text().split())) if path.exists() else []
    return packages or ["system updates"]


def parse_listeners(text):
    listeners = {}
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 6 or fields[0] not in ("tcp", "udp"):
            continue
        protocol = fields[0]
        endpoint = fields[4]
        address, separator, port = endpoint.rpartition(":")
        if not separator or not port.isdigit():
            continue
        address = address.strip("[]")
        try:
            loopback = ipaddress.ip_address(address.split("%", 1)[0]).is_loopback
        except ValueError:
            loopback = False
        process = re.search(r'\("([^"\n]+)",pid=([0-9]+)', " ".join(fields[6:]))
        key = "%s|%s|%s" % (protocol, address, port)
        listeners[key] = dict(protocol=protocol, address=address, port=int(port),
                              scope="localhost" if loopback else "non-loopback",
                              process=process.group(1) if process else "not visible to service user")
    return listeners


def listening_ports():
    return parse_listeners(command(["ss", "-H", "-lntup"]))


def port_description(item):
    scope = 'local only' if item['scope'] == 'localhost' else 'network interface'
    text = '%s/%s · %s · %s' % (item['port'], item['protocol'].upper(), item['address'], scope)
    if item['process'] != 'not visible to service user':
        text += ' · ' + item['process']
    return text


def port_changes(previous, current, expected):
    expected = {part.strip() for part in expected.split(",") if part.strip()}
    messages = []
    for key in sorted(set(current) - set(previous)):
        item = current[key]
        was_local = any(old["protocol"] == item["protocol"] and old["port"] == item["port"]
                        and old["scope"] == "localhost" for old in previous.values())
        if "%s:%s" % (item["protocol"], item["port"]) in expected and not (was_local and item["scope"] != "localhost"):
            continue
        messages.append("➕ New listener · " + port_description(item))
    for key in sorted(set(previous) - set(current)):
        messages.append("➖ Listener stopped · " + port_description(previous[key]))
    return messages


def reimu_update():
    path = Path(__file__).resolve().parent / "build.json"
    if not path.exists():
        raise RuntimeError("Installed build identity missing; reinstall from the Git checkout")
    local = json.loads(path.read_text())["commit"]
    if not re.fullmatch(r"[0-9a-f]{40,64}", local):
        raise RuntimeError("Installed build identity is invalid")
    headers = {"User-Agent": "Reimu-VPS-Monitor", "Accept": "application/vnd.github+json"}
    base = "https://api.github.com/repos/" + REPOSITORY
    try:
        request = urllib.request.Request(base + "/git/ref/heads/main", headers=headers)
        with urllib.request.urlopen(request, timeout=30) as response:
            remote = json.load(response)["object"]["sha"]
        if remote == local:
            return ""
        request = urllib.request.Request(base + "/compare/%s...%s" % (local, remote), headers=headers)
        with urllib.request.urlopen(request, timeout=30) as response:
            comparison = json.load(response)
    except (OSError, ValueError):
        raise RuntimeError("Could not check Reimu updates on GitHub") from None
    if comparison.get("status") == "ahead":
        return remote
    if comparison.get("status") in ("behind", "diverged"):
        raise RuntimeError("Installed Reimu history differs from main; review manually")
    return ""


class Maintenance:
    def __init__(self, config, send):
        self.config, self.send = config, send
        path = config.get("state_directory") or str(Path.home() / ".local/state/reimu-vps")
        self.directory = Path(path)
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.path = self.directory / "state.json"
        try:
            self.state = json.loads(self.path.read_text()) if self.path.exists() else {}
        except (ValueError, OSError):
            raise RuntimeError("Maintenance state is unreadable; inspect " + str(self.path)) from None
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.thread = None

    def notify(self, key, value, messages, baseline=False):
        # Save only after every message is delivered, so failed sends retry next check.
        with self.lock:
            old = self.state.get(key)
            if old == value:
                return
            if messages and not (baseline and key not in self.state):
                text = "\n".join(messages)
                if len(text) > 3500:
                    text = text[:3300] + "\n… Message shortened; full check data is in the VPS state directory."
                self.send(self.config, text)
            self.state[key] = value
            atomic_json(self.path, self.state)

    def updates(self):
        packages = package_updates()
        count = sum(package["security"] for package in packages)
        messages = ['📦 Package updates available' if packages else '✅ Package updates cleared',
                    'Available: %s packages · %s security' % (len(packages), count), '']
        messages += ["%s: %s → %s%s" % (p["package"], p["installed"], p["candidate"], " [security]" if p["security"] else "") for p in packages[:12]]
        self.notify("packages", packages, messages, baseline=not packages)
        age = apt_cache_age()
        stale = age is None or age > 172800
        self.notify("apt_stale", stale, ["⚠️ Package metadata freshness is unverified or older than 48 hours. Check reimu-apt-refresh.service and run sudo apt-get update."] if stale else [], baseline=False)

    def reboot(self):
        packages = reboot_required()
        self.notify("reboot", packages, ["🔔 Reboot required: " + ", ".join(packages)] if packages else ["✅ Reboot-required flag cleared"], baseline=not packages)

    def tailscale_expiry(self):
        expiry = self.config['tailscale_key_expiry']
        self.notify('tailscale_expiry_configuration', expiry,
                    ['🔑 Tailscale reminder saved', 'Expiry: ' + expiry,
                     'Reminders: 30, 14, 7, 3 and 1 days before; on and after expiry.',
                     'Manual date; renewal is not automatic.']
                    if expiry else ['Tailscale key-expiry reminders disabled.'], baseline=not expiry)
        if not expiry:
            self.notify('tailscale_expiry_stage', '', [])
            return
        reminder = tailscale_reminder(expiry)
        if reminder is not None:
            stage, text = reminder
            self.notify('tailscale_expiry_stage', expiry + ':' + stage,
                        [text, 'Update the saved expiry date after renewal.'])

    def automatic_updates(self, directory=Path('/var/lib/reimu-security-updates')):
        configuration = directory / 'configuration.json'
        if not configuration.exists():
            return
        configured = json.loads(configuration.read_text())
        self.notify('automatic_update_configuration', {key: value for key, value in configured.items() if key != 'enabled_at'},
                    ['🛡️ Security updates enabled',
                     'Schedule: ' + configured['schedule'], 'Reboots: Manual'])
        path = directory / 'status.json'
        if not path.exists():
            if time.time() - configured.get('enabled_at', time.time()) > 30 * 3600:
                self.notify('automatic_update_missing', True, ['⚠️ No automatic security-update run recorded after 30 hours. Check reimu-security-updates.timer and its service.'])
            return
        report = json.loads(path.read_text())
        if report['status'] == 'running':
            if time.time() - report['started_at'] > 7200:
                self.notify('automatic_update_slow', report['run_id'],
                            ['⚠️ Security update has been running for over 2 hours or was interrupted. Inspect reimu-security-updates.service; do not kill dpkg blindly.'])
            return
        stale = time.time() - report.get('finished_at', time.time()) > 30 * 3600
        self.notify('automatic_update_missing', stale,
                    ['⚠️ Last automatic security-update result is older than 30 hours. Check reimu-security-updates.timer.'] if stale else [], baseline=not stale)
        with self.lock:
            previous = self.state.get('automatic_update_result', {})
        packages = report.get('changes', [])
        failed = report['status'] == 'failed'
        lines = []
        if failed or packages or previous.get('status') == 'failed' or report.get('inventory_warning'):
            lines = ['❌ Automatic security update failed' if failed else '✅ Automatic security update completed']
            if failed:
                lines += ['Stage: ' + report['stage'], 'Reason: ' + report.get('error', 'Unknown error'),
                          'Details: sudo journalctl -u reimu-security-updates; root-only last-run.log is in /var/lib/reimu-security-updates.']
            lines += ['%s: %s → %s' % (item['package'], item['before'], item['after']) for item in packages[:12]]
            if len(packages) > 12:
                lines.append('%s packages changed; full report is saved on the VPS.' % len(packages))
            if report.get('inventory_warning'):
                lines.append('⚠️ ' + report['inventory_warning'])
            if report.get('reboot_required'):
                lines.append('🔔 Reboot required; restart manually when ready.')
        pending = report.get('pending_security', [])
        self.notify('automatic_update_pending', pending,
                    ['⚠️ Security updates remain pending after the automatic run: ' + ', '.join(pending[:12]),
                     'Some packages may be held back or need manual attention.'] if pending else [], baseline=not pending)
        self.notify('automatic_update_result', {'run_id': report['run_id'], 'status': report['status']}, lines)

    def ports(self):
        current = listening_ports()
        with self.lock:
            previous = self.state.get("ports")
        if previous is None:
            messages = ['🔌 Network ports recorded', 'Listeners: %s' % len(current), '']
            messages += ['• ' + port_description(item) for item in list(current.values())[:12]]
        else:
            messages = port_changes(previous, current, self.config["expected_ports"])
        if messages:
            if previous is not None:
                messages.insert(0, '🔌 Network ports changed')
            messages += ['', 'Firewall reachability is not tested.']
        self.notify("ports", current, messages)


    def version(self):
        commit = reimu_update()
        self.notify("version", commit, ["🔔 Reimu update available on GitHub main: " + commit[:12],
                    "Update manually from https://github.com/" + REPOSITORY] if commit else ["✅ Reimu is up to date"], baseline=not commit)

    def guarded(self, name, action):
        try:
            action()
            self.notify("error:" + name, "", [])
        except Exception as exc:
            LOG.warning("%s check failed (%s)", name, type(exc).__name__)
            # Only our own sanitized errors are sent to Telegram.
            detail = str(exc) if isinstance(exc, RuntimeError) else type(exc).__name__
            try:
                self.notify("error:" + name, detail, ["⚠️ %s check unavailable: %s" % (name, detail)])
            except Exception:
                LOG.warning("Could not deliver maintenance failure notification")

    def run(self):
        tasks = {"reboot": (60, self.reboot), "automatic updates": (60, self.automatic_updates),
                 "Tailscale expiry": (3600, self.tailscale_expiry)}
        if self.config["port_alerts"]:
            tasks["ports"] = (self.config["port_interval"], self.ports)
        if self.config["update_alerts"]:
            tasks["updates"] = (self.config["maintenance_interval"], self.updates)
        if self.config["reimu_update_alerts"]:
            tasks["version"] = (self.config["maintenance_interval"], self.version)
        due, pending = {}, {}
        with ThreadPoolExecutor(max_workers=3, thread_name_prefix="reimu-check") as pool:
            while not self.stop.is_set():
                for name, (interval, action) in tasks.items():
                    if name in pending and pending[name].done():
                        del pending[name]
                        due[name] = time.monotonic() + interval
                    if name not in pending and time.monotonic() >= due.get(name, 0):
                        pending[name] = pool.submit(self.guarded, name, action)
                self.stop.wait(2)

    def start(self):
        self.thread = threading.Thread(target=self.run, daemon=True, name="reimu-maintenance")
        self.thread.start()

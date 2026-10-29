#!/usr/bin/env python3
"""Linux VPS -> Telegram alerts. Python 3.8+, standard library only.

  python3 vps_monitor.py setup
  python3 vps_monitor.py test
  python3 vps_monitor.py run
  sudo python3 vps_monitor.py install --config /absolute/path/to/.env

Default config: .env beside this script
No inbound ports, bot commands, or remote shell execution.
"""
import argparse
import getpass
import json
import logging
import math
import os
from pathlib import Path
import pwd
import re
import secrets
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import security_checks
from alert_format import format_alert

LOG = logging.getLogger("vps-monitor")
DEFAULT_CONFIG = Path(__file__).resolve().parent / ".env"
ENV_FIELDS = {
    "TELEGRAM_BOT_TOKEN": ("token", str, ""),
    "TELEGRAM_CHAT_ID": ("chat_id", str, ""),
    "SERVER_NAME": ("name", str, "ubuntu-flandre"),
    "CHECK_INTERVAL_SECONDS": ("interval_seconds", float, "15"),
    "SUSTAINED_SECONDS": ("sustained_seconds", float, "120"),
    "REMINDER_SECONDS": ("reminder_seconds", float, "1800"),
    "CPU_THRESHOLD": ("cpu_percent", float, "90"),
    "RAM_THRESHOLD": ("ram_percent", float, "90"),
    "DISK_THRESHOLD": ("disk_percent", float, "85"),
    "DISK_PATH": ("disk_path", str, "/"),
    "NETWORK_INTERFACE": ("network_interface", str, "auto"),
    "NETWORK_MBPS": ("network_mbps", float, "100"),
}
ENV_FIELDS.update(security_checks.ENV_FIELDS)
RETIRED_SETTINGS = {'CVE_ALERTS', 'CVE_INTERVAL_SECONDS'}
SEND_LOCK = threading.Lock()
SEND_LAST = 0.0


def read_env(path):
    values = {}
    if not path.exists():
        return values
    for number, line in enumerate(path.read_text().splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if separator and key.strip() in RETIRED_SETTINGS:
            continue
        if not separator or key.strip() not in ENV_FIELDS:
            raise RuntimeError("Invalid .env setting on line %d" % number)
        value = value.strip()
        if value.startswith(('"', "'")):
            if len(value) < 2 or value[-1] != value[0]:
                raise RuntimeError("Unclosed .env quote on line %d" % number)
            value = value[1:-1]
        values[key.strip()] = value
    return values


class TelegramConnectionError(RuntimeError):
    """A transport failure that pairing can safely retry."""


def connection_error(reason):
    if isinstance(reason, ssl.SSLCertVerificationError):
        return RuntimeError("Telegram TLS certificate verification failed; check server time and CA certificates.")
    if isinstance(reason, socket.gaierror):
        detail = "DNS lookup failed for api.telegram.org"
    elif isinstance(reason, (TimeoutError, socket.timeout)):
        detail = "request timed out"
    elif isinstance(reason, ssl.SSLError):
        detail = "TLS connection failed"
    elif isinstance(reason, ConnectionResetError):
        detail = "connection was reset"
    else:
        # Do not print arbitrary exception text: it can contain the token URL.
        detail = "network connection failed (%s)" % type(reason).__name__
    return TelegramConnectionError("Telegram: " + detail)


def api(token, method, **params):
    """Never expose a token-bearing URL through an exception or log."""
    data = urllib.parse.urlencode(params).encode()
    url = "https://api.telegram.org/bot" + token + "/" + method
    try:
        with urllib.request.urlopen(url, data=data, timeout=max(30, int(params.get("timeout", 0)) + 15)) as response:
            result = json.load(response)
    except urllib.error.HTTPError as exc:
        details = {401: "invalid or revoked bot token", 403: "bot blocked or chat access denied",
                   409: "another bot poller or webhook is using this bot",
                   429: "rate limited; wait before trying again"}
        error_type = TelegramConnectionError if exc.code >= 500 else RuntimeError
        raise error_type("Telegram HTTP %s: %s" % (exc.code, details.get(exc.code, "request rejected"))) from None
    except urllib.error.URLError as exc:
        raise connection_error(exc.reason) from None
    except (OSError, TimeoutError) as exc:
        raise connection_error(exc) from None
    except (ValueError, UnicodeError):
        raise TelegramConnectionError("Telegram returned an unreadable response") from None
    if not result.get("ok"):
        raise RuntimeError("Telegram rejected the request.")
    return result["result"]


def wait_for_pairing(token, code, seconds=180):
    deadline, offset = time.monotonic() + seconds, 0
    last_error = None
    while time.monotonic() < deadline:
        try:
            # Short polling avoids holding an idle HTTPS request open during setup.
            updates = api(token, "getUpdates", offset=offset, timeout=0,
                          allowed_updates=json.dumps(["message"]))
            last_error = None
        except TelegramConnectionError as exc:
            last_error = str(exc)
            print(last_error + "; retrying in 3 seconds...", flush=True)
            time.sleep(3)
            continue
        for update in updates:
            offset = update["update_id"] + 1
            message = update.get("message", {})
            if message.get("text", "").strip() == code and message.get("chat", {}).get("type") == "private":
                return message["chat"]["id"]
        time.sleep(2)
    detail = " Last error: " + last_error if last_error else ""
    raise RuntimeError("Pairing timed out. Run setup again and send the new pairing code." + detail)


def send(config, text):
    global SEND_LAST
    # Resource and maintenance threads share one chat: avoid startup bursts.
    with SEND_LOCK:
        delay = 1.1 - (time.monotonic() - SEND_LAST)
        if delay > 0:
            time.sleep(delay)
        try:
            api(config["token"], "sendMessage", chat_id=config["chat_id"],
                text=format_alert(config, text), parse_mode='HTML',
                link_preview_options=json.dumps({'is_disabled': True}))
        finally:
            SEND_LAST = time.monotonic()


def setup(path):
    if not sys.stdin.isatty():
        raise RuntimeError("Run this saved file from an interactive SSH terminal.")
    existing = read_env(path)
    token = existing.get("TELEGRAM_BOT_TOKEN", "").strip()
    if not token or token == "paste_your_bot_token_here":
        token = getpass.getpass("Bot token (hidden): ").strip()
    if not re.fullmatch(r"\d+:[A-Za-z0-9_-]+", token):
        raise RuntimeError("The token format looks incorrect.")
    bot = api(token, "getMe")
    if api(token, "getWebhookInfo").get("url"):
        raise RuntimeError("This bot has a webhook. Use a dedicated monitoring bot without a webhook.")
    code = "pair-" + secrets.token_hex(4)
    print("\nOpen https://t.me/%s and send this exact message:\n\n%s\n" % (bot["username"], code))
    print("Waiting up to 3 minutes for your message...", flush=True)
    chat_id = wait_for_pairing(token, code)
    existing["TELEGRAM_BOT_TOKEN"] = token
    existing["TELEGRAM_CHAT_ID"] = str(chat_id)
    config = {key: convert(existing.get(env, default))
              for env, (key, convert, default) in ENV_FIELDS.items()}
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    # Restrictive permissions from the moment the file is opened.
    descriptor = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.fchmod(descriptor, 0o600)
    with os.fdopen(descriptor, "w") as output:
        for env, (_, _, default) in ENV_FIELDS.items():
            output.write(env + "=" + existing.get(env, default) + "\n")
    print("Saved private configuration:", path)
    try:
        send(config, "✅ Connected. Run the monitor or install its service to start alerts.")
    except RuntimeError as exc:
        print("Pairing saved, but confirmation could not be sent: " + str(exc))
    print("Next: python3 vps_monitor.py test")


def load(path):
    try:
        values = read_env(path)
        config = {key: convert(values.get(env, default))
                  for env, (key, convert, default) in ENV_FIELDS.items()}
    except (OSError, ValueError):
        raise RuntimeError("Cannot read .env; check paths and numeric settings.") from None
    for key in ("token", "chat_id", "name", "disk_path", "network_interface"):
        if not config.get(key):
            raise RuntimeError("Missing configuration field: " + key)
    for key in ("interval_seconds", "sustained_seconds", "reminder_seconds"):
        if not isinstance(config.get(key), (int, float)) or not math.isfinite(config[key]) or config[key] < 1:
            raise RuntimeError("Invalid positive setting: " + key)
    for key in ("cpu_percent", "ram_percent", "disk_percent"):
        if not isinstance(config.get(key), (int, float)) or not 1 <= config[key] <= 100:
            raise RuntimeError("Invalid percentage: " + key)
    if not isinstance(config.get("network_mbps"), (int, float)) or not math.isfinite(config["network_mbps"]) or config["network_mbps"] < 0:
        raise RuntimeError("network_mbps must be nonnegative; 0 disables traffic alerts.")
    for key in ("maintenance_interval", "port_interval"):
        if config[key] < 30:
            raise RuntimeError(key + " must be at least 30 seconds")
    for entry in config["expected_ports"].split(","):
        if entry.strip() and not re.fullmatch(r"(?:tcp|udp):(?:[0-9]{1,5})", entry.strip()):
            raise RuntimeError("EXPECTED_PORTS must contain comma-separated tcp:PORT or udp:PORT entries")
        if entry.strip() and not 1 <= int(entry.strip().split(":")[1]) <= 65535:
            raise RuntimeError("EXPECTED_PORTS contains an invalid port")
    if config['tailscale_key_expiry']:
        try:
            security_checks.tailscale_reminder(config['tailscale_key_expiry'])
        except ValueError:
            raise RuntimeError('TAILSCALE_KEY_EXPIRY must be a valid YYYY-MM-DD date') from None
    return config


def interface(config):
    if config["network_interface"] != "auto":
        return config["network_interface"]
    for line in Path("/proc/net/route").read_text().splitlines()[1:]:
        fields = line.split()
        if fields[1] == "00000000" and int(fields[3], 16) & 1:
            return fields[0]
    raise RuntimeError("No default IPv4 route; set network_interface in the configuration.")


def counters(nic):
    # Guest and guest_nice are already included in user and nice.
    cpu = [int(x) for x in Path("/proc/stat").read_text().splitlines()[0].split()[1:9]]
    idle = cpu[3] + cpu[4]
    for line in Path("/proc/net/dev").read_text().splitlines()[2:]:
        name, values = line.split(":", 1)
        if name.strip() == nic:
            parts = values.split()
            return sum(cpu), idle, int(parts[0]), int(parts[8]), time.monotonic()
    raise RuntimeError("Network interface disappeared: " + nic)


def metrics(previous, current, disk_path):
    total = current[0] - previous[0]
    cpu = 100 * (1 - (current[1] - previous[1]) / total) if total > 0 else 0
    memory = {}
    for line in Path("/proc/meminfo").read_text().splitlines():
        key, value = line.split(":", 1)
        memory[key] = int(value.split()[0])
    ram = 100 * (1 - memory["MemAvailable"] / memory["MemTotal"])
    disk = shutil.disk_usage(disk_path)
    elapsed = max(0.001, current[4] - previous[4])
    rx = max(0, current[2] - previous[2]) * 8 / elapsed / 1e6
    tx = max(0, current[3] - previous[3]) * 8 / elapsed / 1e6
    return {"CPU": max(0, min(100, cpu)), "RAM": ram,
            "Disk": disk.used / disk.total * 100, "Incoming traffic": rx,
            "Outgoing traffic": tx}


class Alert:
    def __init__(self):
        self.since = None
        self.active = False
        self.last_sent = float("-inf")

    def check(self, value, threshold, now, sustained, reminder):
        if value >= threshold:
            if self.since is None:
                self.since = now
            if now - self.since >= sustained and now - self.last_sent >= reminder:
                return "⚠️ HIGH" if not self.active else "⚠️ STILL HIGH"
        else:
            self.since = None
            # Hysteresis prevents repeated high/recovery alerts at the boundary.
            if self.active and value < threshold * 0.95:
                return "✅ RECOVERED"
        return None

    def delivered(self, event, now):
        self.active = "RECOVERED" not in event
        self.last_sent = now if self.active else float("-inf")


def monitor(config):
    nic = interface(config)
    previous = counters(nic)
    limits = {"CPU": config["cpu_percent"], "RAM": config["ram_percent"],
              "Disk": config["disk_percent"]}
    if config["network_mbps"]:
        limits.update({"Incoming traffic": config["network_mbps"],
                       "Outgoing traffic": config["network_mbps"]})
    alerts = {key: Alert() for key in limits}
    startup_pending = True
    stopping = False

    def stop(signum, frame):
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    maintenance = security_checks.Maintenance(config, send)
    maintenance.start()
    LOG.info("Monitoring %s on interface %s", config["name"], nic)
    while not stopping:
        # Interruptible wait, with metrics sampled over the full interval.
        end = time.monotonic() + config["interval_seconds"]
        while not stopping and time.monotonic() < end:
            time.sleep(min(0.5, max(0, end - time.monotonic())))
        if stopping:
            break
        try:
            current = counters(nic)
            values = metrics(previous, current, config["disk_path"])
            previous = current
            now = time.monotonic()
            if startup_pending:
                send(config, "🟢 Monitoring started\nHost: " + socket.gethostname())
                startup_pending = False
            rows = []
            for key, value in values.items():
                unit = '%'
                if 'traffic' in key:
                    unit = 'Mbps'
                    if value < 1:
                        value, unit = value * 1000, 'Kbps'
                rows.append('%s: %.1f %s' % (key, value, unit))
            summary = '\n'.join(rows)
            for key, threshold in limits.items():
                alert = alerts[key]
                event = alert.check(values[key], threshold, now,
                                    config["sustained_seconds"], config["reminder_seconds"])
                if event:
                    note = "\nTraffic threshold exceeded; this alone does not confirm a DoS attack." if "traffic" in key else ""
                    unit = 'Mbps' if 'traffic' in key else '%'
                    context = ('Recovery: Below %.1f %s' % (threshold * 0.95, unit)
                               if 'RECOVERED' in event else
                               'Threshold: %.1f %s\nDuration: At least %s seconds' % (threshold, unit, config['sustained_seconds']))
                    send(config, event + " — " + key + "\n\n" + summary + '\n' + context + note)
                    alert.delivered(event, now)
                    LOG.info("%s: %s", key, event)
        except (RuntimeError, OSError, ValueError, KeyError) as exc:
            # Only our sanitized Telegram errors and local metric errors reach this log.
            LOG.warning("%s; retrying next interval", exc)
    maintenance.stop.set()
    LOG.info("Monitor stopped")


def install(path, root=Path("/"), enable_security_updates=False, tailscale_key_expiry=None):
    if os.geteuid() != 0:
        raise RuntimeError("Installation needs sudo. Setup and testing do not.")
    config = load(path)
    if enable_security_updates and not Path('/usr/bin/unattended-upgrade').exists():
        raise RuntimeError('Install unattended-upgrades first: sudo apt-get install unattended-upgrades')
    # Read before opening the destination: updates may use the installed .env itself.
    private_config = ('\n'.join(line for line in path.read_text().splitlines()
                       if line.partition('=')[0].strip() not in RETIRED_SETTINGS) + '\n').encode()
    if tailscale_key_expiry is not None:
        try:
            security_checks.tailscale_reminder(tailscale_key_expiry)
        except ValueError:
            raise RuntimeError('--tailscale-key-expiry must be a valid YYYY-MM-DD date') from None
        private_config += ('\nTAILSCALE_KEY_EXPIRY=' + tailscale_key_expiry + '\n').encode()
    if config["state_directory"] not in ("", "/var/lib/reimu-vps"):
        raise RuntimeError("Installed service requires STATE_DIRECTORY=/var/lib/reimu-vps")
    owner = pwd.getpwuid(path.stat().st_uid)
    source = Path(__file__).resolve().parent
    try:
        commit = subprocess.run(["git", "-c", "safe.directory=" + str(source), "-C", str(source), "rev-parse", "HEAD"],
                                check=True, capture_output=True, text=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        raise RuntimeError("Install from a Git clone so Reimu can track its installed version") from None
    if not re.fullmatch(r"[0-9a-f]{40,64}", commit):
        raise RuntimeError("Invalid Git build identity")
    dest = root / "opt/reimu-vps"
    dest.mkdir(mode=0o755, parents=True, exist_ok=True)
    shutil.copyfile(Path(__file__).resolve(), dest / "vps_monitor.py")
    os.chmod(dest / "vps_monitor.py", 0o644)
    shutil.copyfile(Path(__file__).resolve().parent / "security_checks.py", dest / "security_checks.py")
    os.chmod(dest / "security_checks.py", 0o644)
    shutil.copyfile(source / 'alert_format.py', dest / 'alert_format.py')
    os.chmod(dest / 'alert_format.py', 0o644)
    shutil.copyfile(source / "security_updater.py", dest / "security_updater.py")
    os.chmod(dest / "security_updater.py", 0o644)
    (dest / "build.json").write_text(json.dumps({"commit": commit}))
    target = root / "etc/reimu-vps.env"
    descriptor, temporary = security_checks.tempfile.mkstemp(dir=target.parent, prefix=".reimu-env-")
    with os.fdopen(descriptor, "wb") as output:
        output.write(private_config)
        # StateDirectory is writable despite the service sandbox.
        if not config["state_directory"]:
            output.write(b"\nSTATE_DIRECTORY=/var/lib/reimu-vps\n")
    os.replace(temporary, target)
    os.chown(target, owner.pw_uid, owner.pw_gid)
    state = root / "var/lib/reimu-vps"
    state.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chown(state, owner.pw_uid, owner.pw_gid)
    unit = """[Unit]
Description=Reimu VPS Telegram Monitor
Wants=network-online.target
After=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
User=%s
ExecStart=/usr/bin/python3 /opt/reimu-vps/vps_monitor.py run --config /etc/reimu-vps.env
Restart=on-failure
RestartSec=15
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
StateDirectory=reimu-vps
StateDirectoryMode=0700
ReadWritePaths=/var/lib/reimu-vps
CapabilityBoundingSet=
RestrictSUIDSGID=true
UMask=0077

[Install]
WantedBy=multi-user.target
""" % owner.pw_name
    (root / "etc/systemd/system").mkdir(parents=True, exist_ok=True)
    (root / "etc/systemd/system/reimu-vps.service").write_text(unit)
    (root / "etc/systemd/system/reimu-apt-refresh.service").write_text("""[Unit]
Description=Refresh APT metadata for Reimu alerts (no package upgrades)
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/bin/apt-get -o APT::Update::Error-Mode=any update
ExecStartPost=/usr/bin/touch /var/lib/apt/periodic/update-success-stamp
TimeoutStartSec=300
Nice=10
""")
    (root / "etc/systemd/system/reimu-apt-refresh.timer").write_text("""[Unit]
Description=Refresh package lists daily for Reimu

[Timer]
OnCalendar=daily
RandomizedDelaySec=1800
Persistent=true

[Install]
WantedBy=timers.target
""")
    (root / "var/lib/apt/periodic").mkdir(parents=True, exist_ok=True)
    subprocess.run(["systemctl", "daemon-reload"], check=True)
    subprocess.run(["systemctl", "enable", "--now", "reimu-apt-refresh.timer"], check=True)
    subprocess.run(["systemctl", "start", "--no-block", "reimu-apt-refresh.service"], check=True)
    if enable_security_updates:
        import security_updater
        security_updater.configure(root)
    subprocess.run(["systemctl", "enable", "reimu-vps.service"], check=True)
    subprocess.run(["systemctl", "restart", "reimu-vps.service"], check=True)
    print("Installed. Runs after SSH disconnects and starts at boot.")
    print("Status: sudo systemctl status reimu-vps --no-pager")
    print("Logs:   sudo journalctl -u reimu-vps -n 30 --no-pager")
    print("Edit thresholds: sudo nano /etc/reimu-vps.env")
    print("Then restart: sudo systemctl restart reimu-vps")
    if enable_security_updates:
        print("Automatic Ubuntu security updates enabled: daily 03:00–03:30 Cambodia time.")
        print("Reboots remain manual. Regular feature updates and Reimu updates remain manual.")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("command", choices=["setup", "test", "run", "install", "check"])
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--enable-security-updates", action="store_true",
                        help="With install: enable daily Ubuntu security updates, keeping reboots manual")
    parser.add_argument('--tailscale-key-expiry', help='With install: save the supplied expiry date (YYYY-MM-DD)')
    args = parser.parse_args()
    if args.enable_security_updates and args.command != 'install':
        parser.error('--enable-security-updates is only valid with install')
    if args.tailscale_key_expiry is not None and args.command != 'install':
        parser.error('--tailscale-key-expiry is only valid with install')
    path = args.config.expanduser().resolve()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    try:
        if args.command == "setup":
            setup(path)
        elif args.command == "install":
            install(path, enable_security_updates=args.enable_security_updates,
                    tailscale_key_expiry=args.tailscale_key_expiry)
        else:
            config = load(path)
            if args.command == "test":
                send(config, "✅ Test successful. This VPS can send Telegram alerts.")
                print("Test sent. Check Telegram.")
            elif args.command == "check":
                checks = security_checks.Maintenance(config, send)
                for name, action in (("updates", checks.updates), ("reboot", checks.reboot),
                                     ("ports", checks.ports), ("version", checks.version)):
                    checks.guarded(name, action)
                print("Checks completed. Inspect Telegram and logs for findings or unavailable checks.")
            else:
                monitor(config)
    except KeyboardInterrupt:
        print("\nCancelled.")
        return 130
    except (RuntimeError, OSError, ValueError, subprocess.CalledProcessError) as exc:
        print("Error:", exc, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

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
import os
from pathlib import Path
import pwd
import re
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

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


def read_env(path):
    values = {}
    if not path.exists():
        return values
    for number, line in enumerate(path.read_text().splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if not separator or key.strip() not in ENV_FIELDS:
            raise RuntimeError("Invalid .env setting on line %d" % number)
        value = value.strip()
        if value.startswith(('"', "'")):
            if len(value) < 2 or value[-1] != value[0]:
                raise RuntimeError("Unclosed .env quote on line %d" % number)
            value = value[1:-1]
        values[key.strip()] = value
    return values


def api(token, method, **params):
    """Never expose a token-bearing URL through an exception or log."""
    data = urllib.parse.urlencode(params).encode()
    url = "https://api.telegram.org/bot" + token + "/" + method
    try:
        with urllib.request.urlopen(url, data=data, timeout=25) as response:
            result = json.load(response)
    except urllib.error.HTTPError as exc:
        raise RuntimeError("Telegram HTTP %s; check token, permissions, rate limits or webhook conflicts."
                           % exc.code) from None
    except Exception:
        raise RuntimeError("Cannot reach Telegram; check DNS and internet access.") from None
    if not result.get("ok"):
        raise RuntimeError("Telegram rejected the request.")
    return result["result"]


def send(config, text):
    api(config["token"], "sendMessage", chat_id=config["chat_id"],
        text=config["name"] + "\n" + text)


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
    deadline, offset, chat_id = time.monotonic() + 180, 0, None
    while time.monotonic() < deadline and chat_id is None:
        for update in api(token, "getUpdates", offset=offset, timeout=10,
                          allowed_updates=json.dumps(["message"])):
            offset = update["update_id"] + 1
            message = update.get("message", {})
            if message.get("text", "").strip() == code and message.get("chat", {}).get("type") == "private":
                chat_id = message["chat"]["id"]
                break
    if chat_id is None:
        raise RuntimeError("Pairing timed out. Run setup again and send the new pairing code.")
    existing["TELEGRAM_BOT_TOKEN"] = token
    existing["TELEGRAM_CHAT_ID"] = str(chat_id)
    config = {key: convert(existing.get(env, default))
              for env, (key, convert, default) in ENV_FIELDS.items()}
    send(config, "✅ Connected. Run the monitor or install its service to start alerts.")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    # Restrictive permissions from the moment the file is opened.
    descriptor = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.fchmod(descriptor, 0o600)
    with os.fdopen(descriptor, "w") as output:
        for env, (_, _, default) in ENV_FIELDS.items():
            output.write(env + "=" + existing.get(env, default) + "\n")
    print("Saved private configuration:", path)
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
        if not isinstance(config.get(key), (int, float)) or config[key] < 1:
            raise RuntimeError("Invalid positive setting: " + key)
    for key in ("cpu_percent", "ram_percent", "disk_percent"):
        if not isinstance(config.get(key), (int, float)) or not 1 <= config[key] <= 100:
            raise RuntimeError("Invalid percentage: " + key)
    if not isinstance(config.get("network_mbps"), (int, float)) or config["network_mbps"] < 0:
        raise RuntimeError("network_mbps must be nonnegative; 0 disables traffic alerts.")
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
                send(config, "🟢 Monitoring started on " + socket.gethostname())
                startup_pending = False
            summary = "\n".join("%s: %.1f %s" % (key, value, "Mbps" if "traffic" in key else "%")
                                for key, value in values.items())
            for key, threshold in limits.items():
                alert = alerts[key]
                event = alert.check(values[key], threshold, now,
                                    config["sustained_seconds"], config["reminder_seconds"])
                if event:
                    note = "\nTraffic threshold exceeded; this alone does not confirm a DoS attack." if "traffic" in key else ""
                    send(config, event + " — " + key + "\n" + summary + note)
                    alert.delivered(event, now)
                    LOG.info("%s: %s", key, event)
        except (RuntimeError, OSError, ValueError, KeyError) as exc:
            # Only our sanitized Telegram errors and local metric errors reach this log.
            LOG.warning("%s; retrying next interval", exc)
    LOG.info("Monitor stopped")


def install(path):
    if os.geteuid() != 0:
        raise RuntimeError("Installation needs sudo. Setup and testing do not.")
    load(path)
    owner = pwd.getpwuid(path.stat().st_uid)
    dest = Path("/opt/reimu-vps")
    dest.mkdir(mode=0o755, parents=True, exist_ok=True)
    shutil.copyfile(Path(__file__).resolve(), dest / "vps_monitor.py")
    os.chmod(dest / "vps_monitor.py", 0o644)
    target = Path("/etc/reimu-vps.env")
    descriptor = os.open(str(target), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.fchmod(descriptor, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(path.read_bytes())
    os.chown(target, owner.pw_uid, owner.pw_gid)
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
CapabilityBoundingSet=
RestrictSUIDSGID=true
UMask=0077

[Install]
WantedBy=multi-user.target
""" % owner.pw_name
    Path("/etc/systemd/system/reimu-vps.service").write_text(unit)
    subprocess.run(["systemctl", "daemon-reload"], check=True)
    subprocess.run(["systemctl", "enable", "--now", "reimu-vps.service"], check=True)
    print("Installed. Runs after SSH disconnects and starts at boot.")
    print("Status: sudo systemctl status reimu-vps --no-pager")
    print("Logs:   sudo journalctl -u reimu-vps -n 30 --no-pager")
    print("Edit thresholds: sudo nano /etc/reimu-vps.env")
    print("Then restart: sudo systemctl restart reimu-vps")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("command", choices=["setup", "test", "run", "install"])
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    args = parser.parse_args()
    path = args.config.expanduser().resolve()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    try:
        if args.command == "setup":
            setup(path)
        elif args.command == "install":
            install(path)
        else:
            config = load(path)
            if args.command == "test":
                send(config, "✅ Test successful. This VPS can send Telegram alerts.")
                print("Test sent. Check Telegram.")
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

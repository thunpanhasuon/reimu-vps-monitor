# Reimu VPS Monitor

Telegram alerts for CPU, RAM, disk usage, and network traffic on a Linux VPS.
Python 3.8+ and systemd; no pip packages, domain, or inbound ports required.

## Install on your VPS

Clone this repository, enter its directory, then run:

```bash
cp .env.example .env
chmod 600 .env
nano .env
```

Paste your bot token after `TELEGRAM_BOT_TOKEN=` and save. Leave
`TELEGRAM_CHAT_ID` empty; setup will fill it for you. Keep `.env` private;
Git ignores it. The committed `.env.example` contains placeholders only.

```bash
python3 vps_monitor.py setup
```

Open your bot in Telegram, press Start, and send the exact pairing code
displayed in your SSH terminal. Setup waits up to three minutes and saves
your chat ID. It preserves the other settings already in `.env`.

```bash
python3 vps_monitor.py test
sudo python3 vps_monitor.py install --config "$PWD/.env"
sudo systemctl status reimu-vps --no-pager
```

The installer copies the script into `/opt/reimu-vps`, copies the private
configuration to `/etc/reimu-vps.env`, and starts `reimu-vps.service`.
The service runs as the owner of your `.env` file, starts after reboot,
and continues when SSH disconnects. Do not also run a second foreground
monitor, or you will receive duplicate alerts.

## Alerts

Defaults: CPU 90%, RAM 90%, disk 85%, incoming or outgoing traffic 100 Mbps.
A threshold must remain exceeded for 120 seconds, sampled every 15 seconds.
Ongoing incidents send reminders every 30 minutes. Recovery messages are
sent once usage drops below 95% of the configured threshold. RAM usage
uses Linux MemAvailable, so reclaimable cache is not treated as full RAM.
Disk monitoring covers the filesystem at DISK_PATH, `/` by default.

Traffic alerts report usage, not a confirmed DoS/DDoS attack. Set NETWORK_MBPS
for your normal workload, or use 0 to disable traffic alerts. Automatic
interface discovery uses the default IPv4 route; set NETWORK_INTERFACE
explicitly if needed. Provider-filtered traffic might never reach the VPS.

A monitor on the VPS cannot report a complete VPS/network outage while
offline. Use a separate external uptime monitor for that. This version
does not monitor individual application health or offer remote bot commands.
Alerts retry on subsequent samples when Telegram is unavailable; in-memory
incident state resets if the monitoring process restarts.

## Configure the installed service

```bash
sudo nano /etc/reimu-vps.env
sudo systemctl restart reimu-vps
sudo journalctl -u reimu-vps -n 50 --no-pager
```

After installation, editing the repository's `.env` does not change the
service configuration. Edit `/etc/reimu-vps.env` instead.

To test in the foreground before installing:

```bash
python3 vps_monitor.py run
```

Press Ctrl+C to stop. To stop the installed service:

```bash
sudo systemctl disable --now reimu-vps
```

## Development

```bash
python3 -m unittest discover -s tests -v
```

The tests simulate Linux metrics and Telegram requests. A live Telegram
connection and systemd installation must be verified on the target VPS.

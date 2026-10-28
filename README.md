# Reimu VPS Monitor

Telegram alerts for CPU, RAM, disk usage, and network traffic on a Linux VPS.
Python 3.8+ and systemd; no pip packages, domain, or inbound ports required.

## Install on your VPS

Clone this repository, enter its directory, then run:

```bash
sudo apt-get update
sudo apt-get install -y python3-apt openscap-scanner iproute2
cp .env.example .env
chmod 600 .env
nano .env
```

Paste your bot token after `TELEGRAM_BOT_TOKEN=` and save. Leave
`TELEGRAM_CHAT_ID` empty; setup will fill it for you. Keep `.env` private;
Git ignores it. The committed `.env.example` contains placeholders only.

```bash
/usr/bin/python3 vps_monitor.py setup
```

Open your bot in Telegram, press Start, and send the exact pairing code
displayed in your SSH terminal. Setup waits up to three minutes and saves
your chat ID. It preserves the other settings already in `.env`.

```bash
/usr/bin/python3 vps_monitor.py test
sudo /usr/bin/python3 vps_monitor.py install --config "$PWD/.env"
sudo systemctl status reimu-vps --no-pager
```

The installer copies the script into `/opt/reimu-vps`, copies the private
configuration to `/etc/reimu-vps.env`, and starts `reimu-vps.service`.
The service runs as the owner of your `.env` file, starts after reboot,
and continues when SSH disconnects. Do not also run a second foreground
monitor, or you will receive duplicate alerts.

The installer also enables a daily `reimu-apt-refresh.timer`. It refreshes
APT package metadata only; it does not install package upgrades. The
maintenance checks use Ubuntu's system Python and the official APT and
OpenSCAP packages listed above. A separate Ubuntu package such as
unattended-upgrades may already apply updates independently of Reimu.

## Update an existing installation

```bash
git pull --ff-only
sudo apt-get update
sudo apt-get install -y python3-apt openscap-scanner iproute2
sudo /usr/bin/python3 vps_monitor.py install --config /etc/reimu-vps.env
sudo systemctl status reimu-vps --no-pager
```

The installer preserves the installed credentials, restarts the service,
and uses defaults for any new settings missing from your older `.env`.
Do not run `setup` again just to update. Installed build identity is
recorded so update notifications compare against the version actually running.

## Maintenance and security alerts

| Check | Default frequency | Behavior |
| --- | --- | --- |
| Package and security updates | Every 6 hours | Reports pending APT packages and versions, with security-origin labels |
| Reboot required | Every minute | Reports Ubuntu's reboot-required flag and when it clears |
| Ubuntu CVEs | Daily | Downloads Canonical CVE OVAL data and evaluates installed packages using OpenSCAP |
| Reimu updates | Every 6 hours | Checks GitHub main against the installed Git commit |
| Listening-port changes | Every minute | Reports new or stopped TCP/UDP listeners and binding changes |

Checks run on startup, then at these intervals. Only changed results are
reported. State persists under `/var/lib/reimu-vps`, so restarting does not
repeat unchanged maintenance alerts. These checks run separately from CPU
sampling. A failed check is reported as unavailable, never as an all-clear.

The first port check records and reports a baseline. `EXPECTED_PORTS=tcp:22`
suppresses expected new SSH listeners; it still reports a port changing from
localhost to a non-loopback address. Stopped listeners are reported. Listening
on a non-loopback address is **not proof of internet reachability**; Reimu does
not change or probe firewalls. Process names may be unavailable for processes
owned by another user. Short-lived listeners between checks may be missed.

CVE alerts show the Canonical severity, CVE ID, installed package or running
kernel evidence, and the fixed version when supplied by the assessment.
For APT packages, candidate availability is checked against your enabled
repositories using Debian version comparison. Kernel findings link to the
Ubuntu advisory for package-specific remediation. Some fixes require Ubuntu
Pro/ESM. Potentially affected packages
are labeled as such. This covers Ubuntu APT package assessments, not pip/npm
dependencies, Docker images, custom builds, or every third-party PPA.
An old vulnerable kernel package can match even when a newer kernel is
running; assess the listed installed package and reboot status together.

Alerts show at most eight CVEs per summary, with higher Canonical severities
first. Full findings are saved privately at
`/var/lib/reimu-vps/cve-findings.json`. Scan errors and incomplete evaluations
are explicitly reported. Feeds more than seven days old are rejected rather
than treated as current. Review advisories before installing fixes.

Sources: [Canonical OVAL documentation](https://documentation.ubuntu.com/security/security-updates/oval/)
and [official Ubuntu feeds](https://security-metadata.canonical.com/oval/).

Configuration switches and intervals are listed in `.env.example`. They are
optional in existing `.env` files; sensible defaults apply. Change the installed
configuration and restart the service to override them. To run checks manually:

```bash
/usr/bin/python3 /opt/reimu-vps/vps_monitor.py check --config /etc/reimu-vps.env
```

Run as the service's user (normally your SSH user) to access its private state.
Avoid running manual checks concurrently with the service. GitHub errors,
missing dependencies, and unavailable Ubuntu feeds produce a check-unavailable
alert. Package metadata older than 48 hours or without a successful-refresh
stamp produces a freshness warning.

To disable the metadata timer:

```bash
sudo systemctl disable --now reimu-apt-refresh.timer
```

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

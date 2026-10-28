"""Read-only maintenance checks. No upgrades, reboots, or firewall changes."""
import bz2
from concurrent.futures import ThreadPoolExecutor
from datetime import date, datetime, timedelta, timezone
import hashlib
import ipaddress
import json
import logging
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import threading
import time
import urllib.request
import xml.etree.ElementTree as ET

LOG = logging.getLogger("reimu-maintenance")
REPOSITORY = "thunpanhasuon/reimu-vps-monitor"


def boolean(value):
    if value.lower() not in ("true", "false", "1", "0", "yes", "no"):
        raise ValueError("Expected true or false")
    return value.lower() in ("true", "1", "yes")


ENV_FIELDS = {
    "UPDATE_ALERTS": ("update_alerts", boolean, "true"),
    "CVE_ALERTS": ("cve_alerts", boolean, "true"),
    "REIMU_UPDATE_ALERTS": ("reimu_update_alerts", boolean, "true"),
    "PORT_ALERTS": ("port_alerts", boolean, "true"),
    "MAINTENANCE_INTERVAL_SECONDS": ("maintenance_interval", int, "21600"),
    "CVE_INTERVAL_SECONDS": ("cve_interval", int, "86400"),
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
        return 'passed', '⚠️ Configured Tailscale key expiry (%s) has passed. Verify access and renew/re-authenticate the device.' % expiry
    stage = next(str(limit) for limit in (0, 1, 3, 7, 14, 30) if days <= limit)
    when = 'today' if days == 0 else 'in %s day(s)' % days
    return stage, '🔑 Tailscale key expires %s (%s). Renew/re-authenticate before expiry to preserve remote access.' % (when, expiry)


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


def download(url, target, limit=25 * 1024 * 1024):
    request = urllib.request.Request(url, headers={"User-Agent": "Reimu-VPS-Monitor"})
    try:
        with urllib.request.urlopen(request, timeout=45) as response:
            with target.open("wb") as output:
                total = 0
                while True:
                    chunk = response.read(65536)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > limit:
                        raise RuntimeError("Downloaded data exceeded its size limit")
                    output.write(chunk)
    except (OSError, ValueError):
        raise RuntimeError("Could not download maintenance data over HTTPS") from None


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
    return "%s/%s on %s (%s); process: %s" % (
        item["port"], item["protocol"].upper(), item["address"], item["scope"], item["process"])


def port_changes(previous, current, expected):
    expected = {part.strip() for part in expected.split(",") if part.strip()}
    messages = []
    for key in sorted(set(current) - set(previous)):
        item = current[key]
        was_local = any(old["protocol"] == item["protocol"] and old["port"] == item["port"]
                        and old["scope"] == "localhost" for old in previous.values())
        if "%s:%s" % (item["protocol"], item["port"]) in expected and not (was_local and item["scope"] != "localhost"):
            continue
        messages.append("⚠️ New listener: " + port_description(item))
    for key in sorted(set(previous) - set(current)):
        messages.append("ℹ️ Listener stopped: " + port_description(previous[key]))
    return messages


def local_name(element):
    return element.tag.rsplit("}", 1)[-1]


def child_text(element, name, default=""):
    for child in element:
        if local_name(child) == name:
            return child.text or default
    return default


def contributing_criteria(element):
    """A true leaf inside a false kernel-flavour branch is not evidence."""
    name = local_name(element)
    if name in ("definition", "criteria", "criterion") and element.get("result") != "true":
        return
    if name == "criterion":
        yield element
        return
    for child in element:
        if local_name(child) in ("criteria", "criterion"):
            yield from contributing_criteria(child)


def oval_findings(results_path):
    """Read evaluated OVAL results, not guessed upstream version comparisons."""
    root = ET.parse(results_path).getroot()
    definitions, tests, states, items = {}, {}, {}, {}
    evaluated = []
    result_tests = {}
    incomplete = 0
    for element in root.iter():
        name = local_name(element)
        if name == "definition" and element.get("id"):
            definitions[element.get("id")] = element
        elif name == "definition" and element.get("definition_id"):
            evaluated.append(element)
        elif name in ("dpkginfo_test", "uname_test", "variable_test"):
            tests[element.get("id")] = element
        elif name in ("dpkginfo_state", "uname_state", "variable_state"):
            states[element.get("id")] = element
        elif name in ("dpkginfo_item", "uname_item", "variable_item"):
            items[element.get("id")] = element
        elif name == "test" and element.get("test_id"):
            result_tests[element.get("test_id")] = element
    findings = []
    if not evaluated or not any(definition.get("class") == "vulnerability" for definition in definitions.values()):
        raise RuntimeError("OVAL results lack evaluated vulnerability definitions; assessment unavailable")
    for evaluated_definition in evaluated:
        definition = definitions.get(evaluated_definition.get("definition_id"))
        if definition is None or definition.get("class") != "vulnerability":
            continue
        verdict = evaluated_definition.get("result")
        if verdict in ("error", "unknown", "not evaluated"):
            incomplete += 1
        if verdict != "true":
            continue
        cves = sorted({ref.get("ref_id") for ref in definition.iter()
                       if local_name(ref) == "reference" and ref.get("source") == "CVE"})
        severity = next((node.text for node in definition.iter() if local_name(node) == "severity"), "Unknown")
        packages = []
        comments = {node.get("test_ref"): node.get("comment", "") for node in definition.iter() if node.get("test_ref")}
        for criterion in contributing_criteria(evaluated_definition):
            test_id = criterion.get("test_ref")
            test, tested = tests.get(test_id), result_tests.get(test_id)
            if test is None or tested is None:
                continue
            fixed = []
            for state_ref in test:
                state = states.get(state_ref.get("state_ref"))
                if state is not None:
                    fixed.extend(node.text for node in state if local_name(node) in ("evr", "value") and node.get("operation") == "less than")
            for tested_item in tested:
                existence_only = not any(local_name(node) == "state" for node in test)
                if local_name(tested_item) != "tested_item" or not (tested_item.get("result") == "true" or (existence_only and tested_item.get("result") == "not evaluated")):
                    continue
                item = items.get(tested_item.get("item_id"))
                if item is None:
                    continue
                variable = local_name(item) == "variable_item"
                if variable and "kernel" not in test.get("comment", "").lower():
                    continue
                kernel = local_name(item) == "uname_item" or variable
                comment = comments.get(test_id, "") or test.get("comment", "Ubuntu OVAL matched")
                packages.append({"name": "Linux kernel" if kernel else child_text(item, "name"),
                                 "installed": child_text(item, "value") if variable else child_text(item, "os_release") if kernel else child_text(item, "evr"),
                                 "fixed": sorted(set(fixed)),
                                 "assessment": comment, "kind": "kernel" if kernel else "apt"})
        kernels = [package for package in packages if package["kind"] == "kernel"]
        if kernels:
            combined = kernels[0].copy()
            combined["fixed"] = sorted({version for package in kernels for version in package["fixed"]})
            packages = [package for package in packages if package["kind"] != "kernel"] + [combined]
        if not packages:
            incomplete += 1
        for cve in cves:
            findings.append({"cve": cve, "severity": severity or "Unknown", "packages": packages})
    return sorted(findings, key=lambda finding: finding["cve"]), incomplete


def verify_feed_age(path):
    stamp = None
    for _, element in ET.iterparse(path, events=("end",)):
        if local_name(element) == "generator":
            stamp = child_text(element, "timestamp")
            break
    try:
        generated = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
        if generated.tzinfo is None:
            generated = generated.replace(tzinfo=timezone.utc)
        age = (datetime.now(timezone.utc) - generated).total_seconds()
    except (AttributeError, ValueError):
        raise RuntimeError("Ubuntu CVE feed has no usable generation timestamp") from None
    if age > 7 * 86400 or age < -86400:
        raise RuntimeError("Ubuntu CVE feed is stale or server time is incorrect; assessment unavailable")


def annotate_fixes(findings):
    try:
        import apt
        import apt_pkg
        cache = apt.Cache()
    except ImportError:
        cache = None
    for finding in findings:
        for package in finding["packages"]:
            if not package["fixed"]:
                package["fix_status"] = "No fixed version specified in the assessment"
            elif package.get("kind") == "kernel":
                package["fix_status"] = "Kernel fix listed; review Ubuntu advisory and kernel package updates"
            elif cache is None:
                package["fix_status"] = "APT availability could not be checked"
            elif package["name"] not in cache or cache[package["name"]].candidate is None:
                package["fix_status"] = "No candidate in enabled APT repositories"
            else:
                candidate = cache[package["name"]].candidate.version
                available = any(apt_pkg.version_compare(candidate, version) >= 0 for version in package["fixed"])
                package["fix_status"] = ("Available candidate: " + candidate) if available else "Fix not offered by enabled APT repositories"
    return findings


def cve_scan(directory, keep_results=False):
    if not shutil.which("oscap"):
        raise RuntimeError("CVE scan unavailable: install openscap-scanner")
    release = {}
    for line in Path("/etc/os-release").read_text().splitlines():
        key, separator, value = line.partition("=")
        if separator:
            release[key] = value.strip('"')
    codename = release.get("VERSION_CODENAME", "")
    if release.get("ID") != "ubuntu" or not re.fullmatch("[a-z]+", codename):
        raise RuntimeError("CVE checks currently support standard Ubuntu releases only")
    with tempfile.TemporaryDirectory(dir=directory, prefix="scan-") as scratch:
        scratch = Path(scratch)
        archive, source, results = scratch / "feed.bz2", scratch / "feed.xml", scratch / "results.xml"
        download("https://security-metadata.canonical.com/oval/com.ubuntu.%s.cve.oval.xml.bz2" % codename, archive)
        with bz2.open(archive, "rb") as compressed, source.open("wb") as output:
            size = 0
            while True:
                chunk = compressed.read(65536)
                if not chunk:
                    break
                size += len(chunk)
                if size > 300 * 1024 * 1024:
                    raise RuntimeError("Expanded OVAL feed exceeded its size limit")
                output.write(chunk)
        verify_feed_age(source)
        try:
            with (scratch / "oscap.log").open("w") as log:
                result = subprocess.run(["oscap", "oval", "eval", "--results", str(results), str(source)],
                                        stdout=log, stderr=log, timeout=900)
        except subprocess.TimeoutExpired:
            raise RuntimeError("CVE scan timed out after 15 minutes") from None
        if result.returncode != 0 or not results.exists():
            shutil.copyfile(scratch / "oscap.log", Path(directory) / "last-oscap-error.log")
            raise RuntimeError("OpenSCAP scan failed (exit %s); see last-oscap-error.log in the state directory" % result.returncode)
        if keep_results:
            shutil.copyfile(results, Path(directory) / "last-oval-results.xml")
        findings, incomplete = oval_findings(results)
        return annotate_fixes(findings), incomplete


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


def cve_snapshot(findings):
    """Compare security facts, ignoring ordering, timestamps and prose edits."""
    snapshot = {}
    for finding in findings:
        packages = [{
            'name': package['name'], 'installed': package['installed'],
            'kind': package.get('kind', 'apt'), 'fixed': sorted(set(package['fixed'])),
            'fix_status': package.get('fix_status', ''),
            'potential': 'might' in package.get('assessment', '').lower(),
        } for package in finding['packages']]
        snapshot[finding['cve']] = {'severity': finding['severity'],
                                   'packages': sorted(packages, key=lambda item: json.dumps(item, sort_keys=True))}
    return snapshot


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
        messages = ["🔔 Package updates: %s (%s security)" % (len(packages), count)]
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
                    ['🔑 Tailscale key-expiry reminder configured: ' + expiry,
                     'Uses your supplied date, not a live Tailscale check. Reminders at 30, 14, 7, 3 and 1 days, on expiry day, and after expiry.']
                    if expiry else ['Tailscale key-expiry reminders disabled.'], baseline=not expiry)
        if not expiry:
            self.notify('tailscale_expiry_stage', '', [])
            return
        reminder = tailscale_reminder(expiry)
        if reminder is not None:
            stage, text = reminder
            self.notify('tailscale_expiry_stage', expiry + ':' + stage,
                        [text, 'Exact expiry time is not known. Update TAILSCALE_KEY_EXPIRY in /etc/reimu-vps.env after renewal, then restart Reimu.'])

    def automatic_updates(self, directory=Path('/var/lib/reimu-security-updates')):
        configuration = directory / 'configuration.json'
        if not configuration.exists():
            return
        configured = json.loads(configuration.read_text())
        self.notify('automatic_update_configuration', {key: value for key, value in configured.items() if key != 'enabled_at'},
                    ['🛡️ Automatic Ubuntu security updates enabled.',
                     'Schedule: ' + configured['schedule'], 'Reboots remain manual.'])
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
            messages = ["ℹ️ Port baseline recorded (%s listeners). Future changes will be reported." % len(current)]
            messages += [port_description(item) for item in list(current.values())[:12]]
        else:
            messages = port_changes(previous, current, self.config["expected_ports"])
        if messages:
            messages.append("Listening addresses only; firewall/NAT reachability is not tested.")
        self.notify("ports", current, messages)

    def cves(self):
        findings, incomplete = cve_scan(self.directory)
        snapshot = cve_snapshot(findings)
        notified = self.directory / 'cve-notified.json'
        full_report = self.directory / 'cve-findings.json'
        previous = json.loads(notified.read_text()) if notified.exists() else None
        # Migrate an already-delivered legacy report without resending its top CVEs.
        if previous is None and full_report.exists():
            legacy = json.loads(full_report.read_text())
            fingerprint = hashlib.sha256(json.dumps([legacy['findings'], legacy['incomplete']], sort_keys=True).encode()).hexdigest()
            with self.lock:
                delivered = self.state.get('cves') == fingerprint
            if delivered:
                previous = {'findings': cve_snapshot(legacy['findings']), 'incomplete': legacy['incomplete']}
                atomic_json(notified, previous)
        old = previous['findings'] if previous is not None else {}
        added = set(snapshot) - set(old)
        changed = {cve for cve in set(snapshot) & set(old) if snapshot[cve] != old[cve]}
        removed = (set(old) - set(snapshot)) if not incomplete else set()
        selected = findings if previous is None else [finding for finding in findings if finding['cve'] in added | changed]
        lines = []
        if previous is None:
            lines = ['🔴 Initial Ubuntu CVE assessment: %s finding(s)' % len(findings)] if findings else ['✅ No matching CVEs found in the current Ubuntu assessment']
        elif added or changed or removed:
            lines = ['🔔 CVE changes: %s new, %s changed, %s no longer matching.' % (len(added), len(changed), len(removed)),
                     'Current assessment: %s matching CVEs. Unchanged findings are omitted.' % len(snapshot)]
            if removed:
                lines.append('No longer matching does not prove a fix was installed; package changes or revised vulnerability data can also explain it.')
        elif incomplete != previous.get('incomplete'):
            lines = ['⚠️ CVE scan is incomplete' if incomplete else 'ℹ️ CVE scan is complete again; no finding changes.']
        if incomplete:
            if lines:
                lines[0] = '⚠️ Incomplete CVE scan: ' + lines[0].lstrip('🔴🔔✅⚠️ ')
                lines.append('%s definitions could not be evaluated. Missing findings are not marked resolved.' % incomplete)
        if lines:
            lines.append("Scope: Ubuntu packages/running kernel; Canonical severity. Not an all-software safety guarantee.")
        ordered = sorted(selected, key=lambda item: ({"Critical": 0, "High": 1, "Medium": 2, "Low": 3}.get(item["severity"], 4), item["cve"]))
        for finding in ordered[:8]:
            lines.append("\n%s — %s" % (finding["cve"], finding["severity"]))
            for package in finding["packages"][:3]:
                fix = ", ".join(package["fixed"]) or "not specified by this assessment"
                lines.append("%s %s; fixed version: %s" % (package["name"], package["installed"], fix))
                lines.append(package.get("fix_status", "APT availability not checked"))
                if "might" in package["assessment"]:
                    lines.append("Ubuntu marks this as potentially affected; review advisory.")
            lines.append("https://ubuntu.com/security/" + finding["cve"])
        if len(selected) > 8:
            lines.append('\nShowing 8 of %s relevant findings; full assessment saved on VPS.' % len(selected))
        atomic_json(full_report, {'checked_at': time.time(), 'findings': findings, 'incomplete': incomplete})
        # Preserve unobserved prior findings across an incomplete scan.
        baseline = {**old, **snapshot} if incomplete else snapshot
        next_report = {'findings': baseline, 'incomplete': incomplete}
        fingerprint = hashlib.sha256(json.dumps(next_report, sort_keys=True).encode()).hexdigest()
        self.notify('cves', fingerprint, lines)
        atomic_json(notified, next_report)

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
        if self.config["cve_alerts"]:
            tasks["CVEs"] = (self.config["cve_interval"], self.cves)
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

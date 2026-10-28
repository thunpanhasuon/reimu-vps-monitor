"""Run with Ubuntu's /usr/bin/python3 and scanner dependencies installed."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import tempfile
import security_checks as security

updates = security.package_updates()
print('APT check succeeded; pending package count:', len(updates), flush=True)
ports = security.listening_ports()
print('Socket check succeeded; listeners:', len(ports), flush=True)
with tempfile.TemporaryDirectory() as directory:
    findings, incomplete = security.cve_scan(directory)
print('Canonical CVE scan succeeded; findings:', len(findings), 'incomplete:', incomplete, flush=True)
if incomplete:
    raise SystemExit('OpenSCAP returned incomplete results on the integration host')
for finding in findings:
    if not finding['packages']:
        raise SystemExit('Matched CVE lacks package evidence: ' + finding['cve'])
    for package in finding['packages']:
        if not package['name'] or not package['installed']:
            raise SystemExit('Missing installed package evidence')
print('Ubuntu integration passed', flush=True)

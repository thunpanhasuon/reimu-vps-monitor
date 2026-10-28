"""Run with Ubuntu's /usr/bin/python3 and scanner dependencies installed."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import tempfile
import xml.etree.ElementTree as ET
import security_checks as security

updates = security.package_updates()
print('APT check succeeded; pending package count:', len(updates), flush=True)
ports = security.listening_ports()
print('Socket check succeeded; listeners:', len(ports), flush=True)
with tempfile.TemporaryDirectory() as directory:
    findings, incomplete = security.cve_scan(directory, keep_results=True)
    missing = next((finding for finding in findings if not finding['packages']), None)
    if missing:
        root = ET.parse(Path(directory) / 'last-oval-results.xml').getroot()
        definition = next(node for node in root.iter() if security.local_name(node) == 'definition' and node.get('id') and any(ref.get('ref_id') == missing['cve'] for ref in node.iter()))
        print('Missing-package definition:', ET.tostring(definition, encoding='unicode')[:8000], flush=True)
        evaluated = next(node for node in root.iter() if node.get('definition_id') == definition.get('id'))
        print('Evaluated:', ET.tostring(evaluated, encoding='unicode')[:8000], flush=True)
        refs = {node.get('test_ref') for node in evaluated.iter() if node.get('test_ref')}
        item_ids = set()
        for node in root.iter():
            if node.get('test_id') in refs:
                print('Result test:', ET.tostring(node, encoding='unicode')[:8000], flush=True)
                item_ids.update(item.get('item_id') for item in node.iter() if item.get('item_id'))
        for node in root.iter():
            if node.get('id') in item_ids:
                print('Item:', ET.tostring(node, encoding='unicode')[:3000], flush=True)
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

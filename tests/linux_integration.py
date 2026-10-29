"""Run with Ubuntu's /usr/bin/python3 and dependencies installed."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import security_checks as security

updates = security.package_updates()
print('APT check succeeded; pending package count:', len(updates), flush=True)
ports = security.listening_ports()
print('Socket check succeeded; listeners:', len(ports), flush=True)
print('Ubuntu integration passed', flush=True)

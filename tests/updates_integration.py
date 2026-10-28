"""CI only: validate real APT configuration and unattended-upgrade dry run."""
import os
from pathlib import Path
import sys
import tempfile
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import security_updater as updater

if os.geteuid() != 0:
    raise SystemExit('Run this integration test as root on disposable Ubuntu CI')
policy = Path('/etc/apt/apt.conf.d/99zz-reimu-security-updates')
policy.write_text(updater.POLICY)
assert updater.effective_policy_is_safe(), 'Effective Ubuntu APT policy was not security-only'
with tempfile.TemporaryDirectory() as directory:
    result = updater.run_update(dry_run=True, directory=Path(directory))
    if result:
        print((Path(directory) / 'dry-run.json').read_text())
        print((Path(directory) / 'last-run.log').read_text()[-6000:])
        raise SystemExit('Real unattended-upgrade dry run failed')
print('Security-only policy and real unattended-upgrade dry run passed; no packages installed.')

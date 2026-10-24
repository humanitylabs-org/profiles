"""Repackage: `wam package-inline` (exact source inlined into the Runtipi compose), then this app's runtime settings.

Run after every source edit:  python3 -I tools/package.py
"""
import os
import subprocess
import sys
from pathlib import Path

import yaml

root = Path(__file__).resolve().parent.parent
wam = os.path.expanduser('~/.wizard-os/builder/current/bin/wam')
subprocess.run([wam, 'package-inline', str(root)], check=True, stdout=subprocess.DEVNULL)
path = root / 'runtipi' / 'docker-compose.yml'
doc = yaml.safe_load(path.read_text())
svc = doc['services']['profiles']
svc['image'] = 'python:3.12-alpine@sha256:1b668429b3511ab407d8e00648891631b0b1a4d7e15e3ca70f38ab5b91ad4ab4'
svc['pids_limit'] = 64
svc['environment'] = {
    'PORT': '8836', 'BIND': '0.0.0.0', 'DATA_DIR': '/data', 'PYTHONDONTWRITEBYTECODE': '1',
    'OWNER_LOGINS': '${PROFILES_OWNER_LOGINS:-}', 'FRIEND_LINK': '${PROFILES_FRIEND_LINK:-}',
    'WIZARD_TRUSTED_HOSTS': '${WIZARD_TRUSTED_HOSTS:-}', 'WIZARD_TRUSTED_ORIGINS': '${WIZARD_TRUSTED_ORIGINS:-}',
}
# Friends' boxes have *.ts.net names: Tailscale's resolver answers those, a public resolver everything else.
svc['dns'] = ['100.100.100.100', '1.1.1.1']
# Read-only: lets the app save your My skin exactly (comments too) before you wear a friend's look.
svc['volumes'] = ['${APP_DATA_DIR}/data:/data', '${ROOT_FOLDER_HOST}/media/Skins:/skins:ro']
svc['environment']['SKINS_DIR'] = '/skins'
svc['x-runtipi']['internal_port'] = 8836
path.write_text(yaml.safe_dump(doc, sort_keys=False, width=100000))
print('packaged', path.relative_to(root), file=sys.stderr)

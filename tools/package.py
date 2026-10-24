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
# Same files package-inline ships, but zlib-compressed: Linux caps one exec argument at 128 KiB, and the plain
# base64 bundle passed that (exec: argument list too long). Compressed it is about a third of the size.
import base64, json, zlib  # noqa: E402
view = sorted('web/' + p.name for p in (root / 'web').iterdir() if p.is_file() and not p.name.startswith('.'))
payload = {p: (root / p).read_text() for p in ['app/server.py', 'openapi.json'] + view}
blob = base64.b64encode(zlib.compress(json.dumps(payload, sort_keys=True).encode(), 9)).decode()
code = ("import base64,json,pathlib,runpy,zlib\n"
        "root=pathlib.Path('/tmp/wizard-app');root.mkdir(exist_ok=True)\n"
        f"files=json.loads(zlib.decompress(base64.b64decode('{blob}')))\n"
        "for name,text in files.items():\n"
        " p=root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(text)\n"
        "runpy.run_path(str(root/'app/server.py'),run_name='__main__')\n")
if len(code) > 120_000:
    sys.exit(f'bundle too large for one exec argument: {len(code)} bytes')
svc['command'] = ['python', '-c', code]
path.write_text(yaml.safe_dump(doc, sort_keys=False, width=100000))
print('packaged', path.relative_to(root), file=sys.stderr)

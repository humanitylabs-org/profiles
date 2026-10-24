"""Check source/bundle equality and boot the exact inline command in disposable state.
Needs the same PyYAML dependency as package.py. Never installs or restarts an app.
"""
import ast
import base64
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
import zlib

import yaml

root = Path(__file__).resolve().parent.parent
doc = yaml.safe_load((root / 'runtipi/docker-compose.yml').read_text())
code = doc['services']['profiles']['command'][2]
tree = ast.parse(code)
blobs = [n.args[0].value for n in ast.walk(tree) if isinstance(n, ast.Call)
         and isinstance(n.func, ast.Attribute) and n.func.attr == 'b64decode'
         and n.args and isinstance(n.args[0], ast.Constant)]
assert len(blobs) == 1
files = json.loads(zlib.decompress(base64.b64decode(blobs[0])))
expected = sorted([str(p.relative_to(root)) for area in ('app', 'web') for p in (root / area).iterdir()
                   if p.is_file() and (p.suffix == '.py' if area == 'app' else not p.name.startswith('.'))] + ['openapi.json'])
assert sorted(files) == expected, 'Bundle must include EVERY app module and view file'
assert all(text == (root / name).read_text() for name, text in files.items()), 'Stale inline bundle'
assert "sys.path.insert(0,str(root/'app'))" in code, 'Direct-script resolver import must work'
with tempfile.TemporaryDirectory(prefix='profiles-inline-') as temp:
    # Only rewrite the extraction root in the test: no host /tmp or live data is touched.
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and node.value == '/tmp/wizard-app':
            node.value = str(Path(temp) / 'app')
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0)); port = sock.getsockname()[1]
    env = {**os.environ, 'DATA_DIR': str(Path(temp) / 'data'), 'BIND': '127.0.0.1', 'PORT': str(port), 'PROFILES_OFFLINE': '1', 'PROFILES_RELAYS': ''}
    proc = subprocess.Popen([sys.executable, '-c', ast.unparse(tree)], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        for attempt in range(60):
            if proc.poll() is not None:
                raise AssertionError(proc.communicate()[1].decode())
            try:
                with urllib.request.urlopen(f'http://127.0.0.1:{port}/healthz', timeout=1) as response:
                    health = json.load(response)
                break
            except OSError:
                time.sleep(.05)
        else:
            raise AssertionError('Inline bundle did not become ready')
        assert health == {'ok': True, 'app': 'profiles', 'version': '0.6.0'}, health
        print(json.dumps({'source_files_equal': len(files), 'inline_startup_health': health}))
    finally:
        proc.terminate()
        proc.communicate(timeout=10)

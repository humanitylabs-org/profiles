"""Disposable browser harness. Fake relay + fake PHONE (test key only), never public relay I/O.
PROFILES_SHARED_CORE points to an unmodified wizard-ux web/core checkout.
Run on the browser worker: python3 tests/run_browser.py
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
from urllib.parse import urlsplit

os.environ['PROFILES_OFFLINE'] = '1'
os.environ['PROFILES_RELAYS'] = ''
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from app import server as s
from test_owner_identity import FakeRelay, OWNER, PK, signed

HOST_HTML = b'''<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1"><script src="/test-host.js" defer></script></head><body style="margin:0;background:#171122"><iframe id="app" src="/" style="display:block;border:0;width:100%;height:100dvh"></iframe></body></html>'''
HOST_JS = b'''window.fixtureDenied=false;
addEventListener('message',async e=>{
 if(e.source!==document.querySelector('#app').contentWindow||e.origin!==location.origin)return;
 const d=e.data;if(d?.type!=='wizard:app:request'||d.version!==1)return;
 let value;
 if(d.op==='ready')value={version:1,hosted:true};
 else if(d.op.startsWith('identity.'))value=await(await fetch('/test-phone',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({op:d.op,args:d.args,denied:window.fixtureDenied})})).json();
 else value=true;
 e.source.postMessage({type:'wizard:app:reply',version:1,id:d.id,value},e.origin);
});'''


def main():
    core = Path(os.environ['PROFILES_SHARED_CORE'])
    assert (core / 'app-client.js').is_file(), 'Use the real shared app client'
    relay = FakeRelay()
    s.relay_publish, s.relay_query = relay.publish, relay.query
    s.sync_soon = lambda: None
    with tempfile.TemporaryDirectory(prefix='profiles-browser-') as temp:
        s.DATA = Path(temp) / 'data'
        s._KEY = None

        class Handler(s.Handler):
            def do_GET(self):
                path = urlsplit(self.path).path
                if path == '/test-host': return self.send(200, HOST_HTML, 'text/html')
                if path == '/test-host.js': return self.send(200, HOST_JS, 'text/javascript')
                if path.startswith('/wizard-os-home/core/'):
                    name = path.rsplit('/', 1)[1]
                    p = core / name
                    if p.is_file() and p.suffix in ('.js', '.css'):
                        return self.send(200, p.read_bytes(), s.STATIC_TYPES[p.suffix])
                super().do_GET()

            def do_POST(self):
                if self.path == '/test-seed-request':
                    from test_owner_identity import OTHER_BOX
                    owner = s.load()['owner']
                    rumor = s.sign_event(s.HELLO_KIND, '{"name":"Stock requester"}', [], sk=OTHER_BOX)
                    rumor.pop('sig')
                    seal = s.sign_event(13, s.nip44_encrypt(s.conversation_key(OTHER_BOX, owner), json.dumps(rumor)), [], sk=OTHER_BOX)
                    relay.publish([s.wrap_seal(owner, seal)])
                    s.check_requests()
                    return self.send(200, {'ok': True})
                if self.path == '/test-reset':
                    # Disposable app only. Never exists in production Handler.
                    s._KEY = None; s._ck_cache.clear(); relay.events.clear(); relay.published.clear()
                    for p in s.DATA.glob('*'): p.unlink()
                    return self.send(200, {'ok': True})
                if self.path == '/test-phone':
                    body = self.body(); op, a = body['op'], body.get('args') or {}
                    if op == 'identity.info': return self.send(200, {'npub': s.npub_encode(PK[OWNER]), 'name': 'Test owner', 'backed_up': True})
                    if body.get('denied'): return self.send(200, {'denied': True})
                    if op == 'identity.sign': return self.send(200, signed(a['event'], OWNER))
                    if op == 'identity.nip44_encrypt': return self.send(200, {'ciphertext': s.nip44_encrypt(s.conversation_key(OWNER, a['pubkey']), a['plaintext'])})
                    if op == 'identity.nip44_decrypt': return self.send(200, {'plaintext': s.nip44_decrypt(s.conversation_key(OWNER, a['pubkey']), a['ciphertext'])})
                    return self.send(400, {'error': 'Unknown fixture op'})
                super().do_POST()

        server = s.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        port = server.server_address[1]
        s.TRUSTED_HOSTS.add(f'127.0.0.1:{port}'); s.TRUSTED_ORIGINS.add(f'http://127.0.0.1:{port}')
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        env = {**os.environ, 'PROFILES_TEST_URL': f'http://127.0.0.1:{port}/', 'PROFILES_TEST_DATA': str(s.DATA), 'PROFILES_PYTHON': sys.executable, 'PROFILES_FRIEND_NPUB': s.npub_encode(PK[__import__('test_owner_identity').FRIEND])}
        try:
            for script in ('tests/identity-backup.cjs', 'tests/owner-identity-browser.cjs'):
                subprocess.run([os.environ.get('NODE', 'node'), script], check=True, env=env)
        finally:
            server.shutdown(); server.server_close()


if __name__ == '__main__':
    main()

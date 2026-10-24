"""Wizard Profiles: share your build, your look and your App Store apps with friends, or with everyone.

One rule for everything: each part of a profile is Private (the default), Friends or Public. Nothing local is
shared: an app counts only when the Wizard App Index lists its public repo, a build only when its exact commit is
public shell code anyone can fetch, a look only as sanitised CSS (the owner's My skin, read by the view from the shell). Others see a frozen snapshot taken when the owner
taps Publish, never live state.

Who is asking comes from the connection, never from the request body:
  - not through Tailscale Serve (box-local: the agent's MCP gateway, other code on this box)      -> owner
  - through Serve with Tailscale-User-Login in OWNER_LOGINS                                       -> owner
  - through Serve as an accepted friend's login                                                   -> friend
  - through Serve as anyone else, or with no login (tagged nodes)                                 -> visitor
Serve sets the login header and strips any copy a client sends; the app's own port is loopback-only.
Friends are people whose box can reach yours over a private Tailscale connection: that is the gate for trying
on someone's build, which runs their code on your data.

Stdlib only.
"""
import hashlib
import json
import os
import re
import secrets
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote, urlsplit

ROOT = Path(__file__).resolve().parent.parent if '__file__' in globals() else Path(os.environ.get('APP_ROOT', '.')).resolve()
DATA = Path(os.environ.get('DATA_DIR', ROOT / '.data'))
APP_ID = 'profiles'
VERSION = '0.1.0'
INDEX = os.environ.get('WIZARD_APP_INDEX', 'https://apps.aiwizards.com').rstrip('/')
SHELL_REPO = os.environ.get('PROFILES_SHELL_REPO', 'humanitylabs-org/wizard-ux')
OWNER_LOGINS = {x.strip().lower() for x in os.environ.get('OWNER_LOGINS', '').split(',') if x.strip()}
# The address friends add: a Serve port that exposes ONLY /profiles/api/friend/* (never the shell or other apps).
FRIEND_LINK = os.environ.get('FRIEND_LINK', '').strip()
LEVELS = ('private', 'friends', 'public')
SECTIONS = ('build', 'skin', 'apps')
NOT_APPS = {'wizard-ux', 'wizard-agent-service', APP_ID}   # the shell and the service are the build; Profiles is the profile
STATIC_TYPES = {'.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8',
                '.svg': 'image/svg+xml'}
LOCK = threading.RLock()
APP = re.compile(r'^[a-z0-9][a-z0-9-]{0,63}$')
REPO = re.compile(r'^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$')
SHA = re.compile(r'^[0-9a-f]{7,40}$')
FULL_SHA = re.compile(r'^[0-9a-f]{40}$')
SKIN_ID = re.compile(r'^[a-z0-9-]{1,40}$')
LOGIN = re.compile(r'^[^\s@]{1,128}@[^\s@]{1,190}$')
MAX_CSS = 64 * 1024


class Problem(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code, self.message = code, message


def now():
    return time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())


def _text(v, name, limit, required=False):
    if v is None:
        v = ''
    if not isinstance(v, str) or len(v) > limit or re.search(r'[\x00-\x08\x0b-\x1f\x7f]', v):
        raise Problem(400, f'{name} must be text up to {limit} characters.')
    if required and not v.strip():
        raise Problem(400, f'{name} is required.')
    return v.strip()


# ---------- storage: one JSON file, atomic replace ----------

def _blank():
    return {'name': '', 'bio': '', 'visibility': {s: 'private' for s in SECTIONS}, 'hidden': [], 'uses': [],
            'snapshot': None, 'friends': [], 'requests': [], 'activity': [], 'look_backup': None, 'wearing': None}


def load():
    try:
        s = json.loads((DATA / 'profile.json').read_text())
    except (OSError, ValueError):
        return _blank()
    out = _blank()
    if isinstance(s, dict):
        out.update({k: s[k] for k in out if k in s and (type(s[k]) is type(out[k]) or (out[k] is None and isinstance(s[k], dict)))})
    out['visibility'] = {k: out['visibility'].get(k) if out['visibility'].get(k) in LEVELS else 'private' for k in SECTIONS}
    return out


def save(s):
    DATA.mkdir(parents=True, exist_ok=True)
    tmp = DATA / f'.profile.{secrets.token_hex(6)}.tmp'
    tmp.write_text(json.dumps(s, indent=1))
    os.chmod(tmp, 0o600)
    os.replace(tmp, DATA / 'profile.json')


def log(s, text):
    s['activity'] = s['activity'][-59:] + [{'at': now(), 'text': text}]


# ---------- outbound: App Index, GitHub, friends' boxes ----------

def fetch_json(url, body=None, timeout=8):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, method='GET' if body is None else 'POST',
                                 headers={'Accept': 'application/json', 'User-Agent': f'wizard-profiles/{VERSION}',
                                          **({} if body is None else {'Content-Type': 'application/json'})})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read(512 * 1024 + 1)
    except urllib.error.HTTPError as e:
        try:
            detail = json.loads(e.read(4096) or b'{}')
        except ValueError:
            detail = {}
        raise Problem(e.code if 400 <= e.code < 500 else 502, str(detail.get('error') or f'HTTP {e.code}')[:200]) from None
    except (urllib.error.URLError, TimeoutError, OSError):
        raise Problem(502, f'Could not reach {urlsplit(url).hostname}.') from None
    if len(raw) > 512 * 1024:
        raise Problem(502, 'Answer too large.')
    try:
        return json.loads(raw or b'{}')
    except ValueError:
        raise Problem(502, 'Not a JSON answer.') from None


_cache = {}


def _cached(key, ttl, fn):
    hit = _cache.get(key)
    if hit and hit[0] > time.time():
        return hit[1]
    value = fn()
    _cache[key] = (time.time() + ttl, value)
    return value


def store_listing(repo):
    """The App Index record when this exact repo is listed publicly; None for local, private or delisted apps."""
    def look():
        try:
            rec = fetch_json(f'{INDEX}/v1/apps/{quote(repo)}')
        except Problem as p:
            if p.code >= 500:
                raise
            return None
        return rec if rec.get('listed') is True and str(rec.get('repo', '')).lower() == repo.lower() else None
    return _cached('idx:' + repo.lower(), 600, look)


def public_commit(repo, ref):
    """Full sha when `ref` is a commit in a PUBLIC GitHub repo, so anyone can fetch exactly this code; else None."""
    def look():
        try:
            r = fetch_json(f'https://api.github.com/repos/{quote(repo)}/commits/{quote(ref)}')
        except Problem as p:
            if p.code >= 500:
                raise
            return None
        sha = str(r.get('sha', ''))
        return sha if FULL_SHA.fullmatch(sha) else None
    return _cached(f'gh:{repo}@{ref}', 3600, look)


# ---------- look CSS: the shell's My skin rules, applied again on every read and on every friend answer ----------

AT_ALLOWED = {'media', 'supports', 'keyframes', '-webkit-keyframes', 'container', 'layer', 'font-face', 'property', 'scope',
              'starting-style'}
FOREIGN = re.compile(r'^\s*(?:\/\/|[a-z][a-z0-9+.-]*:)', re.I)
IMAGE_DATA = re.compile(r'^\s*data:image\/(?:png|jpe?g|gif|webp|avif)[;,]', re.I)


def clean_css(css):
    css = str(css)[:MAX_CSS]
    css = re.sub(r'/\*.*?\*/', '', css, flags=re.S)
    css = css.replace('\\', '')                       # no escapes, so nothing can spell @import or url( in disguise
    css = re.sub(r'<', '', css)                        # never closes the <style> it is placed in

    # A disallowed at-rule goes away whole (statement up to ';', or its block), so nothing of it survives as text.
    def at(m):
        return m.group(0) if m.group(1).lower() in AT_ALLOWED else ''
    css = re.sub(r'@([-a-z0-9_]+)(?:[^;{}]*;|[^;{}]*\{[^{}]*\})?', at, css, flags=re.I)
    # Strings that name another origin are never needed for styling (content: "Note: hi" stays).
    css = re.sub(r'([\'"])\s*(?:\/\/|[a-z][a-z0-9+.-]*:\/\/)[^\'"]*\1', '""', css, flags=re.I)

    def url(m):
        target = m.group(2).strip()
        return m.group(0) if IMAGE_DATA.match(target) or (not FOREIGN.match(target) and not target.startswith('/')) else 'none'
    css = re.sub(r'\burl\(\s*([\'"]?)([^)\'"]*)\1\s*\)', url, css, flags=re.I)
    css = re.sub(r'\b(?:expression|image-set|-webkit-image-set|src)\s*\(', 'none(', css, flags=re.I)
    css = re.sub(r'javascript:|behavior\s*:|-moz-binding', '', css, flags=re.I)
    return css.strip()


def save_look_backup(body):
    """Before wearing a friend's look, the view parks the owner's own look here so one tap puts it back."""
    if not isinstance(body, dict) or not SKIN_ID.fullmatch(str(body.get('skin') or '')) or not isinstance(body.get('css', ''), str) \
            or len(body.get('css', '')) > MAX_CSS:
        raise Problem(400, 'Expected {skin, css}.')
    with LOCK:
        s = load()
        if not s.get('look_backup'):                 # keep the first one: trying several looks in a row still returns to yours
            s['look_backup'] = {'skin': body['skin'], 'css': body.get('css', ''), 'at': now()}
        s['wearing'] = {'friend': _text(body.get('friend'), 'friend', 60), 'skin': _text(body.get('friend_skin'), 'skin', 60)}
        log(s, f"Wearing {s['wearing']['friend']}'s look")
        save(s)
    return me()


def take_look_backup():
    with LOCK:
        s = load()
        b = s.get('look_backup')
        if not b:
            raise Problem(404, 'Nothing to put back.')
        s['look_backup'], s['wearing'] = None, None
        log(s, 'Back to your own look')
        save(s)
    return b


# ---------- publish: freeze what may be shared ----------

def clean_changes(items):
    out = []
    for c in (items if isinstance(items, list) else [])[:60]:
        if isinstance(c, dict) and isinstance(c.get('title'), str):
            out.append({'title': c['title'][:160], 'date': str(c.get('date', ''))[:10]})
    return out


def publish(body):
    if not isinstance(body, dict):
        raise Problem(400, 'Expected an object.')
    report = {'shared': [], 'kept_private': []}
    snap = {'version': 1, 'published_at': now()}

    b = body.get('build') if isinstance(body.get('build'), dict) else {}
    ref = str(b.get('commit') or '')
    if not SHA.fullmatch(ref):
        raise Problem(400, 'build.commit must be the shell commit this box serves.')
    sha = public_commit(SHELL_REPO, ref)
    if sha:
        snap['build'] = {'repo': SHELL_REPO, 'commit': sha, 'name': _text(b.get('name') or 'Wizard', 'build name', 80),
                         'base': str(b.get('base') or '')[:40], 'changes': clean_changes(b.get('changes')),
                         'built_at': str(b.get('built_at') or '')[:20]}
        report['shared'].append({'part': 'build', 'what': f"{snap['build']['name']} ({sha[:8]})"})
    else:
        snap['build'] = None
        report['kept_private'].append({'part': 'build', 'what': ref[:8],
                                       'why': 'This build is not public shell code yet, so nobody else could run it.'})

    k = body.get('skin') if isinstance(body.get('skin'), dict) else {}
    if not SKIN_ID.fullmatch(str(k.get('id') or '')):
        raise Problem(400, 'skin.id must be the skin this device wears.')
    css = clean_css(k.get('css') or '') if isinstance(k.get('css'), str) else ''
    css = css if re.sub(r'\s+', '', re.sub(r'/\*.*?\*/', '', css, flags=re.S)) else ''
    snap['skin'] = {'id': k['id'], 'name': _text(k.get('name') or k['id'], 'skin name', 60), 'css': css,
                    'sha256': hashlib.sha256(css.encode()).hexdigest()}
    report['shared'].append({'part': 'skin', 'what': snap['skin']['name'] + (' with your own touches' if css else '')})

    apps, seen = [], set()
    for a in (body.get('apps') if isinstance(body.get('apps'), list) else [])[:200]:
        if not isinstance(a, dict) or not APP.fullmatch(str(a.get('id', ''))) or a['id'] in NOT_APPS or a['id'] in seen:
            continue
        seen.add(a['id'])
        repo = str(a.get('repo') or '')
        rec = store_listing(repo) if REPO.fullmatch(repo) else None
        if not rec:
            report['kept_private'].append({'part': 'apps', 'what': str(a.get('name') or a['id'])[:60], 'why': 'Not in the App Store.'})
            continue
        apps.append({'id': a['id'], 'repo': rec['repo'], 'store_id': str(rec.get('id') or a['id'])[:64],
                     'name': str(rec.get('name') or a['id'])[:60], 'summary': str(rec.get('summary') or '')[:200],
                     'category': str(rec.get('category') or '')[:30]})
    snap['apps'] = sorted(apps, key=lambda x: x['name'].lower())
    report['shared'].append({'part': 'apps', 'what': f'{len(apps)} App Store apps'})

    with LOCK:
        s = load()
        snap['fingerprint'] = hashlib.sha256(json.dumps(snap, sort_keys=True).encode()).hexdigest()[:16]
        s['snapshot'] = snap
        log(s, f"Published: {len(apps)} apps, {snap['skin']['name']} look" + (f", build {sha[:8]}" if sha else ', build kept private'))
        save(s)
    return {'snapshot': snap, 'report': report, 'me': me()}



# ---------- what each viewer may see ----------

def view_for(role, s=None):
    s = s or load()
    allowed = {'owner': LEVELS, 'friend': ('friends', 'public'), 'visitor': ('public',)}[role]
    snap = s['snapshot'] or {}
    out = {'app': APP_ID, 'version': VERSION, 'viewer': role, 'name': s['name'] or 'A Wizard owner', 'bio': s['bio'],
           'published_at': snap.get('published_at'), 'fingerprint': snap.get('fingerprint')}
    hidden, uses = set(s['hidden']), set(s['uses'])
    for part in SECTIONS:
        if not snap or s['visibility'][part] not in allowed:
            out[part] = None
        elif part == 'apps':
            out['apps'] = [dict(a, uses=a['id'] in uses) for a in snap.get('apps', []) if a['id'] not in hidden]
        else:
            out[part] = snap.get(part)
    return out


def via_serve(headers):
    """Tailscale Serve always sets X-Forwarded-Host/For; box-local callers (gateway, agent) do not go through it."""
    host = (headers.get('X-Forwarded-Host') or headers.get('Host') or '').lower().split(':')[0]
    return host.endswith('.ts.net') or bool(headers.get('X-Forwarded-For'))


def role_of(headers):
    if not via_serve(headers):
        return 'owner', ''
    login = (headers.get('Tailscale-User-Login') or '').strip().lower()
    if login and login in OWNER_LOGINS:
        return 'owner', login
    if login and any(f['login'] == login for f in load()['friends']):
        return 'friend', login
    return 'visitor', login


# ---------- friends ----------

def clean_address(v):
    v = _text(v, 'profile link', 300, True)
    u = urlsplit(v if '://' in v else 'https://' + v)
    if u.scheme != 'https' or not u.hostname or u.username or u.password or u.query or u.fragment:
        raise Problem(400, 'Use the https link to their Profiles app, like https://their-box.example.ts.net/profiles/')
    path = (u.path or '/').rstrip('/') + '/'
    if not path.endswith('/profiles/'):
        path = path.rstrip('/') + '/profiles/'
    return f'https://{u.netloc.lower()}{path}'


def add_friend(body):
    if not isinstance(body, dict):
        raise Problem(400, 'Expected an object.')
    address = clean_address(body.get('address'))
    login = _text(body.get('login'), 'their Tailscale login', 320, True).lower()
    if not LOGIN.fullmatch(login):
        raise Problem(400, 'Their Tailscale login looks like name@example.com.')
    if login in OWNER_LOGINS:
        raise Problem(400, 'That is you.')
    with LOCK:
        s = load()
        f = next((f for f in s['friends'] if f['login'] == login), None)
        if not f:
            f = {'id': secrets.token_hex(4), 'login': login, 'added_at': now()}
            s['friends'].append(f)
        f['address'] = address
        f['name'] = _text(body.get('name'), 'name', 60) or f.get('name') or login.split('@')[0]
        s['requests'] = [r for r in s['requests'] if r['login'] != login]
        log(s, f"Added {f['name']} as a friend")
        save(s)
        name = s['name'] or 'A Wizard friend'
    # Say hello so their box can offer to add you back. Their Tailscale tells them who you are; nobody can fake it.
    try:
        fetch_json(address + 'api/friend/hello', {'name': name}, timeout=6)
        hello_state = 'sent'
    except Problem as p:
        hello_state = p.message
    return {'friend': f, 'hello': hello_state, 'me': me()}


def remove_friend(fid):
    with LOCK:
        s = load()
        gone = next((f for f in s['friends'] if f['id'] == fid), None)
        if not gone:
            raise Problem(404, 'No friend with that id.')
        s['friends'] = [f for f in s['friends'] if f['id'] != fid]
        log(s, f"Removed {gone.get('name') or gone['login']}")
        save(s)
    return me()


def hello(role, login, body):
    if role == 'owner' or not login:
        raise Problem(400, 'A friend request has to come from another person over Tailscale.')
    with LOCK:
        s = load()
        if any(f['login'] == login for f in s['friends']):
            return {'ok': True, 'friend': True}
        name = _text((body or {}).get('name'), 'name', 60) or login.split('@')[0]
        s['requests'] = [r for r in s['requests'] if r['login'] != login][-19:] + [{'login': login, 'name': name, 'at': now()}]
        log(s, f'{name} ({login}) asked to be friends')
        save(s)
    return {'ok': True, 'friend': False}


def dismiss_request(login):
    with LOCK:
        s = load()
        s['requests'] = [r for r in s['requests'] if r['login'] != login]
        save(s)
    return me()


def clean_remote(p, f):
    """A friend's answer, re-checked here: their box can never make a private app look public or ship unsafe CSS."""
    out = {'friend': {k: f.get(k) for k in ('id', 'name', 'login', 'address')}, 'viewer': str(p.get('viewer') or '')[:10],
           'name': str(p.get('name') or f.get('name') or '')[:60], 'bio': str(p.get('bio') or '')[:400],
           'published_at': str(p.get('published_at') or '')[:20], 'fingerprint': str(p.get('fingerprint') or '')[:16],
           'build': None, 'skin': None, 'apps': None}
    b = p.get('build')
    if isinstance(b, dict) and b.get('repo') == SHELL_REPO and FULL_SHA.fullmatch(str(b.get('commit', ''))) \
            and public_commit(SHELL_REPO, b['commit']) == b['commit']:
        out['build'] = {'repo': SHELL_REPO, 'commit': b['commit'], 'name': str(b.get('name') or '')[:80],
                        'base': str(b.get('base') or '')[:40], 'changes': clean_changes(b.get('changes')),
                        'built_at': str(b.get('built_at') or '')[:20]}
    k = p.get('skin')
    if isinstance(k, dict) and SKIN_ID.fullmatch(str(k.get('id', ''))):
        css = clean_css(k.get('css') or '')
        out['skin'] = {'id': k['id'], 'name': str(k.get('name') or k['id'])[:60], 'css': css,
                       'sha256': hashlib.sha256(css.encode()).hexdigest()}
    if isinstance(p.get('apps'), list):
        apps = []
        for a in p['apps'][:200]:
            if isinstance(a, dict) and APP.fullmatch(str(a.get('id', ''))) and REPO.fullmatch(str(a.get('repo', ''))):
                rec = store_listing(a['repo'])
                if rec:
                    apps.append({'id': a['id'], 'repo': rec['repo'], 'store_id': str(rec.get('id') or a['id'])[:64],
                                 'name': str(rec.get('name') or a['id'])[:60], 'summary': str(rec.get('summary') or '')[:200],
                                 'uses': a.get('uses') is True})
        out['apps'] = apps
    return out


def friend_profile(fid):
    f = next((f for f in load()['friends'] if f['id'] == fid), None)
    if not f:
        raise Problem(404, 'No friend with that id.')
    return clean_remote(fetch_json(f['address'] + 'api/friend/profile'), f)


def me():
    s = load()
    return {**{k: s[k] for k in ('name', 'bio', 'visibility', 'hidden', 'uses', 'snapshot', 'friends', 'requests', 'wearing')},
            'look_saved': bool(s.get('look_backup')), 'you': sorted(OWNER_LOGINS)[0] if OWNER_LOGINS else '', 'link': FRIEND_LINK, 'activity': list(reversed(s['activity'][-20:])), 'shell_repo': SHELL_REPO}


def update_me(body):
    if not isinstance(body, dict):
        raise Problem(400, 'Expected an object.')
    unknown = set(body) - {'name', 'bio', 'visibility', 'hidden', 'uses'}
    if unknown:
        raise Problem(400, 'Unknown field: ' + ', '.join(sorted(unknown)) + '.')
    with LOCK:
        s = load()
        if 'name' in body:
            s['name'] = _text(body['name'], 'name', 60)
        if 'bio' in body:
            s['bio'] = _text(body['bio'], 'bio', 280)
        if 'visibility' in body:
            v = body['visibility']
            if not isinstance(v, dict) or not v or any(k not in SECTIONS or v[k] not in LEVELS for k in v):
                raise Problem(400, 'visibility maps build, skin or apps to private, friends or public.')
            if v.get('build') == 'public':
                # Trying on a build runs its code on your data, so it is only ever for people you're connected to.
                raise Problem(400, 'A build can be shared with friends, never with everyone.')
            for k, level in v.items():
                if s['visibility'][k] != level:
                    log(s, f"{ {'build': 'Build', 'skin': 'Look', 'apps': 'Apps'}[k] }: {level}")
                s['visibility'][k] = level
        for key in ('hidden', 'uses'):
            if key in body:
                v = body[key]
                if not isinstance(v, list) or len(v) > 200 or not all(isinstance(x, str) and APP.fullmatch(x) for x in v):
                    raise Problem(400, f'{key} must be a list of app ids.')
                s[key] = sorted(set(v))
        save(s)
    return me()


# ---------- MCP (same service layer as the view) ----------

TOOLS = [
    {'name': 'profile_get', 'description': "The owner's Wizard profile: who sees the build, look and apps (private, friends, public), the published snapshot, friends and pending friend requests.",
     'inputSchema': {'type': 'object', 'properties': {}, 'additionalProperties': False}, 'annotations': {'readOnlyHint': True}},
    {'name': 'profile_preview', 'description': "Exactly what a friend, or anyone else, sees of the owner's profile right now.",
     'inputSchema': {'type': 'object', 'properties': {'as': {'type': 'string', 'enum': ['friend', 'public']}}, 'required': ['as'], 'additionalProperties': False},
     'annotations': {'readOnlyHint': True}},
    {'name': 'profile_set_visibility', 'description': 'Set who sees one part of the profile: build, skin or apps -> private, friends or public. Only when the owner asked.',
     'inputSchema': {'type': 'object', 'properties': {'part': {'type': 'string', 'enum': list(SECTIONS)}, 'level': {'type': 'string', 'enum': list(LEVELS)}},
                     'required': ['part', 'level'], 'additionalProperties': False}},
    {'name': 'friends_list', 'description': 'Friends (people whose box reaches this one over a private Tailscale connection) and pending friend requests.',
     'inputSchema': {'type': 'object', 'properties': {}, 'additionalProperties': False}, 'annotations': {'readOnlyHint': True}},
    {'name': 'friend_profile', 'description': "Read a friend's profile from their box: their build, look and App Store apps, whatever they share with friends.",
     'inputSchema': {'type': 'object', 'properties': {'id': {'type': 'string', 'description': 'Friend id from friends_list'}}, 'required': ['id'], 'additionalProperties': False},
     'annotations': {'readOnlyHint': True}},
]


def rpc(msg):
    if not isinstance(msg, dict):
        return {'jsonrpc': '2.0', 'id': None, 'error': {'code': -32600, 'message': 'Expected a JSON-RPC object.'}}
    m, i, p = msg.get('method'), msg.get('id'), msg.get('params') or {}
    if 'id' not in msg:
        return None
    try:
        if m == 'initialize':
            r = {'protocolVersion': '2025-06-18', 'capabilities': {'tools': {}}, 'serverInfo': {'name': APP_ID, 'version': VERSION}}
        elif m == 'tools/list':
            r = {'tools': TOOLS}
        elif m == 'tools/call':
            a, n = p.get('arguments') or {}, p.get('name')
            if n == 'profile_get':
                v = me()
            elif n == 'profile_preview':
                v = view_for('friend' if a.get('as') == 'friend' else 'visitor')
            elif n == 'profile_set_visibility':
                v = update_me({'visibility': {a.get('part'): a.get('level')}})['visibility']
            elif n == 'friends_list':
                s = load()
                v = {'friends': s['friends'], 'requests': s['requests']}
            elif n == 'friend_profile':
                v = friend_profile(str(a.get('id', '')))
            else:
                return {'jsonrpc': '2.0', 'id': i, 'error': {'code': -32602, 'message': 'Unknown tool.'}}
            r = {'content': [{'type': 'text', 'text': json.dumps(v)}], 'structuredContent': v, 'isError': False}
        elif m == 'ping':
            r = {}
        else:
            return {'jsonrpc': '2.0', 'id': i, 'error': {'code': -32601, 'message': 'Unknown method.'}}
    except Problem as e:
        r = {'content': [{'type': 'text', 'text': e.message}], 'isError': True}
    return {'jsonrpc': '2.0', 'id': i, 'result': r}


# ---------- HTTP ----------

def _csv(name):
    return {x.strip().lower() for x in os.environ.get(name, '').split(',') if x.strip()}


_PORT = os.environ.get('PORT', '8836')
_LOOPBACK = {f'127.0.0.1:{_PORT}', f'localhost:{_PORT}', f'{APP_ID}:{_PORT}'}
TRUSTED_HOSTS = _csv('WIZARD_TRUSTED_HOSTS') | _LOOPBACK
TRUSTED_ORIGINS = _csv('WIZARD_TRUSTED_ORIGINS') | {'http://' + h for h in _LOOPBACK}
# A friend reaches this box by its own tailnet name, on whichever Serve port; their login decides what they get.
FRIEND_PATHS = ('/api/friend/profile', '/api/friend/hello', '/healthz')


class Handler(BaseHTTPRequestHandler):
    def refused(self, path, write=False):
        host = (self.headers.get('Host') or '').lower()
        friend_route = path in FRIEND_PATHS and via_serve(self.headers)
        if host not in TRUSTED_HOSTS and not friend_route:
            self.send(403, {'error': 'Unknown host.'})
            return True
        if write and not friend_route:
            origin = (self.headers.get('Origin') or '').lower()
            if origin and origin not in TRUSTED_ORIGINS:
                self.send(403, {'error': 'Cross-origin writes refused.'})
                return True
            if not origin and (self.headers.get('Sec-Fetch-Site') or '') == 'cross-site':
                self.send(403, {'error': 'Cross-origin writes refused.'})
                return True
        return False

    def send(self, code, body=None, content_type='application/json'):
        b = body if isinstance(body, bytes) else b'' if body is None else json.dumps(body).encode()
        self.send_response(code)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(b)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Content-Security-Policy', "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'")
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(b)

    def owner_only(self):
        if role_of(self.headers)[0] != 'owner':
            self.send(403, {'error': 'Only the owner can do that.'})
            return True
        return False

    def body(self):
        if self.headers.get('Content-Type', '').split(';')[0].strip() != 'application/json':
            raise Problem(415, 'Use application/json.')
        size = int(self.headers.get('Content-Length') or 0)
        if not 0 <= size <= 256 * 1024:
            raise Problem(413, 'Request too large.')
        return json.loads(self.rfile.read(size) or b'{}')

    def do_GET(self):
        u = urlsplit(self.path)
        path, q = u.path, parse_qs(u.query)
        if self.refused(path):
            return
        try:
            if path == '/healthz':
                return self.send(200, {'ok': True, 'app': APP_ID, 'version': VERSION})
            if path == '/api/friend/profile':
                return self.send(200, view_for(role_of(self.headers)[0]))
            if path.startswith('/api/') and self.owner_only():
                return
            if path == '/api/me':
                return self.send(200, me())
            if path == '/api/preview':
                return self.send(200, view_for('friend' if q.get('as', [''])[0] == 'friend' else 'visitor'))
            m = re.fullmatch(r'/api/friends/([0-9a-f]{8})/profile', path)
            if m:
                return self.send(200, friend_profile(m.group(1)))
            if path == '/openapi.json':
                return self.send(200, (ROOT / 'openapi.json').read_bytes())
            name = 'index.html' if path == '/' else path[1:]
            kind = STATIC_TYPES.get(Path(name).suffix)
            if kind and '/' not in name and not name.startswith('.') and (ROOT / 'web' / name).is_file():
                return self.send(200, (ROOT / 'web' / name).read_bytes(), kind)
            self.send(405 if path == '/mcp' else 404, {'error': 'Use POST /mcp.' if path == '/mcp' else 'Not found.'})
        except Problem as e:
            self.send(e.code, {'error': e.message})

    def do_HEAD(self):
        self.do_GET()

    def do_POST(self):
        path = urlsplit(self.path).path
        if self.refused(path, write=True):
            return
        try:
            body = self.body()
            if path == '/api/friend/hello':
                role, login = role_of(self.headers)
                return self.send(200, hello(role, login, body if isinstance(body, dict) else {}))
            if self.owner_only():
                return
            if path == '/mcp':
                out = rpc(body)
                return self.send(202 if out is None else 200, out)
            if path == '/api/publish':
                return self.send(200, publish(body))
            if path == '/api/friends':
                return self.send(201, add_friend(body))
            if path == '/api/look/backup':
                return self.send(200, save_look_backup(body))
            if path == '/api/look/restore':
                return self.send(200, take_look_backup())
            if path == '/api/requests/dismiss':
                return self.send(200, dismiss_request(_text((body or {}).get('login'), 'login', 320, True).lower()))
            self.send(404, {'error': 'Not found.'})
        except Problem as e:
            self.send(e.code, {'error': e.message})
        except (ValueError, TypeError, AttributeError):
            self.send(400, {'error': 'Invalid JSON request.'})

    def do_PUT(self):
        path = urlsplit(self.path).path
        if self.refused(path, write=True) or self.owner_only():
            return
        try:
            if path == '/api/me':
                return self.send(200, update_me(self.body()))
            self.send(404, {'error': 'Not found.'})
        except Problem as e:
            self.send(e.code, {'error': e.message})
        except (ValueError, TypeError, AttributeError):
            self.send(400, {'error': 'Invalid JSON request.'})

    def do_DELETE(self):
        path = urlsplit(self.path).path
        if self.refused(path, write=True) or self.owner_only():
            return
        try:
            m = re.fullmatch(r'/api/friends/([0-9a-f]{8})', path)
            if m:
                return self.send(200, remove_friend(m.group(1)))
            self.send(404, {'error': 'Not found.'})
        except Problem as e:
            self.send(e.code, {'error': e.message})

    def log_message(self, format, *args):
        pass


if __name__ == '__main__':
    DATA.mkdir(parents=True, exist_ok=True)
    ThreadingHTTPServer((os.environ.get('BIND', '0.0.0.0'), int(_PORT)), Handler).serve_forever()

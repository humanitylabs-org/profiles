"""Wizard Profiles: share your build, your look and your App Store apps with friends, or with everyone.

One rule for everything: each part of a profile is Private (the default), Friends or Public. Nothing local is
shared: an app counts only when the Wizard App Index lists its public repo, a build only when its exact commit is
public shell code anyone can fetch, a look only as sanitised CSS (the owner's My skin, read by the view from the shell). Others see a frozen snapshot taken when the owner
taps Publish, never live state.

Identity is Nostr, never email. This Wizard has its own Nostr key (made on first start, kept in app-data): its npub
is the profile's ID and the only thing you give a friend. Nobody connects to your Wizard: what you share goes out as
signed Nostr events on public relays. Public parts are one signed event anyone with your npub can read; friends'
parts are encrypted to each friend alone (NIP-44) under a tag only the two of you can work out; a friend request is a
NIP-59 gift wrap, so relays never see who added whom. This app answers only you (your own Wizard screens and the
box-local agent).

Stdlib only.
"""
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import socket
import ssl
import struct
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
VERSION = '0.5.0'
INDEX = os.environ.get('WIZARD_APP_INDEX', 'https://apps.aiwizards.com').rstrip('/')
SHELL_REPO = os.environ.get('PROFILES_SHELL_REPO', 'humanitylabs-org/wizard-ux')
SKINS = Path(os.environ.get('SKINS_DIR', '/skins'))   # the owner's Files Skins folder, read-only
OWNER_LOGINS = {x.strip().lower() for x in os.environ.get('OWNER_LOGINS', '').split(',') if x.strip()}
LEVELS = ('private', 'friends', 'public')
SECTIONS = ('build', 'skin', 'apps')
PARTS = ('card',) + SECTIONS
LEVEL_NAMES = {'private': 'Only you', 'friends': 'Friends', 'public': 'Everyone'}
NOT_APPS = {'wizard-ux', 'wizard-agent-service', APP_ID}   # the shell and the service are the build; Profiles is the profile
STATIC_TYPES = {'.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8',
                '.svg': 'image/svg+xml'}
LOCK = threading.RLock()
APP = re.compile(r'^[a-z0-9][a-z0-9-]{0,63}$')
REPO = re.compile(r'^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$')
SHA = re.compile(r'^[0-9a-f]{7,40}$')
FULL_SHA = re.compile(r'^[0-9a-f]{40}$')
SKIN_ID = re.compile(r'^[a-z0-9-]{1,40}$')
MAX_CSS = 64 * 1024


class Problem(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code, self.message = code, message


# ---------- Nostr: npub/bech32, BIP-340 sign/verify (stdlib only) ----------
# Identity is a Nostr key, not an email: this Wizard's own key (spec/WIZARD_ID.md "Your Wizard's own key").

_CS = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'
_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
      0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def _polymod(values):
    gen, chk = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3], 1
    for v in values:
        top = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ v
        for i in range(5):
            chk ^= gen[i] if (top >> i) & 1 else 0
    return chk


def _hrp(h):
    return [ord(x) >> 5 for x in h] + [0] + [ord(x) & 31 for x in h]


def _bits(data, f, t, pad):
    acc = bits = 0
    out, maxv = [], (1 << t) - 1
    for v in data:
        acc = (acc << f) | v
        bits += f
        while bits >= t:
            bits -= t
            out.append((acc >> bits) & maxv)
    if pad and bits:
        out.append((acc << (t - bits)) & maxv)
    elif not pad and (bits >= f or (acc << (t - bits)) & maxv):
        raise ValueError('bad padding')
    return out


def b32_encode(hrp, raw):
    vals = _bits(raw, 8, 5, True)
    chk = _polymod(_hrp(hrp) + vals + [0] * 6) ^ 1
    return hrp + '1' + ''.join(_CS[v] for v in vals + [(chk >> 5 * (5 - i)) & 31 for i in range(6)])


def b32_decode(hrp_want, text):
    s = re.sub(r'\s+', '', str(text or '')).lower()
    if s.startswith('nostr:'):
        s = s[6:]
    hrp, _, data = s.rpartition('1')
    if hrp != hrp_want or not data or any(c not in _CS for c in data):
        return None
    vals = [_CS.index(c) for c in data]
    if len(vals) < 7 or _polymod(_hrp(hrp) + vals) != 1:
        return None
    try:
        return bytes(_bits(vals[:-6], 5, 8, False))
    except ValueError:
        return None


def npub_encode(hexkey):
    vals = _bits(bytes.fromhex(hexkey), 8, 5, True)
    chk = _polymod(_hrp('npub') + vals + [0] * 6) ^ 1
    return 'npub1' + ''.join(_CS[v] for v in vals + [(chk >> 5 * (5 - i)) & 31 for i in range(6)])


def npub_decode(npub):
    s = str(npub or '').strip().lower()
    if s.startswith('nostr:'):
        s = s[6:]
    hrp, _, data = s.rpartition('1')
    if hrp != 'npub' or not data or any(c not in _CS for c in data):
        raise Problem(400, 'That is not a Nostr ID (npub1…).')
    vals = [_CS.index(c) for c in data]
    if _polymod(_hrp(hrp) + vals) != 1:
        raise Problem(400, 'That Nostr ID has a typo (checksum).')
    raw = bytes(_bits(vals[:-6], 5, 8, False))
    if len(raw) != 32:
        raise Problem(400, 'That Nostr ID is the wrong length.')
    return raw.hex()


def _add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    if a[0] == b[0] and a[1] != b[1]:
        return None
    lam = (3 * a[0] * a[0] * pow(2 * a[1], _P - 2, _P) if a == b else (b[1] - a[1]) * pow(b[0] - a[0], _P - 2, _P)) % _P
    x = (lam * lam - a[0] - b[0]) % _P
    return (x, (lam * (a[0] - x) - a[1]) % _P)


def _mul(p, n):
    r = None
    while n:
        if n & 1:
            r = _add(r, p)
        p, n = _add(p, p), n >> 1
    return r


def _tag_hash(tag, msg):
    t = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(t + t + msg).digest()


def _lift_x(x):
    if x >= _P:
        return None
    y2 = (pow(x, 3, _P) + 7) % _P
    y = pow(y2, (_P + 1) // 4, _P)
    return None if y * y % _P != y2 else (x, y if y % 2 == 0 else _P - y)


def schnorr_sign(msg, seckey):
    d0 = int.from_bytes(seckey, 'big')
    P = _mul(_G, d0)
    d = d0 if P[1] % 2 == 0 else _N - d0
    px = P[0].to_bytes(32, 'big')
    t = (d ^ int.from_bytes(_tag_hash('BIP0340/aux', secrets.token_bytes(32)), 'big')).to_bytes(32, 'big')
    k0 = int.from_bytes(_tag_hash('BIP0340/nonce', t + px + msg), 'big') % _N
    R = _mul(_G, k0)
    k = k0 if R[1] % 2 == 0 else _N - k0
    rx = R[0].to_bytes(32, 'big')
    e = int.from_bytes(_tag_hash('BIP0340/challenge', rx + px + msg), 'big') % _N
    return rx + ((k + e * d) % _N).to_bytes(32, 'big')


def schnorr_verify(msg, pubkey, sig):
    if len(pubkey) != 32 or len(sig) != 64:
        return False
    pt = _lift_x(int.from_bytes(pubkey, 'big'))
    r, s = int.from_bytes(sig[:32], 'big'), int.from_bytes(sig[32:], 'big')
    if pt is None or r >= _P or s >= _N:
        return False
    e = int.from_bytes(_tag_hash('BIP0340/challenge', sig[:32] + pubkey + msg), 'big') % _N
    R = _add(_mul(_G, s), _mul(pt, _N - e))
    return R is not None and R[1] % 2 == 0 and R[0] == r


def event_id(ev):
    ser = json.dumps([0, ev['pubkey'], ev['created_at'], ev['kind'], ev['tags'], ev['content']], separators=(',', ':'), ensure_ascii=False)
    return hashlib.sha256(ser.encode()).hexdigest()


def verify_event(ev):
    try:
        return isinstance(ev, dict) and event_id(ev) == ev['id'] and schnorr_verify(bytes.fromhex(ev['id']), bytes.fromhex(ev['pubkey']), bytes.fromhex(ev['sig']))
    except (KeyError, TypeError, ValueError):
        return False


_KEY = None


def box_key():
    """This Wizard's own key: made once on first start, kept 0600 in app-data, never leaves the app."""
    global _KEY
    if _KEY:
        return _KEY
    path = DATA / 'wizard-key.json'
    try:
        sk = bytes.fromhex(json.loads(path.read_text())['secret'])
        # Owner-only, every start: copies and restores of app-data can loosen it.
        for p in [path, *DATA.glob('wizard-key.before-*.json'), DATA / 'profile.json']:
            _quiet(os.chmod, p, 0o600)
    except (OSError, ValueError, KeyError):
        sk = new_secret()
        DATA.mkdir(parents=True, exist_ok=True)
        tmp = DATA / f'.key.{secrets.token_hex(4)}.tmp'
        tmp.write_text(json.dumps({'secret': sk.hex()}))
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    _KEY = (sk, pub_of(sk))
    return _KEY


def new_secret():
    sk = secrets.token_bytes(32)
    while not 0 < int.from_bytes(sk, 'big') < _N:
        sk = secrets.token_bytes(32)
    return sk


def pub_of(sk):
    return _mul(_G, int.from_bytes(sk, 'big'))[0].to_bytes(32, 'big').hex()


_last_ts = [0]


def sign_event(kind, content, tags=(), sk=None, created_at=None):
    if created_at is None and 30000 <= kind < 40000:
        # A replaceable event only replaces an older one: two shares in the same second would leave the relay
        # keeping either. Each new copy is at least one second newer than the last.
        created_at = _last_ts[0] = max(int(time.time()), _last_ts[0] + 1)
    if sk is None:
        sk, pk = box_key()
    else:
        pk = pub_of(sk)
    ev = {'pubkey': pk, 'created_at': int(created_at or time.time()), 'kind': kind, 'tags': [list(t) for t in tags], 'content': content}
    ev['id'] = event_id(ev)
    ev['sig'] = schnorr_sign(bytes.fromhex(ev['id']), sk).hex()
    return ev


def box_npub():
    return npub_encode(box_key()[1])


# NIP-44 v2: what you share with one friend is encrypted to that friend alone (ECDH + HKDF + ChaCha20 + HMAC).
_M32 = 0xffffffff


def _rotl(v, c):
    return ((v << c) & _M32) | (v >> (32 - c))


def _chacha_block(kw, counter, nw):
    st = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574, *kw, counter, *nw]
    x = st[:]
    for _ in range(10):
        for a, b, c, d in ((0, 4, 8, 12), (1, 5, 9, 13), (2, 6, 10, 14), (3, 7, 11, 15),
                           (0, 5, 10, 15), (1, 6, 11, 12), (2, 7, 8, 13), (3, 4, 9, 14)):
            x[a] = (x[a] + x[b]) & _M32; x[d] = _rotl(x[d] ^ x[a], 16)
            x[c] = (x[c] + x[d]) & _M32; x[b] = _rotl(x[b] ^ x[c], 12)
            x[a] = (x[a] + x[b]) & _M32; x[d] = _rotl(x[d] ^ x[a], 8)
            x[c] = (x[c] + x[d]) & _M32; x[b] = _rotl(x[b] ^ x[c], 7)
    return struct.pack('<16I', *((x[i] + st[i]) & _M32 for i in range(16)))


def chacha20(key, nonce, data, counter=0):
    kw, nw = struct.unpack('<8I', key), struct.unpack('<3I', nonce)
    out = bytearray()
    for i in range(0, len(data), 64):
        chunk = data[i:i + 64]
        ks = _chacha_block(kw, counter + i // 64, nw)[:len(chunk)]
        out += (int.from_bytes(chunk, 'little') ^ int.from_bytes(ks, 'little')).to_bytes(len(chunk), 'little')
    return bytes(out)


# ---------- identity backup: NIP-49 (ncryptsec), so any Nostr app that reads it can open it ----------
# scrypt(password) -> key; XChaCha20-Poly1305 seals the 32-byte secret. The password never touches disk.

def _hchacha20(key, nonce16):
    x = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574, *struct.unpack('<8I', key), *struct.unpack('<4I', nonce16)]
    for _ in range(10):
        for a, b, c, d in ((0, 4, 8, 12), (1, 5, 9, 13), (2, 6, 10, 14), (3, 7, 11, 15),
                           (0, 5, 10, 15), (1, 6, 11, 12), (2, 7, 8, 13), (3, 4, 9, 14)):
            x[a] = (x[a] + x[b]) & _M32; x[d] = _rotl(x[d] ^ x[a], 16)
            x[c] = (x[c] + x[d]) & _M32; x[b] = _rotl(x[b] ^ x[c], 12)
            x[a] = (x[a] + x[b]) & _M32; x[d] = _rotl(x[d] ^ x[a], 8)
            x[c] = (x[c] + x[d]) & _M32; x[b] = _rotl(x[b] ^ x[c], 7)
    return struct.pack('<8I', *x[0:4], *x[12:16])


def _poly1305(key, msg):
    r = int.from_bytes(key[:16], 'little') & 0x0ffffffc0ffffffc0ffffffc0fffffff
    sv, acc, p = int.from_bytes(key[16:], 'little'), 0, (1 << 130) - 5
    for i in range(0, len(msg), 16):
        acc = (acc + int.from_bytes(msg[i:i + 16] + b'\x01', 'little')) * r % p
    return ((acc + sv) & ((1 << 128) - 1)).to_bytes(16, 'little')


def _xc_tag(key, nonce12, ad, ct):
    pad = lambda b: b + b'\x00' * (-len(b) % 16)
    otk = chacha20(key, nonce12, b'\x00' * 32)
    return _poly1305(otk, pad(ad) + pad(ct) + struct.pack('<QQ', len(ad), len(ct)))


def xchacha_seal(key, nonce24, ad, pt):
    sub, n12 = _hchacha20(key, nonce24[:16]), b'\x00' * 4 + nonce24[16:]
    ct = chacha20(sub, n12, pt, 1)
    return ct + _xc_tag(sub, n12, ad, ct)


def xchacha_open(key, nonce24, ad, sealed):
    sub, n12 = _hchacha20(key, nonce24[:16]), b'\x00' * 4 + nonce24[16:]
    ct, tag = sealed[:-16], sealed[-16:]
    if not hmac.compare_digest(_xc_tag(sub, n12, ad, ct), tag):
        return None
    return chacha20(sub, n12, ct, 1)


_SCRYPT = threading.Lock()   # one at a time: each takes 64 MB and the app has 128 MB


def _scrypt(password, salt, log_n):
    import unicodedata
    pw = unicodedata.normalize('NFKC', password).encode()
    with _SCRYPT:
        return hashlib.scrypt(pw, salt=salt, n=1 << log_n, r=8, p=1, maxmem=(1 << log_n) * 1024 + (16 << 20), dklen=32)


BACKUP_LOG_N = 16


def _check_password(pw):
    if not isinstance(pw, str) or not 10 <= len(pw) <= 200:
        raise Problem(400, 'Use a password of at least 10 characters.')
    return pw


def ncryptsec_encode(sk, password, log_n=BACKUP_LOG_N):
    salt, nonce = os.urandom(16), os.urandom(24)
    ad = b'\x00'      # NIP-49: this key has lived unencrypted on a server, so say so honestly
    sealed = xchacha_seal(_scrypt(password, salt, log_n), nonce, ad, sk)
    return b32_encode('ncryptsec', bytes([2, log_n]) + salt + nonce + ad + sealed)


def ncryptsec_decode(text, password):
    raw = b32_decode('ncryptsec', text)
    if raw is None and str(text or '').strip().lower().startswith('nsec1'):
        raw = b32_decode('nsec', text)
        if raw is not None and len(raw) == 32:
            return raw
    if raw is None or len(raw) != 91 or raw[0] != 2:
        raise Problem(400, "That isn't a Profiles backup. It should start with ncryptsec1.")
    log_n, salt, nonce, ad, sealed = raw[1], raw[2:18], raw[18:42], raw[42:43], raw[43:]
    if not 1 <= log_n <= 16:
        raise Problem(400, "This backup uses a setting this Wizard can't open.")
    try:
        key = _scrypt(password, salt, log_n)
    except (ValueError, MemoryError):
        raise Problem(400, "This backup uses a setting this Wizard can't open.")
    sk = xchacha_open(key, nonce, ad, sealed)
    if sk is None or len(sk) != 32 or not 0 < int.from_bytes(sk, 'big') < _N:
        raise Problem(400, "That password doesn't open this backup.")
    return sk


def backup_identity(body):
    pw = _check_password((body or {}).get('password'))
    sk, pk = box_key()
    return {'backup': ncryptsec_encode(sk, pw), 'npub': npub_encode(pk)}


def confirm_backup():
    """The owner ticked "I saved it": only then does the screen call the identity backed up."""
    with LOCK:
        s = load()
        s['backed_up_at'] = now()
        log(s, 'You backed up your identity')
        save(s)
    return me()


def restore_identity(body):
    body = body or {}
    sk = ncryptsec_decode(body.get('backup'), str(body.get('password') or ''))
    global _KEY
    with LOCK:
        cur_sk, cur_pk = box_key()
        if sk == cur_sk:
            return {'changed': False, 'me': me()}
        stamp = time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())
        # Keep the ID being replaced, so a restore can always be undone from this Wizard's own files.
        old = DATA / f'wizard-key.before-{stamp}.json'
        tmp = DATA / f'.key.{secrets.token_hex(4)}.tmp'
        tmp.write_text(json.dumps({'secret': cur_sk.hex(), 'npub': npub_encode(cur_pk), 'replaced_at': now()}))
        os.chmod(tmp, 0o600)
        os.replace(tmp, old)
        tmp = DATA / f'.key.{secrets.token_hex(4)}.tmp'
        tmp.write_text(json.dumps({'secret': sk.hex()}))
        os.chmod(tmp, 0o600)
        os.replace(tmp, DATA / 'wizard-key.json')
        _KEY = None
        _ck_cache.clear()
        s = load()
        s.update({'requests': [], 'requests_since': 0, 'shared_at': None, 'sync': None, 'backed_up_at': now(), 'public_live': True})
        log(s, 'You restored your identity from a backup')
        save(s)
    sync_soon()
    threading.Thread(target=lambda: _quiet(check_requests), daemon=True).start()
    return {'changed': True, 'me': me()}


def _hkdf_expand(prk, info, length):
    out, t, i = b'', b'', 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        out, i = out + t, i + 1
    return out[:length]


_ck_cache = {}


def conversation_key(sk, pub_hex):
    k = (sk, pub_hex)
    if k not in _ck_cache:
        pt = _lift_x(int(pub_hex, 16))
        if pt is None:
            raise Problem(400, 'Not a valid Nostr ID.')
        shared = _mul(pt, int.from_bytes(sk, 'big'))[0].to_bytes(32, 'big')
        _ck_cache[k] = hmac.new(b'nip44-v2', shared, hashlib.sha256).digest()
    return _ck_cache[k]


def _padded_len(n):
    if n <= 32:
        return 32
    nxt = 1 << (n - 1).bit_length()
    chunk = 32 if nxt <= 256 else nxt // 8
    return chunk * ((n - 1) // chunk + 1)


def nip44_encrypt(ck, text, nonce=None):
    pt = text.encode()
    if not 1 <= len(pt) <= 65535:
        raise Problem(413, 'Too much to share in one message.')
    nonce = nonce or os.urandom(32)
    keys = _hkdf_expand(ck, nonce, 76)
    padded = struct.pack('>H', len(pt)) + pt + bytes(_padded_len(len(pt)) - len(pt))
    ct = chacha20(keys[:32], keys[32:44], padded)
    mac = hmac.new(keys[44:], nonce + ct, hashlib.sha256).digest()
    return base64.b64encode(b'\x02' + nonce + ct + mac).decode()


def nip44_decrypt(ck, payload):
    raw = base64.b64decode(payload, validate=True)
    if len(raw) < 99 or raw[0] != 2:
        raise ValueError('unknown encryption version')
    nonce, ct, mac = raw[1:33], raw[33:-32], raw[-32:]
    keys = _hkdf_expand(ck, nonce, 76)
    if not hmac.compare_digest(mac, hmac.new(keys[44:], nonce + ct, hashlib.sha256).digest()):
        raise ValueError('bad mac')
    padded = chacha20(keys[:32], keys[32:44], ct)
    n = struct.unpack('>H', padded[:2])[0]
    if n == 0 or len(padded) != 2 + _padded_len(n):
        raise ValueError('bad padding')
    return padded[2:2 + n].decode()


# NIP-59 gift wrap: a friend request reaches someone through public relays without anyone else seeing who sent it.
HELLO_KIND = 1078


def _past():
    return int(time.time()) - secrets.randbelow(2 * 86400)


def gift_wrap(to_pk, content):
    sk, pk = box_key()
    rumor = {'pubkey': pk, 'created_at': int(time.time()), 'kind': HELLO_KIND, 'tags': [['t', 'wizard-profile']], 'content': content}
    rumor['id'] = event_id(rumor)
    seal = sign_event(13, nip44_encrypt(conversation_key(sk, to_pk), json.dumps(rumor)), (), sk, _past())
    esk = new_secret()
    return sign_event(1059, nip44_encrypt(conversation_key(esk, to_pk), json.dumps(seal)), [('p', to_pk)], esk, _past())


def unwrap(wrap):
    sk, _ = box_key()
    seal = json.loads(nip44_decrypt(conversation_key(sk, wrap['pubkey']), wrap['content']))
    if not verify_event(seal) or seal.get('kind') != 13:
        return None
    rumor = json.loads(nip44_decrypt(conversation_key(sk, seal['pubkey']), seal['content']))
    if not isinstance(rumor, dict) or rumor.get('pubkey') != seal['pubkey'] or rumor.get('kind') != HELLO_KIND:
        return None
    return rumor


def pair_tag(friend_pk):
    """The address of what you share with one friend: only the two of you can work it out, so relays can't map friends."""
    return 'wp-' + hmac.new(conversation_key(box_key()[0], friend_pk), b'wizard-profile', hashlib.sha256).hexdigest()[:32]


def pair_tag_from(friend_pk):
    return pair_tag(friend_pk)        # symmetric: the conversation key is the same both ways


# ---------- relays: a tiny websocket client (stdlib) ----------
RELAYS = [r.strip() for r in os.environ.get('PROFILES_RELAYS', 'wss://relay.damus.io,wss://nos.lol,wss://relay.primal.net').split(',')
          if r.strip().startswith('wss://')][:6]


class _WS:
    def __init__(self, url, timeout=8):
        u = urlsplit(url)
        raw = socket.create_connection((u.hostname, u.port or 443), timeout=timeout)
        self.sock = ssl.create_default_context().wrap_socket(raw, server_hostname=u.hostname)
        key = base64.b64encode(os.urandom(16)).decode()
        self.sock.sendall((f'GET {u.path or "/"} HTTP/1.1\r\nHost: {u.hostname}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n'
                           f'Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\nUser-Agent: wizard-profiles/{VERSION}\r\n\r\n').encode())
        head = b''
        while b'\r\n\r\n' not in head:
            c = self.sock.recv(4096)
            if not c:
                raise ConnectionError('closed')
            head += c
        first, _, self.buf = head.partition(b'\r\n\r\n')
        if b' 101 ' not in first.split(b'\r\n')[0]:
            raise ConnectionError('no websocket')

    def _read(self, n):
        while len(self.buf) < n:
            c = self.sock.recv(65536)
            if not c:
                raise ConnectionError('closed')
            self.buf += c
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def _frame(self, op, data):
        mask, n = os.urandom(4), len(data)
        hdr = bytes([0x80 | op]) + (bytes([0x80 | n]) if n < 126 else bytes([0xFE]) + struct.pack('>H', n) if n < 65536
                                    else bytes([0xFF]) + struct.pack('>Q', n))
        m = (mask * (n // 4 + 1))[:n]
        self.sock.sendall(hdr + mask + (int.from_bytes(data, 'big') ^ int.from_bytes(m, 'big')).to_bytes(n, 'big') if n else hdr + mask)

    def send(self, obj):
        self._frame(1, json.dumps(obj, separators=(',', ':')).encode())

    def recv(self):
        msg = b''
        while True:
            b1, b2 = self._read(2)
            op, n = b1 & 15, b2 & 127
            if n == 126:
                n = struct.unpack('>H', self._read(2))[0]
            elif n == 127:
                n = struct.unpack('>Q', self._read(8))[0]
            if n > 4 * 1024 * 1024:
                raise ConnectionError('frame too large')
            data = self._read(n)
            if op == 8:
                return None
            if op == 9:
                self._frame(10, data)
                continue
            if op == 10:
                continue
            msg += data
            if b1 & 0x80:
                return json.loads(msg)

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


def _each_relay(fn):
    out, threads = {}, []

    def run(r):
        try:
            out[r] = fn(r)
        except Exception as e:  # noqa: BLE001 - one relay failing never stops the others
            out[r] = e
    for r in RELAYS:
        t = threading.Thread(target=run, args=(r,), daemon=True)
        t.start()
        threads.append(t)
    for t in threads:
        t.join(20)
    return out


def relay_publish(events):
    """Send events to every relay; returns {event id: number of relays that stored it}."""
    if not events:
        return {}

    def one(r):
        ws, ok = _WS(r), set()
        try:
            for ev in events:
                ws.send(['EVENT', ev])
            end = time.time() + 10
            while len(ok) < len(events) and time.time() < end:
                m = ws.recv()
                if m is None:
                    break
                if m and m[0] == 'OK' and m[2] is True:
                    ok.add(m[1])
        finally:
            ws.close()
        return ok
    got = _each_relay(one)
    return {ev['id']: sum(1 for v in got.values() if isinstance(v, set) and ev['id'] in v) for ev in events}


def relay_query(filters):
    def one(r):
        ws, sub, evs = _WS(r), secrets.token_hex(6), []
        try:
            ws.send(['REQ', sub, *filters])
            end = time.time() + 10
            while time.time() < end:
                m = ws.recv()
                if m is None or (m[0] in ('EOSE', 'CLOSED') and m[1] == sub):
                    break
                if m[0] == 'EVENT' and m[1] == sub and isinstance(m[2], dict):
                    evs.append(m[2])
        finally:
            ws.close()
        return evs
    got, seen, out = _each_relay(one), set(), []
    for v in got.values():
        for ev in v if isinstance(v, list) else []:
            if ev.get('id') not in seen and verify_event(ev):
                seen.add(ev['id'])
                out.append(ev)
    return out, sum(1 for v in got.values() if isinstance(v, list))


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
    return {'name': '', 'bio': '', 'picture': '', 'messenger': '', 'visibility': {**{s: 'private' for s in SECTIONS}, 'card': 'friends'}, 'hidden': [], 'uses': [],
            'snapshot': None, 'friends': [], 'requests': [], 'activity': [], 'look_backup': None, 'wearing': None}


def load():
    try:
        s = json.loads((DATA / 'profile.json').read_text())
    except (OSError, ValueError):
        return _blank()
    out = _blank()
    if isinstance(s, dict):
        out.update({k: s[k] for k in out if k in s and (type(s[k]) is type(out[k]) or (out[k] is None and isinstance(s[k], dict)))})
    vis = out['visibility']
    out['visibility'] = {k: vis.get(k) if vis.get(k) in LEVELS else 'private' for k in SECTIONS}
    out['visibility']['card'] = vis.get('card') if vis.get('card') in ('friends', 'public') else 'friends'
    for k, d in (('sync', None), ('shared_at', None), ('public_live', False), ('unshare', []), ('ignored', []),
                 ('requests_since', 0), ('requests_checked', None), ('backed_up_at', None)):
        out[k] = s.get(k, d) if isinstance(s, dict) else d
    # Friends and requests are Nostr IDs; older email-based entries (before 0.2) are dropped.
    out['friends'] = [f for f in out['friends'] if isinstance(f, dict) and re.fullmatch(r'[0-9a-f]{64}', str(f.get('pubkey', '')))]
    out['requests'] = [r for r in out['requests'] if isinstance(r, dict) and re.fullmatch(r'[0-9a-f]{64}', str(r.get('pubkey', '')))]
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


APP_TYPES = ('view', 'service', 'agent', 'external')   # App Store kinds: Apps, Agent apps, Agents, Connectors


def app_type(rec):
    """The App Store's own kind for a listing, so every Wizard groups a profile's apps the same way."""
    t = str((rec or {}).get('type') or '')
    return t if t in APP_TYPES else 'service'


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


def my_skin_raw():
    """The owner's My skin exactly as saved (comments and all), so putting it back loses nothing."""
    for p in (SKINS / 'My skin' / 'skin.css', SKINS / 'My skin.css'):
        try:
            if p.is_file() and not p.is_symlink() and p.stat().st_size <= MAX_CSS:
                return p.read_text('utf-8', 'replace')
        except OSError:
            pass
    return None


def save_look_backup(body):
    """Before wearing a friend's look, the view parks the owner's own look here so one tap puts it back."""
    if not isinstance(body, dict) or not SKIN_ID.fullmatch(str(body.get('skin') or '')) or not isinstance(body.get('css', ''), str) \
            or len(body.get('css', '')) > MAX_CSS:
        raise Problem(400, 'Expected {skin, css}.')
    with LOCK:
        s = load()
        if not s.get('look_backup'):                 # keep the first one: trying several looks in a row still returns to yours
            raw = my_skin_raw()
            s['look_backup'] = {'skin': body['skin'], 'css': raw if raw is not None else body.get('css', ''), 'exact': raw is not None, 'at': now()}
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
                     'category': str(rec.get('category') or '')[:30], 'type': a['type'] if a.get('type') in APP_TYPES else app_type(rec),
                     'system': a.get('system') is True})
    snap['apps'] = sorted(apps, key=lambda x: x['name'].lower())
    report['shared'].append({'part': 'apps', 'what': f'{len(apps)} App Store apps'})

    # Called every time you open Profiles: it reads what your Wizard has now. Only a real change is shared again.
    body_of = lambda x: {k: v for k, v in (x or {}).items() if k not in ('published_at', 'fingerprint')}
    with LOCK:
        s = load()
        changed = body_of(s['snapshot']) != body_of(snap)
        if changed:
            snap['fingerprint'] = hashlib.sha256(json.dumps(body_of(snap), sort_keys=True).encode()).hexdigest()[:16]
            s['snapshot'] = snap
            log(s, f"Your Wizard changed: {len(apps)} apps, {snap['skin']['name']} look" + (f", build {sha[:8]}" if sha else ''))
            save(s)
    if changed and (s['friends'] or any(s['visibility'][p] == 'public' for p in SECTIONS)):
        sync_soon()
    return {'changed': changed, 'report': report, 'me': me()}



# ---------- what each viewer may see ----------
# Levels: 'private' (only you), 'friends' (people you added, each gets their own encrypted copy), 'public' (anyone who
# has your Nostr ID). Your name and photo ('card') are never private: friends always see who you are.

def view_for(role, s=None):
    s = s or load()
    allowed = {'owner': LEVELS, 'friend': ('friends', 'public'), 'visitor': ('public',)}[role]
    snap = s['snapshot'] or {}
    card = s['visibility'].get('card', 'friends') in allowed
    out = {'app': APP_ID, 'version': VERSION, 'viewer': role, 'npub': box_npub(),
           'name': (s['name'] or 'A Wizard owner') if card else '', 'bio': s['bio'] if card else '',
           'picture': s['picture'] if card else '', 'messenger': s['messenger'] if card and role != 'visitor' else '',
           'updated_at': s.get('shared_at') or snap.get('published_at')}
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
    host = (headers.get('X-Forwarded-Host') or headers.get('Host') or '').lower().split(':')[0]
    return host.endswith('.ts.net') or bool(headers.get('X-Forwarded-For'))


def is_owner(headers):
    """Only you: this box itself (the agent's MCP gateway) or your own Wizard screens. Nobody else reaches this app;
    friends get what you share through Nostr relays, never by connecting to your Wizard."""
    if not via_serve(headers):
        return True
    login = (headers.get('Tailscale-User-Login') or '').strip().lower()
    # With no logins set, anyone signed in to this tailnet counts (Profiles is only published on the owner's private
    # network, like the shell itself); tagged or anonymous callers never do.
    return bool(login) and (not OWNER_LOGINS or login in OWNER_LOGINS)


# ---------- sharing over Nostr ----------
# Public parts: one signed kind 30078 event (d=wizard-profile) anyone with your npub can read.
# Friends' parts: one kind 30078 event per friend, NIP-44 encrypted to that friend, under a d tag only the two of you
# can work out, so relays can't see who your friends are. Friend requests: NIP-59 gift wraps (sender hidden).

PROFILE_KIND = 30078
_sync_lock = threading.Lock()


def share_events(s):
    evs = []
    pub = view_for('visitor', s)
    has_public = any(pub[p] for p in SECTIONS) or s['visibility'].get('card') == 'public'
    if has_public or s.get('public_live'):
        evs.append(sign_event(PROFILE_KIND, json.dumps(pub, separators=(',', ':')), [('d', 'wizard-profile'), ('t', 'wizard-profile')]))
    view = json.dumps(view_for('friend', s), separators=(',', ':'))
    for f in s['friends']:
        evs.append(sign_event(PROFILE_KIND, nip44_encrypt(conversation_key(box_key()[0], f['pubkey']), view), [('d', pair_tag(f['pubkey']))]))
    for pk in s.get('unshare', []):            # someone you removed: their copy is replaced by an encrypted "removed"
        evs.append(sign_event(PROFILE_KIND, nip44_encrypt(conversation_key(box_key()[0], pk), '{"removed":true}'), [('d', pair_tag(pk))]))
    return evs, has_public


def sync(extra=()):
    """Push what you share to the relays now. Returns a short report the screen can show."""
    with _sync_lock:
        with LOCK:
            s = load()
            evs, has_public = share_events(s)
            sent_unshare = set(s.get('unshare', []))
        evs = list(extra) + evs
        if not evs:
            rep = {'at': now(), 'stored': 0, 'relays': len(RELAYS), 'reached': 0, 'note': 'Nothing is shared yet.'}
        else:
            got = relay_publish(evs)
            best = max(got.values()) if got else 0
            worst = min(got.values()) if got else 0
            rep = {'at': now(), 'stored': len(evs), 'relays': len(RELAYS), 'reached': worst, 'best': best}
        with LOCK:
            s = load()
            s['sync'] = rep
            if rep.get('reached', 0) or not evs:
                s['shared_at'] = rep['at']
                s['public_live'] = has_public
                # Clear only the removals this round actually sent; one made meanwhile goes out next round.
                s['unshare'] = [x for x in s.get('unshare', []) if x not in sent_unshare]
            save(s)
        return rep


def sync_soon():
    threading.Thread(target=lambda: _quiet(sync), daemon=True).start()


def _quiet(fn, *a):
    try:
        return fn(*a)
    except Exception:  # noqa: BLE001 - background work reports through state, never crashes the app
        return None


def check_requests():
    """Gift-wrapped friend requests sent to your Nostr ID since the last look."""
    with LOCK:
        since = int(load().get('requests_since') or 0)
    evs, reached = relay_query([{'kinds': [1059], '#p': [box_key()[1]], 'since': max(0, since - 3 * 86400), 'limit': 200}])
    found = []
    for w in evs:
        r = _quiet(unwrap, w)
        if not r:
            continue
        try:
            body = json.loads(r['content'])
        except (ValueError, TypeError):
            continue
        found.append((r['pubkey'], body if isinstance(body, dict) else {}, int(r.get('created_at') or 0)))
    with LOCK:
        s = load()
        mine, friends = box_key()[1], {f['pubkey'] for f in s['friends']}
        known = {r['pubkey'] for r in s['requests']}
        for pk, body, at in sorted(found, key=lambda x: x[2]):
            if pk == mine or pk in friends or pk in known or pk in set(s.get('ignored', [])):
                continue
            s['requests'] = s['requests'][-19:] + [{'pubkey': pk, 'npub': npub_encode(pk), 'name': str(body.get('name') or '')[:60] or npub_encode(pk)[:12] + '…',
                                                   'picture': body.get('picture') if valid_picture(body.get('picture')) else '', 'at': now()}]
            known.add(pk)
            log(s, f"{s['requests'][-1]['name']} added you as a friend")
        if reached:
            s['requests_since'] = int(time.time())
        s['requests_checked'] = now()
        save(s)
    return me()


def background():
    n = 0
    while True:
        _quiet(check_requests)
        if n % 6 == 0:                       # every half hour: keep your shared copies on the relays
            with LOCK:
                s = load()
            if s['friends'] or s.get('public_live'):
                _quiet(sync)
        n += 1
        time.sleep(300)


# ---------- friends: just a Nostr ID ----------

def add_friend(body):
    if not isinstance(body, dict):
        raise Problem(400, 'Expected an object.')
    m = re.search(r'npub1[02-9ac-hj-np-z]{20,}', str(body.get('npub') or body.get('code') or '').lower())
    if not m:
        raise Problem(400, 'Paste their Nostr ID. It starts with npub1.')
    pk = npub_decode(m.group(0))
    if pk == box_key()[1]:
        raise Problem(400, 'That is your own Nostr ID.')
    with LOCK:
        s = load()
        f = next((f for f in s['friends'] if f['pubkey'] == pk), None)
        req = next((r for r in s['requests'] if r['pubkey'] == pk), {})
        if not f:
            f = {'id': secrets.token_hex(4), 'pubkey': pk, 'npub': npub_encode(pk), 'added_at': now()}
            s['friends'].append(f)
        f['name'] = _text(body.get('name'), 'name', 60) or req.get('name') or f.get('name') or f['npub'][:12] + '…'
        f['picture'] = req.get('picture') or f.get('picture', '')
        s['requests'] = [r for r in s['requests'] if r['pubkey'] != pk]
        s['unshare'] = [x for x in s.get('unshare', []) if x != pk]
        log(s, f"Added {f['name']}")
        save(s)
        hello = {'name': s['name'] or 'A Wizard friend', 'picture': s['picture'] if len(s['picture']) < 40000 else ''}
    rep = sync([gift_wrap(pk, json.dumps(hello))])
    return {'friend': f, 'sent': rep.get('reached', 0) > 0, 'me': me()}


def remove_friend(fid):
    with LOCK:
        s = load()
        gone = next((f for f in s['friends'] if f['id'] == fid), None)
        if not gone:
            raise Problem(404, 'No friend with that id.')
        s['friends'] = [f for f in s['friends'] if f['id'] != fid]
        s['unshare'] = sorted(set(s.get('unshare', [])) | {gone['pubkey']})
        log(s, f"Removed {gone.get('name') or gone['npub']}")
        save(s)
    sync_soon()
    return me()


def dismiss_request(npub):
    pk = npub_decode(npub)
    with LOCK:
        s = load()
        s['requests'] = [r for r in s['requests'] if r['pubkey'] != pk]
        s['ignored'] = sorted(set(s.get('ignored', [])) | {pk})[-200:]
        save(s)
    return me()


PICTURE = re.compile(r'^data:image/(?:jpeg|png|webp);base64,[A-Za-z0-9+/=]{100,60000}$')


def valid_picture(v):
    return isinstance(v, str) and bool(PICTURE.fullmatch(v))


def clean_remote(p, f, viewer):
    """A friend's profile, re-checked here: nobody can make a private app look public or send unsafe CSS."""
    out = {'friend': {k: f.get(k) for k in ('id', 'name', 'npub')}, 'viewer': viewer,
           'npub': f.get('npub'), 'name': str(p.get('name') or f.get('name') or '')[:60], 'bio': str(p.get('bio') or '')[:400],
           'picture': p.get('picture') if valid_picture(p.get('picture')) else '',
           'messenger': p.get('messenger') if re.fullmatch(r'npub1[02-9ac-hj-np-z]{58}', str(p.get('messenger') or '')) else '',
           'updated_at': str(p.get('updated_at') or p.get('published_at') or '')[:20], 'build': None, 'skin': None, 'apps': None, 'signed': True}
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
                                 'type': a['type'] if a.get('type') in APP_TYPES else app_type(rec),
                                 'system': a.get('system') is True, 'uses': a.get('uses') is True})
        out['apps'] = apps
    return out


def friend_profile(fid):
    f = next((f for f in load()['friends'] if f['id'] == fid), None)
    if not f:
        raise Problem(404, 'No friend with that id.')
    tag = pair_tag(f['pubkey'])
    evs, reached = relay_query([{'kinds': [PROFILE_KIND], 'authors': [f['pubkey']], '#d': [tag, 'wizard-profile'], 'limit': 10}])
    if not reached:
        raise Problem(502, 'Could not reach any Nostr relay. Check the internet connection of your Wizard.')
    latest = {}
    for ev in evs:                                    # relay_query already checked every signature
        d = next((t[1] for t in ev.get('tags', []) if len(t) >= 2 and t[0] == 'd'), '')
        if ev.get('pubkey') == f['pubkey'] and (d not in latest or ev['created_at'] > latest[d]['created_at']):
            latest[d] = ev
    p, viewer = None, 'none'
    if latest.get(tag, {}).get('content'):
        try:
            p, viewer = json.loads(nip44_decrypt(conversation_key(box_key()[0], f['pubkey']), latest[tag]['content'])), 'friend'
        except (ValueError, TypeError):
            p = None
        if isinstance(p, dict) and p.get('removed'):   # they removed you: only their public parts remain
            p, viewer = None, 'none'
    if p is None and latest.get('wizard-profile'):
        try:
            p, viewer = json.loads(latest['wizard-profile']['content']), 'visitor'
        except (ValueError, TypeError):
            p = None
    out = clean_remote(p if isinstance(p, dict) else {}, f, viewer)
    with LOCK:
        s = load()
        for x in s['friends']:
            if x['id'] == fid:
                x['name'] = out['name'] or x['name']
                x['picture'] = out['picture'] or x.get('picture', '')
        save(s)
    return out


def me():
    s = load()
    return {**{k: s[k] for k in ('name', 'bio', 'picture', 'messenger', 'visibility', 'hidden', 'uses', 'snapshot', 'friends', 'requests', 'wearing')},
            'npub': box_npub(), 'look_saved': bool(s.get('look_backup')), 'sync': s.get('sync'), 'shared_at': s.get('shared_at'),
            'requests_checked': s.get('requests_checked'), 'relays': RELAYS, 'backed_up_at': s.get('backed_up_at'),
            'activity': list(reversed(s['activity'][-20:])), 'shell_repo': SHELL_REPO}


def update_me(body):
    if not isinstance(body, dict):
        raise Problem(400, 'Expected an object.')
    unknown = set(body) - {'name', 'bio', 'picture', 'messenger', 'visibility', 'hidden', 'uses'}
    if unknown:
        raise Problem(400, 'Unknown field: ' + ', '.join(sorted(unknown)) + '.')
    with LOCK:
        s = load()
        before = json.dumps(view_for('friend', s), sort_keys=True) + json.dumps(view_for('visitor', s), sort_keys=True)
        if 'name' in body:
            s['name'] = _text(body['name'], 'name', 60)
        if 'bio' in body:
            s['bio'] = _text(body['bio'], 'bio', 280)
        if 'picture' in body:
            if body['picture'] not in ('', None) and not valid_picture(body['picture']):
                raise Problem(400, 'The photo must be a small JPEG, PNG or WebP.')
            s['picture'] = body['picture'] or ''
        if 'messenger' in body:
            m = str(body['messenger'] or '').strip()
            if m:
                npub_decode(m)
            s['messenger'] = m
        if 'visibility' in body:
            v = body['visibility']
            if not isinstance(v, dict) or not v or any(k not in PARTS or v[k] not in LEVELS for k in v):
                raise Problem(400, 'visibility maps card, build, skin or apps to private, friends or public.')
            if v.get('build') == 'public':
                # Trying on a build runs its code on your data, so it is only ever for people you added.
                raise Problem(400, 'A build can be shared with friends, never with everyone.')
            if v.get('card') == 'private':
                raise Problem(400, 'Friends always see your name and photo.')
            for k, level in v.items():
                if s['visibility'].get(k) != level:
                    log(s, f"{ {'card': 'Name and photo', 'build': 'Build', 'skin': 'Look', 'apps': 'Apps'}[k] }: {LEVEL_NAMES[level]}")
                s['visibility'][k] = level
        for key in ('hidden', 'uses'):
            if key in body:
                v = body[key]
                if not isinstance(v, list) or len(v) > 200 or not all(isinstance(x, str) and APP.fullmatch(x) for x in v):
                    raise Problem(400, f'{key} must be a list of app ids.')
                s[key] = sorted(set(v))
        changed = before != json.dumps(view_for('friend', s), sort_keys=True) + json.dumps(view_for('visitor', s), sort_keys=True)
        save(s)
    if changed:
        sync_soon()
    return me()


# ---------- MCP (same service layer as the view) ----------

TOOLS = [
    {'name': 'profile_get', 'description': "The owner's Wizard profile and Nostr ID (npub): who sees the build, look and apps (private, friends, public), the published snapshot, friends and pending friend requests.",
     'inputSchema': {'type': 'object', 'properties': {}, 'additionalProperties': False}, 'annotations': {'readOnlyHint': True}},
    {'name': 'profile_preview', 'description': "Exactly what a friend, or anyone else, sees of the owner's profile right now.",
     'inputSchema': {'type': 'object', 'properties': {'as': {'type': 'string', 'enum': ['friend', 'public']}}, 'required': ['as'], 'additionalProperties': False},
     'annotations': {'readOnlyHint': True}},
    {'name': 'profile_set_visibility', 'description': 'Set who sees one part of the profile: build, skin or apps -> private, friends or public. Only when the owner asked.',
     'inputSchema': {'type': 'object', 'properties': {'part': {'type': 'string', 'enum': list(SECTIONS)}, 'level': {'type': 'string', 'enum': list(LEVELS)}},
                     'required': ['part', 'level'], 'additionalProperties': False}},
    {'name': 'friends_list', 'description': 'Friends (by Nostr ID; their Wizard reaches this one over a private connection) and pending friend requests.',
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


class Handler(BaseHTTPRequestHandler):
    def refused(self, path, write=False):
        host = (self.headers.get('Host') or '').lower()
        if host not in TRUSTED_HOSTS:
            self.send(403, {'error': 'Unknown host.'})
            return True
        if path != '/healthz' and not is_owner(self.headers):
            self.send(403, {'error': 'Only the owner of this Wizard can open Profiles.'})
            return True
        if write:
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
        self.send_header('Content-Security-Policy', "default-src 'self'; img-src 'self' data: blob:; style-src 'self'; style-src-attr 'unsafe-inline'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'")
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(b)

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
            if path == '/api/me':
                return self.send(200, me())
            if path == '/api/preview':
                return self.send(200, view_for('friend' if q.get('as', [''])[0] == 'friend' else 'visitor'))
            if path == '/api/icons':
                return self.send(200, app_icons(q.get('repo', [])))
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
            if path == '/mcp':
                out = rpc(body)
                return self.send(202 if out is None else 200, out)
            if path == '/api/publish':
                return self.send(200, publish(body))
            if path == '/api/friends':
                return self.send(201, add_friend(body))
            if path == '/api/sync':
                sync()
                return self.send(200, me())
            if path == '/api/requests/check':
                return self.send(200, check_requests())
            if path == '/api/look/backup':
                return self.send(200, save_look_backup(body))
            if path == '/api/look/restore':
                return self.send(200, take_look_backup())
            if path == '/api/identity/backup':
                return self.send(200, backup_identity(body))
            if path == '/api/identity/confirm':
                return self.send(200, confirm_backup())
            if path == '/api/identity/restore':
                return self.send(200, restore_identity(body))
            if path == '/api/requests/dismiss':
                return self.send(200, dismiss_request(str((body or {}).get('npub') or '')))
            self.send(404, {'error': 'Not found.'})
        except Problem as e:
            self.send(e.code, {'error': e.message})
        except (ValueError, TypeError, AttributeError):
            self.send(400, {'error': 'Invalid JSON request.'})

    def do_PUT(self):
        path = urlsplit(self.path).path
        if self.refused(path, write=True):
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
        if self.refused(path, write=True):
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


def app_icons(repos):
    """App Store icons for the apps on screen (the logo each listing publishes)."""
    out = {}
    for r in repos[:200]:
        if REPO.fullmatch(r):
            rec = _quiet(store_listing, r)
            logo = str((rec or {}).get('logo') or '')
            if logo.startswith('https://raw.githubusercontent.com/'):
                out[r] = logo
    return out


if __name__ == '__main__':
    DATA.mkdir(parents=True, exist_ok=True)
    if os.environ.get('PROFILES_OFFLINE') != '1':
        threading.Thread(target=background, daemon=True).start()
    ThreadingHTTPServer((os.environ.get('BIND', '0.0.0.0'), int(_PORT)), Handler).serve_forever()

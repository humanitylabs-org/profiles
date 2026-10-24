"""Pure Wizard identity resolution, independent of transport, storage and crypto.

Inputs MUST be signature-verified Nostr events. `now` is an explicit Unix time.
Callers retain the newest signed list (including expired lists) to prevent rollback.
No owner key or server/platform dependency belongs in this module.
"""
import json
import re

DEVICE_KIND = 30078
DEVICE_D = 'wizard-devices'
ROLES = frozenset(('inbox', 'profile', 'messenger', 'agent'))
HEX = re.compile(r'^[0-9a-f]{64}$')


def tags(event, name):
    return [t[1:] for t in event.get('tags', []) if isinstance(t, list) and len(t) >= 2 and t[0] == name]


def newest(events):
    # NIP-01: smaller event id wins equal timestamps.
    return min(events, key=lambda e: (-e['created_at'], e['id']), default=None)


def device_list(owner, events, now):
    ev = newest([e for e in events if e.get('pubkey') == owner and e.get('kind') == DEVICE_KIND
                 and tags(e, 'd') == [[DEVICE_D]] and isinstance(e.get('created_at'), int) and e['created_at'] <= now])
    if not ev:
        return None
    expiry = tags(ev, 'expiration')
    try:
        expires = int(expiry[0][0]) if len(expiry) == 1 else 0
    except (ValueError, TypeError, IndexError):
        expires = 0
    revoked = {}
    for t in tags(ev, 'revoked'):
        if len(t) != 2 or not HEX.fullmatch(str(t[0])):
            continue
        try:
            at = int(t[1])
            if at >= 0:
                revoked[t[0]] = min(at, revoked.get(t[0], at))
        except (ValueError, TypeError):
            continue
    devices = {}
    for t in tags(ev, 'p'):
        if len(t) >= 3 and HEX.fullmatch(str(t[0])):
            roles = set(t[2:]) & ROLES
            if t[0] != owner and roles:
                devices.setdefault(t[0], set()).update(roles)
    return {'owner': owner, 'event': ev, 'current': ev['created_at'] <= now < expires,
            'expires': expires, 'devices': devices, 'revoked': revoked}


def allowed_device(listing, device, role, now, event_at=None):
    if not listing or not listing['current'] or role not in listing['devices'].get(device, set()):
        return False
    cutoff = listing['revoked'].get(device)
    return cutoff is None or (event_at is not None and event_at < cutoff and event_at <= now)


def metadata(pubkey, events):
    ev = newest([e for e in events if e.get('pubkey') == pubkey and e.get('kind') == 0])
    try:
        data = json.loads(ev['content']) if ev else {}
    except (ValueError, TypeError):
        data = {}
    return ev, data if isinstance(data, dict) else {}


def resolve(pubkey, events, now):
    """Return person/inbox/display identity. A revoked/expired claim fails closed.

    A current owner list establishes a person even when it has no inbox. Never
    encrypt to the owner's phone as an implicit replacement for a missing device.
    """
    own = device_list(pubkey, events, now)
    meta, data = metadata(pubkey, events)
    listing, person = own, pubkey
    claimed = bool(own)
    if not own and meta:
        for t in tags(meta, 'p'):
            owner = t[0]
            candidate = device_list(owner, events, now)
            if candidate and (pubkey in candidate['devices'] or pubkey in candidate['revoked']):
                listing, person, claimed = candidate, owner, True
                break
    if listing:
        _, owner_data = metadata(person, events)
        inboxes = [pk for pk in listing['devices'] if allowed_device(listing, pk, 'inbox', now)]
        profiles = [pk for pk in listing['devices'] if allowed_device(listing, pk, 'profile', now)]
        return {'person': person, 'inbox': inboxes[0] if inboxes else None, 'profiles': profiles,
                'claimed': claimed, 'current': listing['current'], 'listing': listing,
                'name': owner_data.get('name') or owner_data.get('display_name') or person[:12]}
    name = str(data.get('name') or data.get('display_name') or pubkey[:12])
    if name.endswith("'s Wizard"):
        name = name[:-9]
    return {'person': pubkey, 'inbox': pubkey, 'profiles': [pubkey], 'claimed': False,
            'current': False, 'listing': None, 'name': name + "'s Wizard (unclaimed)"}


def profile_trusted(event, identity, now):
    pk = event.get('pubkey')
    if identity['claimed']:
        return ([identity['person']] in tags(event, 'p')
                and allowed_device(identity['listing'], pk, 'profile', now, event.get('created_at')))
    return pk == identity['person'] and not tags(event, 'p')

"""Offline two-key protocol/interop regressions. All keys and relay state are disposable.
Run: python3 -m unittest discover -s tests -p 'test_*.py' -v
"""
import copy
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

os.environ['PROFILES_OFFLINE'] = '1'
os.environ['PROFILES_RELAYS'] = ''
from app import server as s
from app import identity_resolve as identity

NOW = int(time.time())
OWNER = (101).to_bytes(32, 'big')
BOX = (102).to_bytes(32, 'big')
FRIEND = (103).to_bytes(32, 'big')
OTHER_OWNER = (104).to_bytes(32, 'big')
OTHER_BOX = (105).to_bytes(32, 'big')
PK = {k: s.pub_of(k) for k in (OWNER, BOX, FRIEND, OTHER_OWNER, OTHER_BOX)}


def signed(event, key):
    ev = copy.deepcopy(event)
    ev['pubkey'] = PK.get(key) or s.pub_of(key)
    ev['id'] = s.event_id(ev)
    ev['sig'] = s.schnorr_sign(bytes.fromhex(ev['id']), key).hex()
    return ev


def listing(owner=OWNER, box=BOX, at=NOW-10, expires=NOW+86400, roles=('inbox', 'profile'), extra=()):
    tags = [['d', 'wizard-devices'], ['expiration', str(expires)]]
    if box:
        tags += [['p', PK[box], 'wss://example.invalid', *roles]]
    return s.sign_event(30078, '', tags + list(extra), sk=owner, created_at=at)


def meta(box=BOX, owner=OWNER, name="James's Wizard"):
    return s.sign_event(0, json.dumps({'name': name}), [['p', PK[owner]]] if owner else [], sk=box, created_at=NOW-5)


class FakeRelay:
    """Real signed events, same Nostr filter semantics, no network/socket usage."""
    def __init__(self):
        self.events = []
        self.published = []
        self.online = True

    def publish(self, events):
        self.published += copy.deepcopy(events)
        if self.online:
            for e in events:
                assert s.verify_event(e), 'Only valid signed events may enter relay'
                if not any(x['id'] == e['id'] for x in self.events):
                    self.events.append(copy.deepcopy(e))
        return {e['id']: int(self.online) for e in events}

    def query(self, filters):
        out = {}
        for f in filters:
            found = []
            for e in self.events:
                if any(key in f and e[field] not in f[key] for key, field in [('authors', 'pubkey'), ('kinds', 'kind'), ('ids', 'id')]):
                    continue
                if e['created_at'] < f.get('since', 0):
                    continue
                if any(not any(t[0] == key[1:] and len(t) > 1 and t[1] in values for t in e['tags']) for key, values in f.items() if key.startswith('#')):
                    continue
                found.append(e)
            found.sort(key=lambda e: (-e['created_at'], e['id']))
            out.update({e['id']: copy.deepcopy(e) for e in found[:f.get('limit', 1000)]})
        return list(out.values()), int(self.online)


class ResolutionTests(unittest.TestCase):
    def test_owner_to_inbox(self):
        r = identity.resolve(PK[OWNER], [listing()], NOW)
        self.assertEqual((r['person'], r['inbox'], r['claimed']), (PK[OWNER], PK[BOX], True))

    def test_box_to_person_requires_both_sides(self):
        evs = [listing(), meta(), s.sign_event(0, '{"name":"James"}', [], sk=OWNER, created_at=NOW-5)]
        r = identity.resolve(PK[BOX], evs, NOW)
        self.assertEqual((r['person'], r['inbox'], r['name']), (PK[OWNER], PK[BOX], 'James'))
        self.assertFalse(identity.resolve(PK[BOX], [meta()], NOW)['claimed'])
        self.assertFalse(identity.resolve(PK[BOX], [listing()], NOW)['claimed'])

    def test_unclaimed_label_never_person(self):
        r = identity.resolve(PK[FRIEND], [meta(FRIEND, None, 'Miguel')], NOW)
        self.assertEqual(r['name'], "Miguel's Wizard (unclaimed)")
        self.assertEqual(r['inbox'], PK[FRIEND])
        self.assertFalse(r['claimed'])

    def test_expired_latest_does_not_revive_older_list(self):
        old = listing(at=NOW-100)
        expired = listing(at=NOW-50, expires=NOW-1)
        r = identity.resolve(PK[OWNER], [old, expired], NOW)
        self.assertIsNone(r['inbox'])
        self.assertFalse(r['current'])

    def test_roles_are_separate(self):
        ev = listing(roles=('profile',))
        r = identity.resolve(PK[OWNER], [ev], NOW)
        self.assertIsNone(r['inbox'])
        self.assertEqual(r['profiles'], [PK[BOX]])

    def test_revocation_after_cutoff_ignored(self):
        ev = listing(extra=[['revoked', PK[BOX], str(NOW-2)]])
        r = identity.resolve(PK[OWNER], [ev], NOW)
        self.assertIsNone(r['inbox'])
        self.assertTrue(identity.allowed_device(r['listing'], PK[BOX], 'profile', NOW, NOW-3))
        self.assertFalse(identity.allowed_device(r['listing'], PK[BOX], 'profile', NOW, NOW-2))
        self.assertFalse(identity.allowed_device(r['listing'], PK[BOX], 'profile', NOW, NOW))

    def test_removed_revoked_device_keeps_person_and_no_inbox(self):
        ev = listing(box=None, extra=[['revoked', PK[BOX], str(NOW-2)]])
        r = identity.resolve(PK[BOX], [ev, meta()], NOW)
        self.assertEqual(r['person'], PK[OWNER])
        self.assertIsNone(r['inbox'])

    def test_future_list_and_equal_time_tie(self):
        a = listing(at=NOW-5)
        b = listing(at=NOW-5, box=OTHER_BOX)
        r = identity.resolve(PK[OWNER], [a, b, listing(at=NOW+100)], NOW)
        self.assertEqual(r['listing']['event']['id'], min(a['id'], b['id']))

    def test_profile_needs_owner_tag_and_profile_role(self):
        r = identity.resolve(PK[OWNER], [listing()], NOW)
        ev = s.sign_event(30078, '{}', [['d', 'wizard-profile'], ['p', PK[OWNER]]], sk=BOX, created_at=NOW)
        self.assertTrue(identity.profile_trusted(ev, r, NOW))
        ev['tags'].pop()
        self.assertFalse(identity.profile_trusted(ev, r, NOW))
        ev['tags'].append(['p', PK[OWNER]])
        self.assertFalse(identity.profile_trusted(ev, identity.resolve(PK[OWNER], [listing(roles=('inbox',))], NOW), NOW))


class ProtocolTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='profiles-test-')
        self.relay = FakeRelay()
        self.patches = [patch.object(s, 'DATA', Path(self.tmp.name)), patch.object(s, '_KEY', (BOX, PK[BOX])),
                        patch.object(s.time, 'time', return_value=NOW), patch.object(s, '_last_ts', [NOW-1]),
                        patch.object(s, 'relay_query', self.relay.query), patch.object(s, 'relay_publish', self.relay.publish),
                        patch.object(s, 'sync_soon', lambda: None)]
        for p in self.patches:
            p.start()
        self.addCleanup(self.tmp.cleanup)
        for p in reversed(self.patches):
            self.addCleanup(p.stop)
        state = s.load(); state['name'] = 'James'; s.save(state)

    def claim(self):
        prepared = s.claim_prepare({'npub': s.npub_encode(PK[OWNER])})
        s.claim_commit({'token': prepared['token'], 'event': signed(prepared['event'], OWNER)})

    def friend_flow(self, pk=PK[FRIEND]):
        p = s.friend_prepare({'npub': s.npub_encode(pk)})
        cipher = s.nip44_encrypt(s.conversation_key(OWNER, p['recipient']), json.dumps(p['rumor']))
        ev = s.friend_seal({'token': p['token'], 'ciphertext': cipher})['event']
        return p, signed(ev, OWNER)

    def test_claim_phone_signed_box_metadata_and_persistence(self):
        self.claim()
        self.assertEqual(s.me()['npub'], s.npub_encode(PK[OWNER]))
        self.assertEqual(s.me()['box_npub'], s.npub_encode(PK[BOX]))
        s.sync()
        ev = next(e for e in self.relay.published if e['kind'] == 0)
        self.assertEqual(json.loads(ev['content'])['name'], "James's Wizard")
        self.assertIn(['p', PK[OWNER]], ev['tags'])
        self.assertEqual(ev['pubkey'], PK[BOX])
        self.assertNotIn(OWNER.hex(), (s.DATA / 'profile.json').read_text())
        self.assertEqual(s.load()['owner'], PK[OWNER])

    def test_claim_rejects_other_signer_and_mutated_event(self):
        p = s.claim_prepare({'npub': s.npub_encode(PK[OWNER])})
        for key in (BOX, FRIEND):
            with self.assertRaises(s.Problem):
                s.claim_commit({'token': p['token'], 'event': signed(p['event'], key)})
        ev = copy.deepcopy(p['event']); ev['tags'].append(['p', PK[FRIEND], '', 'inbox'])
        with self.assertRaises(s.Problem):
            s.claim_commit({'token': p['token'], 'event': signed(ev, OWNER)})
        self.assertFalse(s.load()['owner'])
        self.assertFalse(self.relay.published)

    def test_claim_expiry_replay_and_no_reassignment(self):
        p = s.claim_prepare({'npub': s.npub_encode(PK[OWNER])})
        ev = signed(p['event'], OWNER)
        state = s.load(); state['pending_actions'][p['token']]['expires'] = 1; s.save(state)
        with self.assertRaises(s.Problem): s.claim_commit({'token': p['token'], 'event': ev})
        self.claim()
        with self.assertRaises(s.Problem): s.claim_commit({'token': p['token'], 'event': ev})
        with self.assertRaises(s.Problem): s.claim_prepare({'npub': s.npub_encode(PK[OTHER_OWNER])})

    def test_claim_preserves_other_devices_and_roles(self):
        self.relay.publish([listing(box=OTHER_BOX, roles=('agent', 'profile'))])
        self.claim()
        ev = self.relay.published[-1]
        self.assertIn(['p', PK[OTHER_BOX], 'wss://example.invalid', 'agent', 'profile'], ev['tags'])

    def test_claim_no_relay_no_commit(self):
        p = s.claim_prepare({'npub': s.npub_encode(PK[OWNER])})
        self.relay.online = False
        with self.assertRaises(s.Problem): s.claim_commit({'token': p['token'], 'event': signed(p['event'], OWNER)})
        self.assertFalse(s.load()['owner'])

    def test_owner_signed_seal_to_legacy_inbox(self):
        self.claim()
        p, ev = self.friend_flow()
        out = s.friend_commit({'token': p['token'], 'event': ev})
        self.assertTrue(out['sent'])
        wrap = next(e for e in self.relay.published if e['kind'] == 1059)
        self.assertEqual(identity.tags(wrap, 'p'), [[PK[FRIEND]]])
        self.assertNotIn(wrap['pubkey'], (PK[OWNER], PK[BOX]))
        seal = json.loads(s.nip44_decrypt(s.conversation_key(FRIEND, wrap['pubkey']), wrap['content']))
        self.assertEqual(seal['pubkey'], PK[OWNER]); self.assertTrue(s.verify_event(seal))
        rumor = json.loads(s.nip44_decrypt(s.conversation_key(FRIEND, PK[OWNER]), seal['content']))
        self.assertEqual(rumor['pubkey'], PK[OWNER])
        self.assertEqual(rumor['id'], s.event_id(rumor))
        with self.assertRaises(s.Problem): s.friend_commit({'token': p['token'], 'event': ev})
        with self.assertRaises(s.Problem): s.add_friend({'npub': s.npub_encode(PK[FRIEND])})

    def test_friend_seal_tamper_wrong_owner_and_revoked_recipient(self):
        self.claim()
        self.relay.publish([listing(OTHER_OWNER, OTHER_BOX)])
        p, ev = self.friend_flow(PK[OTHER_OWNER])
        for bad in (signed(ev, BOX), signed({**ev, 'content': ev['content'][:-4] + 'AAAA'}, OWNER)):
            with self.assertRaises(s.Problem): s.friend_commit({'token': p['token'], 'event': bad})
        self.relay.publish([listing(OTHER_OWNER, None, at=NOW, extra=[['revoked', PK[OTHER_BOX], str(NOW)]])])
        with self.assertRaises(s.Problem): s.friend_commit({'token': p['token'], 'event': ev})
        self.assertFalse(s.load()['friends'])

    def test_revoked_local_device_cannot_send_or_share(self):
        self.claim()
        self.relay.publish([listing(OWNER, None, at=int(time.time())+1, extra=[['revoked', PK[BOX], str(NOW)]])])
        # Advance protocol clock explicitly; no sleep and no future-list acceptance.
        with patch.object(s.time, 'time', return_value=NOW+10):
            with self.assertRaises(s.Problem): s.friend_prepare({'npub': s.npub_encode(PK[FRIEND])})
            self.assertEqual(s.share_events(s.load())[0], [])

    def test_legacy_box_seal_is_received_by_claimed_inbox(self):
        self.claim()
        with patch.object(s, '_KEY', (FRIEND, PK[FRIEND])):
            wrap = s.gift_wrap(PK[BOX], '{"name":"Miguel"}')
        self.relay.publish([wrap]); s.check_requests()
        r = s.load()['requests'][0]
        self.assertEqual(r['pubkey'], PK[FRIEND])
        self.assertEqual(r['name'], "Miguel's Wizard (unclaimed)")
        self.assertFalse(r['claimed'])

    def test_owner_seal_received_and_paired_by_person(self):
        self.relay.publish([listing(OTHER_OWNER, OTHER_BOX)])
        with patch.object(s, '_KEY', (OTHER_OWNER, PK[OTHER_OWNER])):
            wrap = s.gift_wrap(PK[BOX], '{"name":"Other person"}')
        self.relay.publish([wrap]); s.check_requests()
        self.assertEqual(s.load()['requests'][0]['pubkey'], PK[OTHER_OWNER])
        self.assertEqual(s.load()['requests'][0]['inbox'], PK[OTHER_BOX])

    def test_claim_rekeys_friend_and_request_without_readding(self):
        out = s.add_friend({'npub': s.npub_encode(PK[FRIEND]), 'name': 'Miguel'})
        old_id = out['friend']['id']
        self.relay.publish([listing(OTHER_OWNER, FRIEND), meta(FRIEND, OTHER_OWNER, "Miguel's Wizard"),
                            s.sign_event(0, '{"name":"Miguel"}', [], sk=OTHER_OWNER, created_at=NOW)])
        s.rekey_friends()
        f = s.load()['friends'][0]
        self.assertEqual(f['id'], old_id)
        self.assertEqual(f['pubkey'], PK[OTHER_OWNER]); self.assertEqual(f['inbox'], PK[FRIEND])
        self.assertEqual(f['name'], 'Miguel')
        self.assertIn(PK[FRIEND], f['aliases'])

    def test_device_revoke_stops_sharing_to_old_key(self):
        self.relay.publish([listing(OTHER_OWNER, OTHER_BOX)])
        s.add_friend({'npub': s.npub_encode(PK[OTHER_OWNER])})
        self.relay.publish([listing(OTHER_OWNER, None, at=NOW, extra=[['revoked', PK[OTHER_BOX], str(NOW)]])])
        events, _ = s.share_events(s.load())
        self.assertFalse(any(e['kind'] == 30078 for e in events))
        self.assertIsNone(s.resolve_key(PK[OTHER_OWNER])['inbox'])

    def test_invalid_and_tampered_giftwrap_rejected(self):
        with patch.object(s, '_KEY', (FRIEND, PK[FRIEND])):
            w = s.gift_wrap(PK[BOX], '{"name":"Miguel"}')
        w['content'] += 'a'
        self.assertIsNone(s.unwrap(w))
        self.assertIsNone(s.validate_rumor({}, {}))
        seal = s.sign_event(13, 'dummy', [], sk=FRIEND)
        self.assertIsNone(s.validate_rumor(seal, {'pubkey': PK[FRIEND], 'kind': 1078}))

    def test_owner_addressed_request_queue_and_phone_open(self):
        self.claim()
        with patch.object(s, '_KEY', (FRIEND, PK[FRIEND])):
            w = s.gift_wrap(PK[OWNER], '{"name":"Miguel"}')
        self.relay.publish([w]); s.check_requests(); s.check_requests()
        self.assertEqual(s.me()['sealed_requests'], 1)
        self.assertFalse(s.load()['requests'])
        seal = json.loads(s.nip44_decrypt(s.conversation_key(OWNER, w['pubkey']), w['content']))
        rumor = json.loads(s.nip44_decrypt(s.conversation_key(OWNER, seal['pubkey']), seal['content']))
        s.open_request({'id': w['id'], 'seal': seal, 'rumor': rumor})
        self.assertEqual(s.me()['sealed_requests'], 0)
        self.assertEqual(s.load()['requests'][0]['pubkey'], PK[FRIEND])
        s.check_requests(); self.assertEqual(s.me()['sealed_requests'], 0)

    def test_auto_share_box_signed_to_resolved_inbox_with_owner_tag(self):
        self.claim(); self.relay.publish([listing(OTHER_OWNER, OTHER_BOX)])
        p, ev = self.friend_flow(PK[OTHER_OWNER])
        s.friend_commit({'token': p['token'], 'event': ev})
        event = next(e for e in reversed(self.relay.published) if e['kind'] == 30078 and identity.tags(e, 'd') != [['wizard-devices']])
        self.assertEqual(event['pubkey'], PK[BOX]); self.assertIn(['p', PK[OWNER]], event['tags'])
        p = json.loads(s.nip44_decrypt(s.conversation_key(OTHER_BOX, PK[BOX]), event['content']))
        self.assertEqual(p['npub'], s.npub_encode(PK[OWNER]))

    def test_known_expiration_cached_no_provisional_fallback(self):
        self.relay.publish([listing(OTHER_OWNER, OTHER_BOX, expires=NOW+1)])
        self.assertEqual(s.resolve_key(PK[OTHER_OWNER])['inbox'], PK[OTHER_BOX])
        self.relay.events = []
        with patch.object(s.time, 'time', return_value=NOW+10):
            self.assertIsNone(s.resolve_key(PK[OTHER_OWNER])['inbox'])

    def test_owner_secret_never_in_backup_restore_is_device_only(self):
        self.claim()
        out = s.backup_identity({'format': 'nsec'})
        self.assertEqual(s.b32_decode('nsec', out['backup']), BOX)
        self.assertNotEqual(s.b32_decode('nsec', out['backup']), OWNER)
        with self.assertRaises(s.Problem): s.restore_identity({'backup': s.b32_encode('nsec', FRIEND)})

    def test_unsupported_event_shapes_and_invalid_list_signature_fail_closed(self):
        valid = listing(OTHER_OWNER, OTHER_BOX)
        invalid = {**valid, 'content': 'changed after signing'}
        self.relay.events.append(invalid)
        self.assertFalse(s.resolve_key(PK[OTHER_OWNER])['claimed'])
        for update in ({'created_at': True}, {'kind': '13'}, {'tags': [['p', {}]]}, {'pubkey': None}, {'content': []}):
            self.assertFalse(s.verify_event({**valid, **update}))

    def test_revoked_device_seal_before_cutoff_accepted_after_cutoff_ignored(self):
        self.relay.publish([listing(OTHER_OWNER, OTHER_BOX, extra=[['revoked', PK[OTHER_BOX], str(NOW-2)]]), meta(OTHER_BOX, OTHER_OWNER)])
        for at, expected in ((NOW-3, True), (NOW-2, False), (NOW, False)):
            rumor = s.sign_event(1078, '{"name":"Friend"}', [], sk=OTHER_BOX, created_at=at)
            rumor.pop('sig')
            seal = s.sign_event(13, s.nip44_encrypt(s.conversation_key(OTHER_BOX, PK[BOX]), json.dumps(rumor)), [], sk=OTHER_BOX, created_at=NOW-10)
            self.assertEqual(s.validate_rumor(seal, rumor) is not None, expected)

    def test_profile_post_revocation_ignored_pre_cutoff_history_readable(self):
        self.relay.publish([listing(OTHER_OWNER, OTHER_BOX)])
        f = s.add_friend({'npub': s.npub_encode(PK[OTHER_OWNER])})['friend']
        self.relay.publish([listing(OTHER_OWNER, OTHER_BOX, at=NOW, extra=[['revoked', PK[OTHER_BOX], str(NOW-2)]])])
        for at, name in ((NOW-3, 'Before cutoff'), (NOW, 'After cutoff')):
            self.relay.publish([s.sign_event(30078, json.dumps({'name': name}), [['d', 'wizard-profile'], ['p', PK[OTHER_OWNER]]], sk=OTHER_BOX, created_at=at)])
        out = s.friend_profile(f['id'])
        self.assertEqual(out['name'], 'Before cutoff')
        self.assertEqual(out['viewer'], 'visitor')

    def test_requests_cache_verified_owner_evidence_across_offline_restart(self):
        self.relay.publish([listing(OTHER_OWNER, OTHER_BOX)])
        with patch.object(s, '_KEY', (OTHER_OWNER, PK[OTHER_OWNER])):
            w = s.gift_wrap(PK[BOX], '{"name":"Owner"}')
        self.relay.publish([w]); s.check_requests()
        self.relay.events.clear()
        self.assertTrue(s.resolve_key(PK[OTHER_OWNER])['claimed'])
        self.assertEqual(s.resolve_key(PK[OTHER_OWNER])['inbox'], PK[OTHER_BOX])

    def test_claim_rekeys_legacy_request_without_id_and_merges_duplicates(self):
        state = s.load()
        state['requests'] = [{'pubkey': PK[FRIEND], 'npub': s.npub_encode(PK[FRIEND]), 'name': 'Miguel'}]
        s.save(state)
        self.relay.publish([listing(OTHER_OWNER, FRIEND), meta(FRIEND, OTHER_OWNER), s.sign_event(0, '{"name":"Miguel"}', [], sk=OTHER_OWNER, created_at=NOW)])
        s.rekey_friends()
        self.assertEqual(s.load()['requests'][0]['pubkey'], PK[OTHER_OWNER])
        state = s.load(); state['requests'].append({'pubkey': PK[FRIEND], 'name': 'Duplicate'}); s.save(state)
        s.rekey_friends()
        self.assertEqual(len(s.load()['requests']), 1)

    def test_forged_profile_owner_tag_or_wrong_role_never_trusted(self):
        self.relay.publish([listing(OTHER_OWNER, OTHER_BOX, roles=('inbox',))])
        f = s.add_friend({'npub': s.npub_encode(PK[OTHER_OWNER])})['friend']
        self.relay.publish([s.sign_event(30078, '{"name":"Forged"}', [['d','wizard-profile'], ['p',PK[OTHER_OWNER]]], sk=OTHER_BOX, created_at=NOW)])
        self.assertEqual(s.friend_profile(f['id'])['viewer'], 'none')

    def test_restore_invalidates_prepared_device_claim(self):
        p = s.claim_prepare({'npub': s.npub_encode(PK[OWNER])})
        # Disable the stock background poll; no process survives the disposable test.
        with patch.object(s.threading.Thread, 'start', lambda self: None):
            s.restore_identity({'backup': s.b32_encode('nsec', FRIEND)})
        with self.assertRaises(s.Problem):
            s.claim_commit({'token': p['token'], 'event': signed(p['event'], OWNER)})

    def test_stock_miguel_receives_james_and_james_reads_stock_profile(self):
        # Unchanged upstream 0.5.1 module in a separate disposable DATA directory.
        spec = importlib.util.spec_from_file_location('stock_profiles', Path(__file__).parent / 'fixtures' / 'stock_server.py')
        stock = importlib.util.module_from_spec(spec); spec.loader.exec_module(stock)
        stock.DATA = s.DATA / 'stock'; stock._KEY = (FRIEND, PK[FRIEND])
        stock.relay_query = self.relay.query; stock.relay_publish = self.relay.publish; stock.sync_soon = lambda: None
        self.claim()
        p, ev = self.friend_flow()
        out = s.friend_commit({'token': p['token'], 'event': ev})
        stock.check_requests()
        self.assertEqual(stock.load()['requests'][0]['pubkey'], PK[OWNER])
        stock.update_me({'name': 'Miguel'})
        stock.add_friend({'npub': s.npub_encode(PK[OWNER])})
        s.check_requests()
        self.assertEqual(s.me()['sealed_requests'], 1)
        profile = s.friend_profile(out['friend']['id'])
        self.assertTrue(profile['sealed_profiles'])
        e = profile['sealed_profiles'][0]
        plaintext = s.nip44_decrypt(s.conversation_key(OWNER, e['pubkey']), e['content'])
        opened = s.open_profile(out['friend']['id'], {'event': e, 'plaintext': plaintext})
        self.assertEqual(opened['viewer'], 'friend')
        self.assertEqual(opened['name'], "Miguel's Wizard (unclaimed)")


if __name__ == '__main__':
    unittest.main()

'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { create } = require('../web/identity-client.js');
const OWNER = 'npub-owner-fixture', BOX = 'box-hex-fixture', FRIEND = 'friend-inbox-hex';
function fixture({ unavailable = false, denied = '', owner = OWNER } = {}) {
  const calls = [], requests = [];
  const event = { pubkey: 'owner-hex', created_at: 42, kind: 30078, tags: [['d', 'wizard-devices']], content: '' };
  const rumor = { pubkey: 'owner-hex', created_at: 42, kind: 1078, tags: [], content: '{"name":"James"}' };
  const seal = { ...event, kind: 13, content: 'encrypted-by-phone' };
  const signed = { ...seal, id: 'event-id', sig: 'phone-signature' };
  const me = { owner_npub: OWNER, npub: OWNER, box_npub: BOX, sealed_requests: 0 };
  const api = async (path, method = 'GET', body) => {
    calls.push({ path, method, body });
    if (path === 'api/identity/claim/prepare') return { token: 'claim-token', event };
    if (path === 'api/identity/claim') return me;
    if (path === 'api/friends/prepare') return { token: 'friend-token', recipient: FRIEND, rumor };
    if (path === 'api/friends/seal') return { event: seal };
    if (path === 'api/friends/commit' || path === 'api/friends') return { friend: {}, me, sent: true };
    if (path === 'api/identity/pending') return { requests: [{ id: 'wrap-id', pubkey: 'throwaway-key', content: 'outer-ciphertext' }] };
    if (path === 'api/requests/open') return me;
    if (path.endsWith('/profile/open')) return { viewer: 'friend', name: 'Miguel' };
    throw new Error('Unexpected API call: ' + path);
  };
  const request = async (op, args) => {
    requests.push({ op, args });
    if (op === 'identity.info') return unavailable ? { unavailable: true } : { npub: owner, name: 'James', backed_up: true };
    if (op === denied) return { denied: true };
    if (op === 'identity.sign') return { ...args.event, id: 'event-id', sig: 'phone-signature' };
    if (op === 'identity.nip44_encrypt') return { ciphertext: 'encrypted-by-phone' };
    if (op === 'identity.nip44_decrypt') return { plaintext: JSON.stringify(args.ciphertext === 'outer-ciphertext' ? seal : rumor) };
    throw new Error('Unexpected op: ' + op);
  };
  const client = create({ api, request });
  return { client, calls, requests, event, rumor, seal, signed, me, api, request };
}

test('claim gets unsigned list, asks shared bridge for phone signature, posts exact event', async () => {
  const f = fixture(); await f.client.info(); assert.equal((await f.client.claim()).owner_npub, OWNER);
  assert.deepEqual(f.requests[1], { op: 'identity.sign', args: { event: f.event } });
  assert.equal(f.calls[1].body.token, 'claim-token'); assert.equal(f.calls[1].body.event.sig, 'phone-signature');
});
test('claim denial never commits', async () => {
  const f = fixture({ denied: 'identity.sign' }); await f.client.info();
  await assert.rejects(f.client.claim(), /denied/);
  assert.deepEqual(f.calls.map(c => c.path), ['api/identity/claim/prepare']);
});
test('sending and accepting encrypt rumor on phone then sign owner seal', async () => {
  for (const body of [{ npub: 'friend-person' }, { npub: 'friend-person', name: 'Add back' }]) {
    const f = fixture(); await f.client.info(); await f.client.addFriend(f.me, body);
    assert.deepEqual(f.requests.map(r => r.op), ['identity.info', 'identity.nip44_encrypt', 'identity.sign']);
    assert.equal(f.requests[1].args.pubkey, FRIEND); assert.deepEqual(JSON.parse(f.requests[1].args.plaintext), f.rumor);
    assert.equal(f.requests[2].args.event.kind, 13);
    assert.deepEqual(f.calls.map(c => c.path), ['api/friends/prepare', 'api/friends/seal', 'api/friends/commit']);
  }
});
test('encrypt denial never asks box to sign or commits', async () => {
  const f = fixture({ denied: 'identity.nip44_encrypt' }); await f.client.info();
  await assert.rejects(f.client.addFriend(f.me, { npub: 'friend' }), /denied/);
  assert.deepEqual(f.calls.map(c => c.path), ['api/friends/prepare']);
});
test('sign denial does not send friend request', async () => {
  const f = fixture({ denied: 'identity.sign' }); await f.client.info();
  await assert.rejects(f.client.addFriend(f.me, { npub: 'friend' }), /denied/);
  assert.ok(!f.calls.some(c => c.path === 'api/friends/commit'));
});
test('unavailable bridge keeps unclaimed stock behavior', async () => {
  const f = fixture({ unavailable: true }); await f.client.info();
  await f.client.addFriend({ owner_npub: null }, { npub: 'legacy-friend' });
  assert.deepEqual(f.calls.map(c => c.path), ['api/friends']);
  await assert.rejects(f.client.claim(), /Set up your Wizard ID on your phone/);
});
test('claimed install with missing or different phone cannot downgrade to box signing', async () => {
  for (const options of [{ unavailable: true }, { owner: 'another-phone' }]) {
    const f = fixture(options); await f.client.info();
    await assert.rejects(f.client.addFriend(f.me, { npub: 'friend' }), /phone that owns/);
    assert.equal(f.calls.length, 0);
  }
});
test('owner-addressed queue is explicitly opened in two phone decryptions', async () => {
  const f = fixture(); await f.client.info(); const states = [];
  await f.client.openRequests(f.me, me => states.push(me));
  assert.deepEqual(f.requests.slice(1).map(r => r.args.pubkey), ['throwaway-key', 'owner-hex']);
  assert.equal(f.calls[1].body.id, 'wrap-id'); assert.deepEqual(f.calls[1].body.rumor, f.rumor);
  assert.equal(states.length, 1);
});
test('decryption denial leaves queue unopened and retryable', async () => {
  const f = fixture({ denied: 'identity.nip44_decrypt' }); await f.client.info();
  await assert.rejects(f.client.openRequests(f.me), /denied/);
  assert.ok(!f.calls.some(c => c.path === 'api/requests/open'));
});
test('stock phone-addressed encrypted profile opens through phone, never server owner key', async () => {
  const f = fixture();
  const request = (op, args) => op === 'identity.nip44_decrypt'
    ? Promise.resolve({ plaintext: '{"app":"profiles","name":"Miguel"}' }) : f.request(op, args);
  const client = create({ api: f.api, request }); await client.info();
  const event = { pubkey: 'miguel-box', content: 'stock-owner-encrypted-copy' };
  const opened = await client.openProfile(f.me, 'deadbeef', { sealed_profiles: [event] });
  assert.equal(opened.viewer, 'friend'); assert.equal(f.calls[0].path, 'api/friends/deadbeef/profile/open');
  assert.deepEqual(f.calls[0].body.event, event);
});
test('profile decryption denial is not swallowed or silently retried', async () => {
  const f = fixture({ denied: 'identity.nip44_decrypt' }); await f.client.info();
  await assert.rejects(f.client.openProfile(f.me, 'deadbeef', { sealed_profiles: [{ pubkey: FRIEND, content: 'ciphertext' }] }), /denied/);
  assert.equal(f.calls.length, 0);
});
test('default wrapper uses shared WizardApp.identity, not app-local postMessage', async () => {
  const ops = [];
  globalThis.WizardApp = { identity: { info: async args => { ops.push(args); return { npub: OWNER }; }, sign: async event => { assert.equal(event.kind, 30078); assert.equal(event.event, undefined); return { ...event, id: 'signed', sig: 'phone' }; } } };
  try {
    const client = create({ api: async path => path.endsWith('/prepare') ? { token: 'claim', event: { kind: 30078 } } : { owner_npub: OWNER } });
    assert.equal((await client.info()).npub, OWNER); assert.deepEqual(ops, [{}]);
    assert.equal((await client.claim()).owner_npub, OWNER);
  } finally { delete globalThis.WizardApp; }
});

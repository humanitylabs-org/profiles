/* Profiles domain flow only. Privileged transport belongs to WizardApp, never this app.
 * request(op,args) is injectable for tests; the server never receives an owner secret. */
(function (root) {
  'use strict';
  function create({ api, request = sharedRequest }) {
    let phone = { unavailable: true };
    async function call(op, args = {}) {
      const result = await request(op, args);
      if (!result || result.denied || result.cancelled || result.unavailable || result.none) {
        const e = new Error(result?.denied ? 'Phone approval denied. Nothing sent.' : 'Your phone Wizard ID is unavailable.');
        e.denied = !!result?.denied; throw e;
      }
      return result;
    }
    async function info() {
      try { phone = await request('identity.info', {}); } catch (_) { phone = { unavailable: true }; }
      if (!phone?.npub) phone = { unavailable: true };
      return phone;
    }
    function matching(me) {
      if (!phone.npub || phone.npub !== me.owner_npub) throw new Error('Open Profiles on the phone that owns this Wizard.');
    }
    async function claim() {
      if (!phone.npub) throw new Error('Set up your Wizard ID on your phone to claim this Wizard');
      const prepared = await api('api/identity/claim/prepare', 'POST', { npub: phone.npub });
      const event = await call('identity.sign', { event: prepared.event });
      return api('api/identity/claim', 'POST', { token: prepared.token, event });
    }
    async function addFriend(me, body) {
      // Unclaimed devices retain the stock path; claimed devices NEVER downgrade.
      if (!me.owner_npub) return api('api/friends', 'POST', body);
      matching(me);
      const prepared = await api('api/friends/prepare', 'POST', body);
      const { ciphertext } = await call('identity.nip44_encrypt', { pubkey: prepared.recipient, plaintext: JSON.stringify(prepared.rumor) });
      if (typeof ciphertext !== 'string') throw new Error('Phone returned no sealed request.');
      const unsigned = await api('api/friends/seal', 'POST', { token: prepared.token, ciphertext });
      const event = await call('identity.sign', { event: unsigned.event });
      return api('api/friends/commit', 'POST', { token: prepared.token, event });
    }
    async function openRequests(me, progress = () => {}) {
      matching(me);
      const pending = await api('api/identity/pending');
      for (const wrap of pending.requests) {
        const outer = await call('identity.nip44_decrypt', { pubkey: wrap.pubkey, ciphertext: wrap.content });
        const seal = JSON.parse(outer.plaintext);
        const inner = await call('identity.nip44_decrypt', { pubkey: seal.pubkey, ciphertext: seal.content });
        me = await api('api/requests/open', 'POST', { id: wrap.id, seal, rumor: JSON.parse(inner.plaintext) });
        progress(me);
      }
      return me;
    }
    async function openProfile(me, id, profile) {
      matching(me);
      for (const event of profile.sealed_profiles || []) {
        try {
          const { plaintext } = await call('identity.nip44_decrypt', { pubkey: event.pubkey, ciphertext: event.content });
          const p = JSON.parse(plaintext);
          if (!p || (!p.removed && p.app !== 'profiles')) continue;
          return await api(`api/friends/${id}/profile/open`, 'POST', { event, plaintext });
        } catch (e) { if (e.denied || /unavailable|owns this Wizard/.test(e.message)) throw e; }
      }
      throw new Error('No profile copy could be opened by your phone. Ask your friend to share again.');
    }
    return { info, claim, addFriend, openRequests, openProfile, get phone() { return phone; } };
  }
  async function sharedRequest(op, args) {
    const facade = root.WizardApp?.identity;
    const method = op.slice('identity.'.length);
    if (!facade || typeof facade[method] !== 'function') return { unavailable: true };
    // WizardApp.sign takes the event directly; the facade supplies {event} on the wire.
    return method === 'sign' ? facade.sign(args.event) : facade[method](args);
  }
  const exports = { create };
  if (typeof module !== 'undefined' && module.exports) module.exports = exports;
  else root.ProfilesIdentity = exports;
})(typeof window !== 'undefined' ? window : globalThis);

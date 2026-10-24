'use strict';
/* Profiles view. Talks to this app's own API (relative paths) and, because it runs on the Wizard origin, reads what
 * the box already knows: the shell build (my-release.json or the installed shell commit), the installed apps, the
 * skin this device wears and the owner's My skin. Owner text is rendered with textContent only. */
const $ = id => document.getElementById(id);
const hosted = document.documentElement.classList.contains('wz-hosted');
const TRYON = '/wizard-os-home/tryon/api/';
const LEVEL = { private: 'Only you', friends: 'Friends', public: 'Everyone' };
const PART = { build: 'Build', skin: 'Look', apps: 'Apps' };
const HINT = {
  build: 'Your version of Wizard. Friends can try it on beside their own Wizard; Stop ends it.',
  skin: 'Your skin and your own touches to it.',
  apps: 'Only apps from the App Store. Apps you build yourself never show.',
};
let ME = null, TAB = 'me', FRIEND = null, TRY = null, tryTimer = 0, busy = false;

function h(tag, attrs = {}, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v == null || v === false) continue;
    if (k === 'class') el.className = v; else if (k === 'text') el.textContent = v;
    else if (k.startsWith('on')) el.addEventListener(k.slice(2), v); else el.setAttribute(k, v === true ? '' : v);
  }
  for (const c of kids.flat()) if (c != null && c !== false) el.append(c.nodeType ? c : document.createTextNode(String(c)));
  return el;
}
function say(text, kind = '') { const s = $('status'); s.classList.toggle('wz-sr', !kind); s.classList.toggle('note', kind === 'note'); s.textContent = text; }
async function api(path, method = 'GET', body) {
  const r = await fetch(path, { method, cache: 'no-store', credentials: 'same-origin', ...(body === undefined ? {} : { headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }) });
  let j = {}; try { j = await r.json(); } catch (_) {}
  if (!r.ok) throw new Error(j.error || j.message || `Something went wrong (${r.status}).`);
  return j;
}
const ago = iso => { if (!iso) return ''; const s = (Date.now() - Date.parse(iso)) / 1000; if (!(s >= 0)) return ''; if (s < 90) return 'just now'; if (s < 5400) return Math.round(s / 60) + ' min ago'; if (s < 129600) return Math.round(s / 3600) + ' h ago'; return Math.round(s / 86400) + ' days ago'; };
const shell = () => { try { return parent !== window ? parent : null; } catch (_) { return null; } };

/* ---------- what this box runs (read on the Wizard origin) ---------- */
async function getJSON(url) { try { const r = await fetch(url, { cache: 'no-store', credentials: 'same-origin' }); return r.ok ? await r.json() : null; } catch (_) { return null; } }
async function getText(url) { try { const r = await fetch(url, { cache: 'no-store', credentials: 'same-origin' }); return r.ok ? await r.text() : ''; } catch (_) { return ''; } }
async function localFacts() {
  const [rel, inst, css] = await Promise.all([getJSON('/wizard-os-home/my-release.json'), getJSON('/wizard-os-home/store-data/wizard/v1/installed-apps'), getText('/wizard/v1/my-skin')]);
  const wam = Array.isArray(inst?.wam) ? inst.wam : [];
  const shellApp = wam.find(a => a.id === 'wizard-ux');
  const build = rel?.build ? { commit: rel.build, name: rel.name || 'My Wizard', base: rel.base?.ref || '', changes: rel.changes || [], built_at: rel.built_at || '' }
    : shellApp?.commit ? { commit: shellApp.commit, name: 'Wizard', base: '', changes: [], built_at: '' } : null;
  const { id: skinId, name: skinName } = currentSkin();
  return { build, apps: wam.map(a => ({ id: a.id, repo: a.repo, name: a.name || a.id })), skin: { id: skinId, name: skinName, css } };
}

const SKIN_NAMES = { nebula: 'Nebula', grove: 'Grove', tide: 'Tide', ember: 'Ember', signal: 'Signal', obsidian: 'Dark', 'obsidian-light': 'Light', landscapes: 'Landscapes' };
function currentSkin() {
  // The skin Wizard is wearing right now: the shell's own picker first (parent or top window), then the skin the
  // shell pushed into this frame, then this device's saved choice. Never a guess.
  let S = null;
  for (const w of [shell(), (() => { try { return top !== window ? top : null; } catch (_) { return null; } })()]) { try { if (w?.WosSkin) { S = w.WosSkin; break; } } catch (_) {} }
  let id = S?.current || '';
  if (!id && window.WizardTheme?.connected) id = window.WizardTheme.current?.skin || '';
  if (!id) { try { id = localStorage.getItem('wos.skin') || ''; } catch (_) {} }
  id = id || 'nebula';
  return { id, name: S?.list?.find(x => x.id === id)?.name || SKIN_NAMES[id] || id };
}
function avatar(p, cls = '') {
  return p?.picture ? h('img', { class: 'pf-avatar ' + cls, src: p.picture, alt: '' })
    : h('div', { class: 'pf-avatar ' + cls, 'aria-hidden': 'true', text: (p?.name || '?').trim().charAt(0).toUpperCase() || '?' });
}
const shortNpub = n => n ? n.slice(0, 12) + '…' + n.slice(-6) : '';
async function copy(btn, text, label = 'Copy') {
  try { await navigator.clipboard.writeText(text); btn.textContent = 'Copied'; setTimeout(() => { btn.textContent = label; }, 1600); }
  catch (_) { say('Copy failed. Long-press the text instead.', 'error'); }
}
// A photo becomes a small square JPEG on this device (about 30 KB) before it is saved; the original never leaves.
function squarePhoto(file) {
  return new Promise((resolve, reject) => {
    const img = new Image(), url = URL.createObjectURL(file);
    img.onload = () => {
      const side = Math.min(img.naturalWidth, img.naturalHeight), c = document.createElement('canvas');
      c.width = c.height = 256;
      c.getContext('2d').drawImage(img, (img.naturalWidth - side) / 2, (img.naturalHeight - side) / 2, side, side, 0, 0, 256, 256);
      URL.revokeObjectURL(url);
      let q = .85, out = c.toDataURL('image/jpeg', q);
      while (out.length > 100000 && q > .4) { q -= .15; out = c.toDataURL('image/jpeg', q); }
      resolve(out);
    };
    img.onerror = () => { URL.revokeObjectURL(url); reject(new Error('That file is not a photo this device can read.')); };
    img.src = url;
  });
}

/* ---------- You ---------- */
function segmented(part) {
  const cur = ME.visibility[part];
  const levels = part === 'build' ? ['private', 'friends'] : ['private', 'friends', 'public'];
  return h('div', { class: 'pf-seg', role: 'radiogroup', 'aria-label': `Who sees your ${PART[part].toLowerCase()}` },
    levels.map(l => h('button', { type: 'button', role: 'radio', 'aria-checked': String(cur === l), class: cur === l ? 'on' : '', onclick: () => setLevel(part, l) }, LEVEL[l])));
}
async function setLevel(part, level) {
  if (busy) return; busy = true;
  try { ME = await api('api/me', 'PUT', { visibility: { [part]: level } }); say(`${PART[part]}: ${LEVEL[level]}`); render(); }
  catch (e) { say(e.message, 'error'); } finally { busy = false; }
}
async function publish(btn) {
  btn.disabled = true; btn.textContent = 'Publishing…';
  try {
    const f = await localFacts();
    if (!f.build) throw new Error('Could not read which Wizard build this box runs.');
    const out = await api('api/publish', 'POST', { build: f.build, skin: f.skin, apps: f.apps });
    ME = out.me; render();
    const kept = out.report.kept_private.length;
    say(`Published. ${kept ? kept + ' thing' + (kept === 1 ? '' : 's') + ' stayed private.' : ''}`, 'note');
  } catch (e) { say(e.message, 'error'); btn.disabled = false; btn.textContent = 'Publish'; }
}
async function toggleApp(key, id) {
  const set = new Set(ME[key]); set.has(id) ? set.delete(id) : set.add(id);
  try { ME = await api('api/me', 'PUT', { [key]: [...set] }); render(); } catch (e) { say(e.message, 'error'); }
}
function editName() {
  let picture = ME.picture || '';
  const box = h('form', { class: 'pf-edit', onsubmit: async e => {
    e.preventDefault();
    try { ME = await api('api/me', 'PUT', { name: n.value, bio: b.value, picture, messenger: m.value.trim() }); render(); say('Saved.'); }
    catch (err) { say(err.message, 'error'); }
  } });
  const face = h('div', { class: 'pf-photo' });
  const paint = () => face.replaceChildren(avatar({ name: n.value || ME.name, picture }, 'lg'));
  const file = h('input', { type: 'file', accept: 'image/*', hidden: true, onchange: async () => {
    const f0 = file.files?.[0]; if (!f0) return;
    try { picture = await squarePhoto(f0); paint(); remove.hidden = false; } catch (err) { say(err.message, 'error'); }
  } });
  const remove = h('button', { type: 'button', class: 'pf-chip', hidden: !picture, onclick: () => { picture = ''; paint(); remove.hidden = true; } }, 'Remove');
  const n = h('input', { class: 'wz-input', maxlength: 60, placeholder: 'Your name', 'aria-label': 'Your name', oninput: () => { if (!picture) paint(); } }); n.value = ME.name;
  const b = h('input', { class: 'wz-input', maxlength: 280, placeholder: 'A line about you (optional)', 'aria-label': 'About you' }); b.value = ME.bio;
  const m = h('input', { class: 'wz-input', placeholder: 'Your Messenger address, npub1… (optional)', 'aria-label': 'Messenger address', autocomplete: 'off', spellcheck: 'false' }); m.value = ME.messenger || '';
  paint();
  box.append(h('div', { class: 'pf-photo-row' }, face, h('button', { type: 'button', class: 'pf-chip on', onclick: () => file.click() }, picture ? 'Change photo' : 'Add photo'), remove, file),
    n, b, m, h('p', { class: 'pf-hint', text: 'Friends see your Messenger address so they can message you there.' }),
    h('div', { class: 'pf-row-acts' }, h('button', { type: 'submit', class: 'pf-btn go' }, 'Save'), h('button', { type: 'button', class: 'pf-btn', onclick: render }, 'Cancel')));
  $('view-me').querySelector('.pf-who').replaceWith(box); n.focus();
}
function partBody(part, snap) {
  if (part === 'build') {
    const b = snap?.build;
    if (!snap) return h('small', {}, 'Publish to share it.');
    if (!b) return h('small', {}, 'This build is not public code yet, so it stays private.');
    return h('small', {}, `${b.name} · ${b.changes.length} change${b.changes.length === 1 ? '' : 's'} of your own`);
  }
  if (part === 'skin') {
    const live = currentSkin();
    if (!snap) return h('small', {}, `${live.name} · publish to share it`);
    return h('small', {}, snap.skin.id === live.id ? live.name + (snap.skin.css ? ' with your own touches' : '') : `Shared: ${snap.skin.name}. You wear ${live.name} now, publish again to share it.`);
  }
  return h('small', {}, snap ? `${snap.apps.length - ME.hidden.filter(id => snap.apps.some(a => a.id === id)).length} of ${snap.apps.length} App Store apps shown` : 'Publish to share them.');
}
function renderMe() {
  const v = $('view-me'); v.replaceChildren();
  const snap = ME.snapshot;
  v.append(h('div', { class: 'pf-who' },
    avatar(ME),
    h('div', { class: 'wz-main' }, h('b', { text: ME.name || 'Add your name and photo' }), h('small', { text: ME.bio || 'Your Wizard profile' }),
      h('button', { type: 'button', class: 'pf-npub', title: ME.npub, onclick: e => copy(e.currentTarget, ME.npub, shortNpub(ME.npub)) }, shortNpub(ME.npub))),
    h('button', { type: 'button', class: 'pf-btn', onclick: editName }, 'Edit')));
  const sec = h('section', { class: 'wz-sec' }, h('h2', { class: 'wz-sec-h' }, 'Who sees what'));
  for (const part of ['build', 'skin', 'apps']) {
    sec.append(h('div', { class: 'pf-part' },
      h('div', { class: 'wz-main' }, h('b', { text: PART[part] }), partBody(part, snap)),
      segmented(part),
      h('p', { class: 'pf-hint', text: HINT[part] })));
  }
  v.append(sec);
  const pub = h('button', { type: 'button', class: 'pf-btn go wide', onclick: e => publish(e.currentTarget) }, snap ? 'Publish again' : 'Publish');
  v.append(h('div', { class: 'pf-publish' }, pub, h('small', { text: snap ? `What friends see was frozen ${ago(snap.published_at)}. Publish again after you change things.` : 'Nothing is shared until you publish. Friends then see a frozen copy, never your live box.' })));
  if (snap?.apps?.length) {
    const list = h('ul', { class: 'wz-list' });
    for (const a of snap.apps) {
      const hidden = ME.hidden.includes(a.id), uses = ME.uses.includes(a.id);
      list.append(h('li', { class: 'pf-item' + (hidden ? ' off' : '') },
        h('div', { class: 'wz-main' }, h('b', { text: a.name }), h('small', { text: hidden ? 'Hidden from your profile' : uses ? 'Shown · you use this a lot' : 'Shown' })),
        h('button', { type: 'button', class: 'pf-chip' + (uses ? ' on' : ''), 'aria-pressed': String(uses), disabled: hidden, onclick: () => toggleApp('uses', a.id) }, 'I use this'),
        h('button', { type: 'button', class: 'pf-chip', onclick: () => toggleApp('hidden', a.id) }, hidden ? 'Show' : 'Hide')));
    }
    v.append(h('section', { class: 'wz-sec' }, h('h2', { class: 'wz-sec-h' }, 'Your App Store apps', h('small', { text: 'Apps you built yourself are never listed' })), list));
  }
  v.append(h('section', { class: 'wz-sec' }, h('h2', { class: 'wz-sec-h' }, 'Check it'),
    h('div', { class: 'pf-row-acts' }, h('button', { type: 'button', class: 'pf-btn', onclick: () => preview('friend') }, 'See it as a friend'), h('button', { type: 'button', class: 'pf-btn', onclick: () => preview('public') }, 'See it as everyone'))));
}
async function preview(as) {
  try { const p = await api('api/preview?as=' + as); FRIEND = { profile: { ...p, friend: { name: as === 'friend' ? 'A friend' : 'Everyone' } }, preview: as }; show('friend'); }
  catch (e) { say(e.message, 'error'); }
}

/* ---------- Friends ---------- */
function renderFriends() {
  const v = $('view-friends'); v.replaceChildren();
  if (ME.requests.length) {
    const reqs = h('ul', { class: 'wz-list' });
    for (const r of ME.requests) reqs.append(h('li', { class: 'pf-item' },
      avatar(r, 'sm'),
      h('div', { class: 'wz-main' }, h('b', { text: r.name }), h('small', { text: `${shortNpub(r.npub)} · wants to be friends` })),
      r.address ? h('button', { type: 'button', class: 'pf-chip on', onclick: () => accept(r) }, 'Accept') : h('button', { type: 'button', class: 'pf-chip on', onclick: () => addForm(r) }, 'Add back'),
      h('button', { type: 'button', class: 'pf-chip', onclick: async () => { ME = await api('api/requests/dismiss', 'POST', { npub: r.npub }); render(); } }, 'Ignore')));
    v.append(h('section', { class: 'wz-sec' }, h('h2', { class: 'wz-sec-h' }, 'Requests'), reqs));
  }
  const list = h('ul', { class: 'wz-list' });
  for (const f of ME.friends) list.append(h('li', {},
    h('button', { type: 'button', class: 'wz-row', onclick: () => openFriend(f) },
      avatar(f, 'sm'),
      h('span', { class: 'wz-main' }, h('b', { text: f.name }), h('small', { text: shortNpub(f.npub) })), h('span', { class: 'pf-go', 'aria-hidden': 'true' }, '›'))));
  v.append(h('section', { class: 'wz-sec' }, h('h2', { class: 'wz-sec-h' }, 'Friends', ME.friends.length ? h('span', { class: 'wz-count', text: String(ME.friends.length) }) : null),
    ME.friends.length ? list : h('div', { class: 'wz-empty' }, h('div', { class: 'wz-tile', 'aria-hidden': 'true' }, '☺'), h('strong', {}, 'No friends yet'),
      h('p', {}, 'Swap friend codes with someone. Each code is their Nostr ID plus the private address of their Wizard.'))));
  v.append(h('div', { class: 'pf-publish' }, h('button', { type: 'button', class: 'pf-btn go wide', onclick: () => addForm() }, 'Add a friend')));
  const cp = h('button', { type: 'button', class: 'pf-chip', onclick: e => copy(e.currentTarget, ME.code) }, 'Copy');
  v.append(h('section', { class: 'wz-sec' }, h('h2', { class: 'wz-sec-h' }, 'Your friend code'),
    h('div', { class: 'pf-item' }, h('div', { class: 'wz-main' }, h('b', { class: 'pf-link', text: ME.code }), h('small', { text: 'Send this to a friend. It is your Nostr ID and the address of your Wizard.' })), cp),
    h('p', { class: 'pf-hint', text: ME.link ? 'That address only answers signed friend requests and what you share. Your Wizard and apps stay closed.' : 'Friends can see your Nostr ID, but your Wizard has no friend address yet. Ask your agent to set one up.' })));
}
function addForm(req) {
  const v = $('view-friends');
  const f = h('form', { class: 'pf-edit', onsubmit: async e => {
    e.preventDefault(); const b = f.querySelector('button[type=submit]'); b.disabled = true;
    try { await added(await api('api/friends', 'POST', { code: a.value, name: n.value })); }
    catch (err) { say(err.message, 'error'); b.disabled = false; }
  } });
  const a = h('textarea', { class: 'wz-input pf-code', required: true, rows: 2, placeholder: 'Paste their friend code (…/profiles/#npub1…)', 'aria-label': 'Their friend code', autocomplete: 'off', spellcheck: 'false' });
  const n = h('input', { class: 'wz-input', placeholder: 'Name (optional, their profile fills it in)', 'aria-label': 'Name', maxlength: 60 });
  if (req) { a.value = req.npub; n.value = req.name; }
  f.append(h('h2', { class: 'wz-sec-h' }, req ? `Add ${req.name} back` : 'Add a friend'), a, n,
    h('p', { class: 'pf-hint', text: 'Their Nostr ID is how your Wizard knows it is really them: everything they send is signed with it.' }),
    h('div', { class: 'pf-row-acts' }, h('button', { type: 'submit', class: 'pf-btn go' }, 'Add'), h('button', { type: 'button', class: 'pf-btn', onclick: render }, 'Cancel')));
  v.prepend(f); a.focus();
}
async function added(out) {
  ME = out.me; render();
  say(out.hello === 'sent' ? `${out.friend.name} added. They'll see your request.` : `${out.friend.name} added. Their Wizard didn't answer yet (${out.hello}).`, 'note');
}
async function accept(r) {
  try { await added(await api('api/friends', 'POST', { address: r.address, npub: r.npub, name: r.name })); } catch (e) { say(e.message, 'error'); }
}
async function openFriend(f) {
  FRIEND = { profile: null, friend: f }; show('friend');
  try { FRIEND.profile = await api(`api/friends/${f.id}/profile`); }
  catch (e) { FRIEND.error = e.message; }
  if (TAB === 'friend') renderFriend();
}
async function removeFriend(f) {
  if (!confirm(`Remove ${f.name}? They stop seeing what you share with friends.`)) return;
  try { ME = await api('api/friends/' + f.id, 'DELETE'); show('friends'); } catch (e) { say(e.message, 'error'); }
}

/* ---------- A friend's profile ---------- */
function renderFriend() {
  const v = $('view-friend'); v.replaceChildren();
  const back = h('button', { type: 'button', class: 'pf-back', onclick: () => show(FRIEND?.preview ? 'me' : 'friends') }, '‹ ', FRIEND?.preview ? 'Your profile' : 'Friends');
  v.append(back);
  if (!FRIEND) return;
  const p = FRIEND.profile, f = FRIEND.friend || p?.friend || {};
  if (FRIEND.preview) v.append(h('p', { class: 'pf-banner', text: FRIEND.preview === 'friend' ? 'This is what a friend sees.' : 'This is what everyone sees.' }));
  if (FRIEND.error) { v.append(h('div', { class: 'wz-empty' }, h('strong', {}, `Couldn't reach ${f.name || 'them'}`), h('p', { text: FRIEND.error }))); return; }
  if (!p) { v.append(h('p', { class: 'pf-hint', text: 'Asking their Wizard…' })); return; }
  v.append(h('div', { class: 'pf-who' }, avatar(p),
    h('div', { class: 'wz-main' }, h('b', { text: p.name }), h('small', { text: p.bio || (p.published_at ? `Updated ${ago(p.published_at)}` : 'Nothing shared yet') }),
      p.npub ? h('span', { class: 'pf-npub static', title: p.npub }, (p.signed ? '✓ ' : '') + shortNpub(p.npub)) : null)));
  if (p.messenger && !FRIEND.preview) {
    const mb = h('button', { type: 'button', class: 'pf-chip', onclick: e => copy(e.currentTarget, p.messenger, 'Copy Messenger address') }, 'Copy Messenger address');
    v.append(h('div', { class: 'pf-row-acts' }, h('a', { class: 'pf-btn go', href: '/messenger/' }, 'Message in Messenger'), mb));
  }
  const nothing = !p.build && !p.skin && !p.apps;
  if (nothing) v.append(h('div', { class: 'wz-empty' }, h('strong', {}, 'Nothing shared with you yet'), h('p', {}, p.viewer === 'visitor' ? "Their box doesn't know you as a friend yet. Ask them to add you." : 'They haven\'t published anything for friends.')));
  if (p.build) {
    const b = p.build, mine = FRIEND.preview;
    const sec = h('section', { class: 'wz-sec' }, h('h2', { class: 'wz-sec-h' }, 'Build', h('small', { text: b.name })));
    const changes = h('ul', { class: 'pf-changes' }, b.changes.slice(0, 12).map(c => h('li', { text: c.title })));
    sec.append(b.changes.length ? changes : h('p', { class: 'pf-hint', text: 'Stock Wizard, no changes of their own.' }));
    if (!mine) {
      const t = TRY?.commit === b.commit ? TRY : null;
      sec.append(h('div', { class: 'pf-row-acts' },
        t?.state === 'ready' ? [h('a', { class: 'pf-btn go', href: t.url, target: '_blank', rel: 'noopener' }, 'Open it'), h('button', { type: 'button', class: 'pf-btn', onclick: stopTry }, 'Stop trying')]
          : t && ['queued', 'building', 'starting'].includes(t.state) ? h('button', { type: 'button', class: 'pf-btn', disabled: true }, 'Getting it ready…')
            : h('button', { type: 'button', class: 'pf-btn go', onclick: () => tryOn(b, p.name) }, 'Try it on')),
        h('p', { class: 'pf-hint', text: 'Runs their exact build beside yours, with your own chats and apps. Your Wizard is not changed; Stop trying ends it.' }));
    }
    v.append(sec);
  }
  if (p.skin) {
    const k = p.skin, wearing = ME.wearing?.friend === p.name;
    v.append(h('section', { class: 'wz-sec' }, h('h2', { class: 'wz-sec-h' }, 'Look', h('small', { text: k.name + (k.css ? ' + their touches' : '') })),
      FRIEND.preview ? null : h('div', { class: 'pf-row-acts' }, wearing ? h('button', { type: 'button', class: 'pf-btn', onclick: restoreLook }, 'Back to my look')
        : h('button', { type: 'button', class: 'pf-btn go', onclick: () => wearLook(k, p.name) }, 'Wear this look'), ME.look_saved && !wearing ? h('button', { type: 'button', class: 'pf-btn', onclick: restoreLook }, 'Back to my look') : null),
      h('p', { class: 'pf-hint', text: 'Only colours and styling. Your own look is saved first.' })));
  }
  if (p.apps) {
    const list = h('ul', { class: 'wz-list' });
    const have = new Set((FRIEND.installed || []));
    for (const a of p.apps) list.append(h('li', { class: 'pf-item' },
      h('div', { class: 'wz-main' }, h('b', { text: a.name }, a.uses ? h('span', { class: 'pf-uses', text: 'uses a lot' }) : null), h('small', { text: a.summary })),
      FRIEND.preview ? null : have.has(a.id) ? h('span', { class: 'pf-have' }, 'You have it') : h('a', { class: 'pf-chip on', href: `/wizard-os-home/store/index.html?app=${encodeURIComponent(a.store_id || a.id)}` }, 'Get')));
    v.append(h('section', { class: 'wz-sec' }, h('h2', { class: 'wz-sec-h' }, 'Apps', h('span', { class: 'wz-count', text: String(p.apps.length) })), p.apps.length ? list : h('p', { class: 'pf-hint', text: 'No App Store apps shared.' })));
  }
  if (!FRIEND.preview && f.id) v.append(h('div', { class: 'pf-publish' }, h('button', { type: 'button', class: 'pf-btn danger', onclick: () => removeFriend(f) }, `Remove ${f.name}`)));
}
// "Get" is a plain same-origin link to the Store page for that app: inside Wizard the shell's link guard opens it
// beside this window (never inside it); standalone it just navigates.

/* ---------- Wear a look: skin id + CSS through the shell's own My skin; undo restores both ---------- */
async function wearLook(k, who) {
  try {
    const f = await localFacts();
    // The server keeps the FIRST saved look, so trying several looks in a row still returns to yours.
    ME = await api('api/look/backup', 'POST', { skin: f.skin.id, css: f.skin.css, friend: who, friend_skin: k.name });
    await putMySkin(k.css || '');
    applySkin(k.id);
    say(`Wearing ${who}'s look.`, 'note'); render();
  } catch (e) { say(e.message, 'error'); }
}
async function restoreLook() {
  try {
    const b = await api('api/look/restore', 'POST', {});
    await putMySkin(b.css || '');
    applySkin(b.skin);
    ME = await api('api/me'); say('Back to your look.', 'note'); render();
  } catch (e) { say(e.message, 'error'); }
}
async function putMySkin(css) {
  const put = !!String(css || '').trim();   // nothing to keep = reset My skin to its template
  const r = await fetch('/wizard/v1/my-skin', { method: put ? 'PUT' : 'DELETE', credentials: 'same-origin', headers: put ? { 'Content-Type': 'text/css' } : {}, body: put ? css : undefined });
  if (!r.ok) throw new Error('Could not change your look on this box.');
  try { await shell()?.WosMySkin?.refresh?.(); } catch (_) {}
}
function applySkin(id) {
  const S = shell()?.WosSkin;
  if (S?.list?.some(s => s.id === id)) S.set(id);
  else try { localStorage.setItem('wos.skin', id); } catch (_) {}
}

/* ---------- Try on a build (box helper builds and runs it beside your shell) ---------- */
async function tryStatus() {
  try { TRY = await api(TRYON + 'status'); } catch (_) { TRY = null; }
  renderTry();
  clearTimeout(tryTimer);
  if (TRY && ['queued', 'building', 'starting'].includes(TRY.state)) tryTimer = setTimeout(tryStatus, 2500);
  if (TAB === 'friend' && FRIEND && !FRIEND.preview) renderFriend();
}
async function tryOn(b, who) {
  try { TRY = await api(TRYON + 'start', 'POST', { commit: b.commit, label: `${who}'s build` }); say(`Getting ${who}'s build ready…`, 'note'); tryStatus(); }
  catch (e) { say(e.message.includes('404') || e.message.includes('Not Found') ? 'Trying on builds is not set up on this box yet.' : e.message, 'error'); }
}
async function stopTry() {
  try { TRY = await api(TRYON + 'stop', 'POST', {}); say('Stopped. You are only on your own build.', 'note'); tryStatus(); } catch (e) { say(e.message, 'error'); }
}
function renderTry() {
  const t = $('tryon'), on = TRY && TRY.state && TRY.state !== 'idle';
  t.hidden = !on; t.replaceChildren();
  if (!on) return;
  const label = TRY.label || 'a build';
  t.append(h('div', { class: 'wz-main' }, h('b', { text: TRY.state === 'ready' ? `Trying on ${label}` : TRY.state === 'failed' ? `Couldn't start ${label}` : `Getting ${label} ready…` }),
    h('small', { text: TRY.state === 'failed' ? TRY.error || '' : TRY.state === 'ready' ? 'Opens beside your Wizard. Yours is unchanged.' : TRY.step || '' })),
    TRY.state === 'ready' ? h('a', { class: 'pf-btn go', href: TRY.url, target: '_blank', rel: 'noopener' }, 'Open') : null,
    h('button', { type: 'button', class: 'pf-btn', onclick: stopTry }, TRY.state === 'failed' ? 'Dismiss' : 'Stop'));
}

/* ---------- frame ---------- */
function show(tab) {
  TAB = tab;
  for (const id of ['me', 'friends', 'friend']) $('view-' + id).hidden = id !== tab;
  for (const b of document.querySelectorAll('.pf-tabs button')) b.setAttribute('aria-current', b.dataset.tab === (tab === 'friend' ? (FRIEND?.preview ? 'me' : 'friends') : tab) ? 'page' : 'false');
  $('title').textContent = tab === 'friends' ? 'Friends' : tab === 'friend' ? (FRIEND?.friend?.name || FRIEND?.profile?.name || 'Friend') : 'Profile';
  render(); $('scroll').scrollTop = 0;
}
function render() {
  if (!ME) return;
  $('req-dot').hidden = !ME.requests.length;
  $('sub').textContent = TAB === 'me' ? (ME.snapshot ? `Published ${ago(ME.snapshot.published_at)}` : 'Not published') : '';
  if (TAB === 'me') renderMe(); else if (TAB === 'friends') renderFriends(); else renderFriend();
}
for (const b of document.querySelectorAll('.pf-tabs button')) b.onclick = () => show(b.dataset.tab);
window.__wizardCloseOverlay = () => { if (TAB === 'friend') { show(FRIEND?.preview ? 'me' : 'friends'); return true; } return false; };

(async () => {
  try {
    ME = await api('api/me');
    const inst = await getJSON('/wizard-os-home/store-data/wizard/v1/installed-apps');
    const installed = (inst?.wam || []).map(a => a.id);
    const origOpen = openFriend;
    openFriend = async f => { await origOpen(f); if (FRIEND) { FRIEND.installed = installed; if (TAB === 'friend') renderFriend(); } };
    show('me'); tryStatus();
  } catch (e) { say(e.message, 'error'); }
})();
document.addEventListener('visibilitychange', () => { if (!document.hidden && ME) api('api/me').then(m => { ME = m; render(); }).catch(() => {}); });

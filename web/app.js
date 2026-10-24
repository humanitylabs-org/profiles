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
  const S = shell()?.WosSkin;
  const skinId = S?.current || (() => { try { return localStorage.getItem('wos.skin') || 'nebula'; } catch (_) { return 'nebula'; } })();
  const skinName = S?.list?.find(s => s.id === skinId)?.name || skinId;
  return { build, apps: wam.map(a => ({ id: a.id, repo: a.repo, name: a.name || a.id })), skin: { id: skinId, name: skinName, css } };
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
  const box = h('form', { class: 'pf-edit', onsubmit: async e => { e.preventDefault(); try { ME = await api('api/me', 'PUT', { name: n.value, bio: b.value }); render(); } catch (err) { say(err.message, 'error'); } } });
  const n = h('input', { class: 'wz-input', maxlength: 60, placeholder: 'Your name', 'aria-label': 'Your name' }); n.value = ME.name;
  const b = h('input', { class: 'wz-input', maxlength: 280, placeholder: 'A line about you (optional)', 'aria-label': 'About you' }); b.value = ME.bio;
  box.append(n, b, h('div', { class: 'pf-row-acts' }, h('button', { type: 'submit', class: 'pf-btn go' }, 'Save'), h('button', { type: 'button', class: 'pf-btn', onclick: render }, 'Cancel')));
  $('view-me').querySelector('.pf-who').replaceWith(box); n.focus();
}
function partBody(part, snap) {
  if (part === 'build') {
    const b = snap?.build;
    if (!snap) return h('small', {}, 'Publish to share it.');
    if (!b) return h('small', {}, 'This build is not public code yet, so it stays private.');
    return h('small', {}, `${b.name} · ${b.changes.length} change${b.changes.length === 1 ? '' : 's'} of your own`);
  }
  if (part === 'skin') return h('small', {}, snap ? snap.skin.name + (snap.skin.css ? ' with your own touches' : '') : 'Publish to share it.');
  return h('small', {}, snap ? `${snap.apps.length - ME.hidden.filter(id => snap.apps.some(a => a.id === id)).length} of ${snap.apps.length} App Store apps shown` : 'Publish to share them.');
}
function renderMe() {
  const v = $('view-me'); v.replaceChildren();
  const snap = ME.snapshot;
  v.append(h('div', { class: 'pf-who' },
    h('div', { class: 'pf-avatar', 'aria-hidden': 'true', text: (ME.name || '?').trim().charAt(0).toUpperCase() || '?' }),
    h('div', { class: 'wz-main' }, h('b', { text: ME.name || 'Add your name' }), h('small', { text: ME.bio || (ME.you ? ME.you : 'Friends see this name') })),
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
      h('div', { class: 'wz-main' }, h('b', { text: r.name }), h('small', { text: `${r.login} · wants to be friends` })),
      h('button', { type: 'button', class: 'pf-chip on', onclick: () => addForm(r) }, 'Add back'),
      h('button', { type: 'button', class: 'pf-chip', onclick: async () => { ME = await api('api/requests/dismiss', 'POST', { login: r.login }); render(); } }, 'Ignore')));
    v.append(h('section', { class: 'wz-sec' }, h('h2', { class: 'wz-sec-h' }, 'Requests'), reqs));
  }
  const list = h('ul', { class: 'wz-list' });
  for (const f of ME.friends) list.append(h('li', {},
    h('button', { type: 'button', class: 'wz-row', onclick: () => openFriend(f) },
      h('span', { class: 'pf-avatar sm', 'aria-hidden': 'true', text: (f.name || '?').charAt(0).toUpperCase() }),
      h('span', { class: 'wz-main' }, h('b', { text: f.name }), h('small', { text: f.login })), h('span', { class: 'pf-go', 'aria-hidden': 'true' }, '›'))));
  v.append(h('section', { class: 'wz-sec' }, h('h2', { class: 'wz-sec-h' }, 'Friends', ME.friends.length ? h('span', { class: 'wz-count', text: String(ME.friends.length) }) : null),
    ME.friends.length ? list : h('div', { class: 'wz-empty' }, h('div', { class: 'wz-tile', 'aria-hidden': 'true' }, '☺'), h('strong', {}, 'No friends yet'),
      h('p', {}, 'A friend is someone whose Wizard can reach yours over a private Tailscale connection. Add them with their Profiles link.'))));
  v.append(h('div', { class: 'pf-publish' }, h('button', { type: 'button', class: 'pf-btn go wide', onclick: () => addForm() }, 'Add a friend')));
  if (ME.link) {
    const copy = h('button', { type: 'button', class: 'pf-chip', onclick: async () => { try { await navigator.clipboard.writeText(`${ME.link}\n${ME.you}`); copy.textContent = 'Copied'; } catch (_) { say('Copy failed. Select the link instead.', 'error'); } } }, 'Copy');
    v.append(h('section', { class: 'wz-sec' }, h('h2', { class: 'wz-sec-h' }, 'Your link'),
      h('div', { class: 'pf-item' }, h('div', { class: 'wz-main' }, h('b', { class: 'pf-link', text: ME.link }), h('small', { text: ME.you ? `Send this and your login (${ME.you}) to a friend.` : 'Send this to a friend.' })), copy),
      h('p', { class: 'pf-hint', text: 'This address only answers friend requests and your shared profile. Your Wizard and apps stay closed to them.' })));
  }
}
function addForm(req) {
  const v = $('view-friends');
  const f = h('form', { class: 'pf-edit', onsubmit: async e => {
    e.preventDefault(); const b = f.querySelector('button[type=submit]'); b.disabled = true;
    try { const out = await api('api/friends', 'POST', { address: a.value, login: l.value, name: n.value }); ME = out.me; render(); say(out.hello === 'sent' ? `${out.friend.name} added. They'll see your request.` : `${out.friend.name} added. Their box didn't answer yet (${out.hello}).`, 'note'); }
    catch (err) { say(err.message, 'error'); b.disabled = false; }
  } });
  const a = h('input', { class: 'wz-input', required: true, placeholder: 'Their Profiles link, e.g. https://their-box.ts.net:8840/profiles/', 'aria-label': 'Their Profiles link' });
  const l = h('input', { class: 'wz-input', required: true, placeholder: 'Their Tailscale login, e.g. james@example.com', 'aria-label': 'Their Tailscale login', autocomplete: 'off' });
  const n = h('input', { class: 'wz-input', placeholder: 'Name (optional)', 'aria-label': 'Name', maxlength: 60 });
  if (req) { l.value = req.login; n.value = req.name; }
  f.append(h('h2', { class: 'wz-sec-h' }, req ? `Add ${req.name} back` : 'Add a friend'), a, l, n,
    h('p', { class: 'pf-hint', text: 'Their login is how your box knows it is really them when they visit. They add you the same way.' }),
    h('div', { class: 'pf-row-acts' }, h('button', { type: 'submit', class: 'pf-btn go' }, 'Add'), h('button', { type: 'button', class: 'pf-btn', onclick: render }, 'Cancel')));
  v.prepend(f); a.focus();
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
  v.append(h('div', { class: 'pf-who' }, h('div', { class: 'pf-avatar', 'aria-hidden': 'true', text: (p.name || '?').charAt(0).toUpperCase() }),
    h('div', { class: 'wz-main' }, h('b', { text: p.name }), h('small', { text: p.bio || (p.published_at ? `Updated ${ago(p.published_at)}` : 'Nothing shared yet') }))));
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
  const r = await fetch('/wizard/v1/my-skin', { method: css ? 'PUT' : 'DELETE', credentials: 'same-origin', headers: css ? { 'Content-Type': 'text/css' } : {}, body: css || undefined });
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

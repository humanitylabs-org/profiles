'use strict';
/* Profiles view. Talks to this app's own API (relative paths) and, because it runs on the Wizard origin, reads what
 * this Wizard already knows: its build, its installed apps, the skin it wears and the owner's My skin. Every time the
 * view opens it hands those facts to the app, which shares again only when something really changed. No Publish step.
 * Owner text is rendered with textContent only; app icons come from the shell's own sigil set (core/sigils.js). */
const $ = id => document.getElementById(id);
const TRYON = '/wizard-os-home/tryon/api/';
const LEVEL = { private: 'Only you', friends: 'Friends', public: 'Everyone' };
const LEVEL_ICON = {
  private: '<svg viewBox="0 0 24 24" aria-hidden="true"><rect x="5.5" y="10.5" width="13" height="9" rx="2"/><path d="M8.5 10.5V8a3.5 3.5 0 0 1 7 0v2.5"/></svg>',
  friends: '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="9" cy="9" r="3"/><circle cx="17" cy="10" r="2.4"/><path d="M3.5 19c.9-3 3-4.6 5.5-4.6s4.6 1.6 5.5 4.6M15 15.2c2.6-.4 4.6 1 5.5 3.8"/></svg>',
  public: '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="8.5"/><path d="M3.5 12h17M12 3.5c2.4 2.4 3.6 5.2 3.6 8.5s-1.2 6.1-3.6 8.5c-2.4-2.4-3.6-5.2-3.6-8.5s1.2-6.1 3.6-8.5z"/></svg>',
};
let ME = null, TAB = 'me', FRIEND = null, TRY = null, tryTimer = 0, busy = false, REPORT = null, INSTALLED = [];

function h(tag, attrs = {}, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v == null || v === false) continue;
    if (k === 'class') el.className = v; else if (k === 'text') el.textContent = v;
    else if (k === 'html') el.innerHTML = v;            // only ever our own constant SVG or WizSigil's escaped markup
    else if (k.startsWith('on')) el.addEventListener(k.slice(2), v); else el.setAttribute(k, v === true ? '' : v);
  }
  for (const c of kids.flat()) if (c != null && c !== false) el.append(c.nodeType ? c : document.createTextNode(String(c)));
  return el;
}
function say(text, kind = '') { const s = $('status'); s.classList.toggle('wz-sr', !kind); s.dataset.kind = kind; s.textContent = text; if (kind) { clearTimeout(say.t); say.t = setTimeout(() => { s.textContent = ''; s.classList.add('wz-sr'); }, 5000); } }
async function api(path, method = 'GET', body) {
  const r = await fetch(path, { method, cache: 'no-store', credentials: 'same-origin', ...(body === undefined ? {} : { headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }) });
  let j = {}; try { j = await r.json(); } catch (_) {}
  if (!r.ok) throw new Error(j.error || j.message || `Something went wrong (${r.status}).`);
  return j;
}
const ago = iso => { if (!iso) return ''; const s = (Date.now() - Date.parse(iso)) / 1000; if (!(s >= 0)) return ''; if (s < 90) return 'just now'; if (s < 5400) return Math.round(s / 60) + ' min ago'; if (s < 129600) return Math.round(s / 3600) + ' h ago'; return Math.round(s / 86400) + ' days ago'; };
const shell = () => { try { return parent !== window ? parent : null; } catch (_) { return null; } };
const shortNpub = n => n ? n.slice(0, 14) + '…' + n.slice(-8) : '';
async function copy(btn, text, label) {
  label = label || btn.textContent;
  try { await navigator.clipboard.writeText(text); btn.textContent = 'Copied'; setTimeout(() => { btn.textContent = label; }, 1600); }
  catch (_) { say('Copy failed. Long-press the ID instead.', 'error'); }
}

/* ---------- app groups: the same kinds, order and system ring as the Wizard app selector (core/app-kinds.js) ---------- */
const KINDS = [['view', 'Apps'], ['service', 'Agent apps'], ['agent', 'Agents'], ['external', 'Connectors']];
// Same defaults as the shell; the shell's own rule wins when Profiles runs inside Wizard.
const SYSTEM_IDS = new Set(['wizard', 'setup', 'files', 'notifications', 'transcriber', 'browser', 'secret-drop', 'wizard-chatgpt', 'wizard-claude']);
function isSystemApp(a) {
  for (const w of [shell(), (() => { try { return top; } catch (_) { return null; } })()]) { try { const K = w?.WosAppKinds; if (K) return !!K.isSystem({ id: a.id, system: a.system }); } catch (_) {} }
  return SYSTEM_IDS.has(a.id);
}
const CONNECTOR_IDS = new Set(['wizard-chatgpt', 'wizard-claude', 'wizard-tinfoil', 'wizard-cloudflare', 'wizard-monarch', 'wizard-simplefin', 'wizard-teller']);
function isConnectorApp(a) {
  for (const w of [shell(), (() => { try { return top; } catch (_) { return null; } })()]) { try { const K = w?.WosAppKinds; if (K) return !!K.isConnector({ id: a.id }); } catch (_) {} }
  return CONNECTOR_IDS.has(a.id);
}
const SYS_KEY = 'profiles.hideSystem';
const hideSystem = () => { try { return localStorage.getItem(SYS_KEY) === '1'; } catch (_) { return false; } };
// Apps grouped by kind; system apps lead each group in purple. `tile(a)` builds one tile.
function appGroups(apps, tile) {
  const wrap = h('div', { class: 'pf-groups' });
  const sysCount = apps.filter(a => a.system).length, folded = hideSystem() && sysCount > 0;
  for (const [type, label] of KINDS) {
    const list = apps.filter(a => (a.type || 'service') === type)
      .sort((x, y) => (!!y.system - !!x.system) || x.name.localeCompare(y.name, undefined, { sensitivity: 'base' }));
    if (!list.length) continue;
    const shown = folded ? list.filter(a => !a.system) : list;
    const grid = h('div', { class: 'pf-grid' }, shown.map(tile));
    const hiddenSys = list.length - shown.length;
    wrap.append(h('section', { class: 'pf-group' },
      h('h3', { class: 'pf-group-h' }, label, h('span', { text: String(list.length) })),
      shown.length ? grid : null,
      hiddenSys && !shown.length ? h('p', { class: 'pf-hint', text: `${hiddenSys} system app${hiddenSys === 1 ? '' : 's'}` }) : null));
  }
  if (sysCount) wrap.append(h('button', { type: 'button', class: 'pf-sys-toggle', onclick: () => { try { localStorage.setItem(SYS_KEY, folded ? '0' : '1'); } catch (_) {} render(); } },
    h('span', { class: 'pf-sys-dot', 'aria-hidden': 'true' }), folded ? `Show ${sysCount} system app${sysCount === 1 ? '' : 's'}` : 'Hide system apps'));
  return wrap;
}

/* ---------- app icons: the same sigils the Wizard dock and Home use ---------- */
function appIcon(a, cls = 'pf-ic') {
  const S = window.WizSigil || shell()?.WizSigil;
  if (S) { const w = h('span', { html: S.box('span', cls, { id: a.store_id || a.id, name: a.name }) }); return w.firstElementChild; }
  return h('span', { class: cls + ' pf-ic-plain', 'aria-hidden': 'true', text: (a.name || a.id || '?').charAt(0).toUpperCase() });
}
function avatar(p, cls = '') {
  return p?.picture ? h('img', { class: 'pf-avatar ' + cls, src: p.picture, alt: '' })
    : h('span', { class: 'pf-avatar ' + cls, 'aria-hidden': 'true', text: (p?.name || '?').trim().charAt(0).toUpperCase() || '?' });
}

/* ---------- what this Wizard runs (read on the Wizard origin) ---------- */
async function getJSON(url) { try { const r = await fetch(url, { cache: 'no-store', credentials: 'same-origin' }); return r.ok ? await r.json() : null; } catch (_) { return null; } }
async function getText(url) { try { const r = await fetch(url, { cache: 'no-store', credentials: 'same-origin' }); return r.ok ? await r.text() : ''; } catch (_) { return ''; } }
async function localFacts() {
  const [rel, inst, css] = await Promise.all([getJSON('/wizard-os-home/my-release.json'), getJSON('/wizard-os-home/store-data/wizard/v1/installed-apps'), getText('/wizard/v1/my-skin')]);
  const wam = Array.isArray(inst?.wam) ? inst.wam : [];
  INSTALLED = wam.map(a => a.id);
  const shellApp = wam.find(a => a.id === 'wizard-ux');
  const build = rel?.build ? { commit: rel.build, name: rel.name || 'My Wizard', base: rel.base?.ref || '', changes: rel.changes || [], built_at: rel.built_at || '' }
    : shellApp?.commit ? { commit: shellApp.commit, name: 'Wizard', base: '', changes: [], built_at: '' } : null;
  const sk = currentSkin();
  // Kind by the app selector's rule: a connector, else an app with a screen, else an agent app.
  const screen = new Map((Array.isArray(inst?.shell) ? inst.shell : []).map(x => [x.id, !!x.url]));
  const kindOf = a => isConnectorApp(a) ? 'external' : screen.get(a.id) ? 'view' : 'service';
  return { build, apps: wam.map(a => ({ id: a.id, repo: a.repo, name: a.name || a.id, system: isSystemApp(a), type: kindOf(a) })), skin: { id: sk.id, name: sk.name, css } };
}
const SKIN_NAMES = { nebula: 'Nebula', grove: 'Grove', tide: 'Tide', ember: 'Ember', signal: 'Signal', obsidian: 'Dark', 'obsidian-light': 'Light', landscapes: 'Landscapes' };
function currentSkin() {
  // What Wizard wears right now: the shell's picker (parent or top), then the skin pushed into this frame, then this
  // device's saved choice.
  let S = null;
  for (const w of [shell(), (() => { try { return top !== window ? top : null; } catch (_) { return null; } })()]) { try { if (w?.WosSkin) { S = w.WosSkin; break; } } catch (_) {} }
  let id = S?.current || '';
  if (!id && window.WizardTheme?.connected) id = window.WizardTheme.current?.skin || '';
  if (!id) { try { id = localStorage.getItem('wos.skin') || ''; } catch (_) {} }
  id = id || 'nebula';
  return { id, name: S?.list?.find(x => x.id === id)?.name || SKIN_NAMES[id] || id };
}
// Every open: give the app what this Wizard has now. It only shares again when something changed.
let APART = false;   // opened on its own address, so it can't read what this Wizard runs
async function refresh() {
  try {
    const f = await localFacts();
    APART = !f.build && !f.apps.length;
    if (APART) { render(); return; }
    const out = await api('api/publish', 'POST', { build: f.build, skin: f.skin, apps: f.apps });
    ME = out.me; REPORT = out.report; render();
  } catch (e) { say(e.message, 'error'); }
}

/* ---------- photo: picked, squared and shrunk on this device, saved at once ---------- */
function squarePhoto(file) {
  return new Promise((resolve, reject) => {
    const img = new Image(), url = URL.createObjectURL(file);
    img.onload = () => {
      const side = Math.min(img.naturalWidth, img.naturalHeight), c = document.createElement('canvas');
      c.width = c.height = 192;
      c.getContext('2d').drawImage(img, (img.naturalWidth - side) / 2, (img.naturalHeight - side) / 2, side, side, 0, 0, 192, 192);
      URL.revokeObjectURL(url);
      let q = .82, out = c.toDataURL('image/jpeg', q);
      while (out.length > 50000 && q > .3) { q -= .12; out = c.toDataURL('image/jpeg', q); }
      out.length > 60000 ? reject(new Error('That photo is too detailed. Try another one.')) : resolve(out);
    };
    img.onerror = () => { URL.revokeObjectURL(url); reject(new Error("This device can't read that file. Pick a JPEG or PNG photo.")); };
    img.src = url;
  });
}
function pickPhoto() {
  const file = h('input', { type: 'file', accept: 'image/jpeg,image/png,image/webp,image/*', class: 'pf-file', onchange: () => {
    const f0 = file.files?.[0]; file.remove(); if (f0) cropPhoto(f0);
  } });
  document.body.append(file); file.click();
}
// Pick which part of the photo shows in the circle: drag to move, pinch or the slider to zoom. Then one square
// JPEG (192 px, under 60 KB) is made on this device and saved; the original never leaves it.
function cropPhoto(file) {
  const url = URL.createObjectURL(file), img = new Image();
  img.onerror = () => { URL.revokeObjectURL(url); say("This device can't read that file. Pick a JPEG or PNG photo.", 'error'); };
  img.onload = () => {
    const S = 280;                                   // the crop circle on screen
    const base = S / Math.min(img.naturalWidth, img.naturalHeight);
    let zoom = 1, x = 0, y = 0;                       // x, y: offset of the image centre from the circle centre (screen px)
    const view = h('canvas', { class: 'pf-crop-c', width: S * 2, height: S * 2, 'aria-label': 'Drag to move the photo, pinch to zoom' });
    const ctx = view.getContext('2d');
    const clamp = () => {
      const w = img.naturalWidth * base * zoom, hh = img.naturalHeight * base * zoom;
      x = Math.max(-(w - S) / 2, Math.min((w - S) / 2, x)); y = Math.max(-(hh - S) / 2, Math.min((hh - S) / 2, y));
    };
    const draw = () => {
      clamp(); const k = base * zoom, w = img.naturalWidth * k, hh = img.naturalHeight * k;
      ctx.setTransform(2, 0, 0, 2, 0, 0); ctx.clearRect(0, 0, S, S);
      ctx.drawImage(img, S / 2 + x - w / 2, S / 2 + y - hh / 2, w, hh);
    };
    const slider = h('input', { type: 'range', min: '1', max: '4', step: '0.01', value: '1', class: 'pf-zoom', 'aria-label': 'Zoom', oninput: () => { zoom = +slider.value; draw(); } });
    const pts = new Map(); let pinch = null;
    view.addEventListener('pointerdown', e => { view.setPointerCapture(e.pointerId); pts.set(e.pointerId, { x: e.clientX, y: e.clientY }); if (pts.size === 2) { const [a, b] = [...pts.values()]; pinch = { d: Math.hypot(a.x - b.x, a.y - b.y), z: zoom }; } });
    view.addEventListener('pointermove', e => {
      const p = pts.get(e.pointerId); if (!p) return;
      if (pts.size === 1) { x += e.clientX - p.x; y += e.clientY - p.y; }
      pts.set(e.pointerId, { x: e.clientX, y: e.clientY });
      if (pts.size === 2 && pinch) { const [a, b] = [...pts.values()]; zoom = Math.max(1, Math.min(4, pinch.z * Math.hypot(a.x - b.x, a.y - b.y) / pinch.d)); slider.value = String(zoom); }
      draw();
    });
    const up = e => { pts.delete(e.pointerId); if (pts.size < 2) pinch = null; };
    view.addEventListener('pointerup', up); view.addEventListener('pointercancel', up);
    view.addEventListener('wheel', e => { e.preventDefault(); zoom = Math.max(1, Math.min(4, zoom * (e.deltaY < 0 ? 1.08 : 1 / 1.08))); slider.value = String(zoom); draw(); }, { passive: false });
    const close = () => { URL.revokeObjectURL(url); sheet.remove(); };
    const save = h('button', { type: 'button', class: 'pf-btn go', onclick: async () => {
      save.disabled = true; save.textContent = 'Saving…';
      try {
        const out = document.createElement('canvas'); out.width = out.height = 192;
        const k = base * zoom, w = img.naturalWidth * k, hh = img.naturalHeight * k, C = S - 40, r = 192 / C;
        out.getContext('2d').drawImage(img, (S / 2 + x - w / 2 - 20) * r, (S / 2 + y - hh / 2 - 20) * r, w * r, hh * r);
        let q = .85, data = out.toDataURL('image/jpeg', q);
        while (data.length > 50000 && q > .3) { q -= .12; data = out.toDataURL('image/jpeg', q); }
        ME = await api('api/me', 'PUT', { picture: data }); close(); render(); say('Photo saved.', 'note');
      } catch (err) { say(err.message, 'error'); save.disabled = false; save.textContent = 'Use photo'; }
    } }, 'Use photo');
    const sheet = h('div', { class: 'pf-crop', role: 'dialog', 'aria-modal': 'true', 'aria-label': 'Choose what shows in your photo' },
      h('div', { class: 'pf-crop-card' },
        h('b', { text: 'Move and zoom' }), h('small', { text: 'Drag to move. Pinch or slide to zoom.' }),
        h('div', { class: 'pf-crop-stage' }, view, h('span', { class: 'pf-crop-ring', 'aria-hidden': 'true' })),
        slider,
        h('div', { class: 'pf-row-acts center' }, h('button', { type: 'button', class: 'pf-btn', onclick: close }, 'Cancel'), save)));
    document.body.append(sheet); draw(); save.focus();
  };
  img.src = url;
}

/* ---------- You ---------- */
function levelPicker(part, levels) {
  const cur = ME.visibility[part];
  return h('div', { class: 'pf-seg', role: 'radiogroup', 'aria-label': 'Who sees this' },
    levels.map(l => h('button', { type: 'button', role: 'radio', 'aria-checked': String(cur === l), class: cur === l ? 'on' : '', onclick: () => setLevel(part, l) },
      h('span', { class: 'pf-lv', html: LEVEL_ICON[l] }), LEVEL[l])));
}
async function setLevel(part, level) {
  if (busy || ME.visibility[part] === level) return; busy = true;
  try { ME = await api('api/me', 'PUT', { visibility: { [part]: level } }); render(); setTimeout(reloadMe, 4000); }
  catch (e) { say(e.message, 'error'); } finally { busy = false; }
}
async function reloadMe() { try { ME = await api('api/me'); render(); } catch (_) {} }
const hintFor = (part, yes, no) => ME.visibility[part] === 'private' ? no : yes;
function card(title, sub, level, body, hint) {
  return h('section', { class: 'pf-card' },
    h('div', { class: 'pf-card-h' }, h('div', { class: 'wz-main' }, h('b', { text: title }), sub ? h('small', { text: sub }) : null)),
    body, level, hint ? h('p', { class: 'pf-hint', text: hint }) : null);
}
function shareLine() {
  const n = ME.friends.length, pub = Object.entries(ME.visibility).some(([k, v]) => k !== 'card' && v === 'public');
  const anything = Object.entries(ME.visibility).some(([k, v]) => k !== 'card' && v !== 'private');
  if (!n && !pub) return anything ? 'Add a friend on the Friends tab to start sharing.' : 'Your look, build and apps are only yours right now. Friends you add see your name and photo.';
  const who = [n ? `${n} friend${n === 1 ? '' : 's'}` : '', pub ? 'everyone with your Nostr ID' : ''].filter(Boolean).join(' and ');
  if (ME.sync && !ME.sync.reached && ME.sync.stored) return `Shared with ${who}. Couldn't reach Nostr just now; your Wizard will try again.`;
  return `Shared with ${who}${ME.shared_at ? ` · up to date ${ago(ME.shared_at)}` : ''}. Changes share by themselves.`;
}
function renderMe() {
  const v = $('view-me'); v.replaceChildren();
  const snap = ME.snapshot;
  // Who you are
  v.append(h('div', { class: 'pf-who' },
    h('button', { type: 'button', class: 'pf-face', 'aria-label': ME.picture ? 'Change photo' : 'Add a photo', onclick: pickPhoto }, avatar(ME, 'lg'), h('span', { class: 'pf-cam', 'aria-hidden': 'true', html: '<svg viewBox="0 0 24 24"><path d="M4 8.5h3l1.6-2.5h6.8L17 8.5h3v10H4z"/><circle cx="12" cy="13" r="3.3"/></svg>' })),
    h('div', { class: 'wz-main' }, h('b', { text: ME.name || 'Add your name' }), h('small', { text: ME.bio || (ME.picture ? 'Your Wizard profile' : 'Tap the circle to add a photo') })),
    h('button', { type: 'button', class: 'pf-btn', onclick: editName }, 'Edit')));
  v.append(idCard());
  if (APART) v.append(h('div', { class: 'pf-banner' }, h('b', { text: "Profiles can't see your Wizard yet. " }),
    'It opened on an address of its own, so it can\'t read your look, build and apps. Ask your Wizard: "Put Profiles on my Wizard\'s own address." Friends and your Nostr ID already work.'));
  v.append(h('p', { class: 'pf-share', text: shareLine() }));
  // Name and photo
  v.append(card('Name and photo', 'Friends always see who you are', levelPicker('card', ['friends', 'public']), null));
  // Look
  const live = currentSkin(), sk = snap?.skin;
  v.append(card('Look', sk ? sk.name + (sk.css ? ' + your own touches' : '') : live.name, levelPicker('skin', ['private', 'friends', 'public']),
    h('div', { class: 'pf-skin' }, h('span', { class: 'pf-swatch', 'aria-hidden': 'true' }), h('span', { text: `The skin you wear now${sk?.css ? ', with your My skin changes' : ''}.` })),
    hintFor('skin', 'Friends can wear it for a while and switch back.', 'Share it and friends can wear it for a while.')));
  // Build
  const b = snap?.build;
  v.append(card('Build', b ? `${b.name} · ${b.changes.length} change${b.changes.length === 1 ? '' : 's'}` : 'Not shareable yet', levelPicker('build', ['private', 'friends']),
    b ? (b.changes.length ? h('ul', { class: 'pf-changes' }, b.changes.slice(0, 3).map(c => h('li', { text: c.title })), b.changes.length > 3 ? h('li', { class: 'more', text: `and ${b.changes.length - 3} more` }) : null) : null)
      : h('p', { class: 'pf-hint', text: "This build isn't public code yet, so nobody else could run it." }),
    hintFor('build', 'Friends can try it on beside their own Wizard.', 'Share it with friends and they can try it on. Never shared with everyone.')));
  // Apps
  const apps = snap?.apps || [];
  const grid = appGroups(apps, a => {
    const off = ME.hidden.includes(a.id);
    return h('button', { type: 'button', class: 'pf-tile' + (off ? ' off' : '') + (a.system ? ' sys' : ''), 'aria-pressed': String(!off), title: off ? 'Hidden. Tap to show.' : 'Shown. Tap to hide.', onclick: () => toggleHidden(a.id) },
      appIcon(a), h('span', { class: 'pf-tile-n', text: a.name }), off ? h('span', { class: 'pf-tile-x', text: 'Hidden' }) : null);
  });
  const kept = (REPORT?.kept_private || []).filter(x => x.part === 'apps').length;
  const shown = apps.length - apps.filter(a => ME.hidden.includes(a.id)).length;
  v.append(card('Apps', `${shown} of ${apps.length} App Store apps`, levelPicker('apps', ['private', 'friends', 'public']),
    apps.length ? grid : h('p', { class: 'pf-hint', text: APART ? 'Not readable from this address yet.' : 'Reading your apps…' }),
    `Tap an app to hide or show it.${kept ? ` ${kept} app${kept === 1 ? '' : 's'} you built or keep private never show.` : ' Apps you built yourself never show.'}`));
  v.append(h('div', { class: 'pf-row-acts center' },
    h('button', { type: 'button', class: 'pf-btn', onclick: () => preview('friend') }, 'See what friends see'),
    h('button', { type: 'button', class: 'pf-btn', onclick: () => preview('public') }, 'See what everyone sees')));
}
function idCard() {
  const cp = h('button', { type: 'button', class: 'pf-chip on', onclick: e => copy(e.currentTarget, ME.npub, 'Copy') }, 'Copy');
  const safe = !!ME.backed_up_at;
  return h('div', { class: 'pf-id-wrap' },
    h('div', { class: 'pf-id' }, h('div', { class: 'wz-main' }, h('small', { text: 'Your Nostr ID' }), h('code', { class: 'pf-npub', title: ME.npub, text: shortNpub(ME.npub) })), cp),
    h('button', { type: 'button', class: 'pf-safe' + (safe ? ' ok' : ''), onclick: () => identitySheet() },
      h('span', { class: 'pf-safe-ic', 'aria-hidden': 'true', html: safe ? ICON.shieldOk : ICON.shield }),
      h('span', { class: 'wz-main' }, h('b', { text: safe ? 'Identity backed up' : 'Back up your identity' }),
        h('small', { text: safe ? `Backed up ${ago(ME.backed_up_at)}` : 'Not backed up yet. Tap to save your key.' })),
      h('span', { class: 'pf-go', 'aria-hidden': 'true', text: '›' })));
}
const ICON = {
  shield: '<svg viewBox="0 0 24 24"><path d="M12 3l7 3v5.5c0 4.4-3 8.1-7 9.5-4-1.4-7-5.1-7-9.5V6z"/><path d="M12 8v4.5M12 15.6v.1"/></svg>',
  shieldOk: '<svg viewBox="0 0 24 24"><path d="M12 3l7 3v5.5c0 4.4-3 8.1-7 9.5-4-1.4-7-5.1-7-9.5V6z"/><path d="M8.6 12.2l2.3 2.3 4.6-4.7"/></svg>',
  key: '<svg viewBox="0 0 24 24"><circle cx="8" cy="15" r="4"/><path d="M11 12l8-8M16 7l2.5 2.5M14 9l2 2"/></svg>',
};
/* ---------- identity backup: a password-locked copy of your Nostr key (NIP-49, opens in other Nostr apps too) ---------- */
function sheet(label, ...kids) {
  const close = () => { el.remove(); document.removeEventListener('keydown', esc); };
  const esc = e => { if (e.key === 'Escape') close(); };
  const el = h('div', { class: 'pf-crop pf-sheet', role: 'dialog', 'aria-modal': 'true', 'aria-label': label, onclick: e => { if (e.target === el) close(); } },
    h('div', { class: 'pf-crop-card pf-sheet-card' }, h('span', { class: 'pf-grabber', 'aria-hidden': 'true' }),
      h('button', { type: 'button', class: 'pf-x', 'aria-label': 'Close', onclick: () => close(), html: '<svg viewBox="0 0 24 24"><path d="M6 6l12 12M18 6L6 18"/></svg>' }), ...kids));
  document.addEventListener('keydown', esc);
  document.body.append(el);
  return { el, close, card: el.firstChild };
}
function pwField(placeholder, auto) {
  const i = h('input', { class: 'wz-input', type: 'password', placeholder, autocomplete: auto, minlength: 10, maxlength: 200, 'aria-label': placeholder });
  const eye = h('button', { type: 'button', class: 'pf-eye', 'aria-label': 'Show password', onclick: () => { const s = i.type === 'password'; i.type = s ? 'text' : 'password'; eye.textContent = s ? 'Hide' : 'Show'; } }, 'Show');
  return { input: i, el: h('div', { class: 'pf-pw' }, i, eye) };
}
function identitySheet() {
  const sh = sheet('Back up your identity');
  const err = h('p', { class: 'pf-err', role: 'alert' });
  const pw = pwField('Choose a password', 'new-password'), pw2 = pwField('Type it again', 'new-password');
  const go = h('button', { type: 'submit', class: 'pf-btn go wide' }, 'Make my backup');
  const form = h('form', { class: 'pf-sheet-form', novalidate: true, onsubmit: async e => {
    e.preventDefault(); err.textContent = '';
    if (pw.input.value.length < 10) { err.textContent = 'Use at least 10 characters.'; return pw.input.focus(); }
    if (pw.input.value !== pw2.input.value) { err.textContent = "Those passwords don't match."; return pw2.input.focus(); }
    go.disabled = true; go.textContent = 'Locking…';
    try { const r = await api('api/identity/backup', 'POST', { password: pw.input.value }); pw.input.value = pw2.input.value = ''; savedStep(sh, r.backup, r.npub); }
    catch (x) { err.textContent = x.message; go.disabled = false; go.textContent = 'Make my backup'; }
  } }, pw.el, pw2.el, err,
    h('p', { class: 'pf-warn soft', text: "Nobody can reset this password, not even your Wizard. Keep it with the backup in your password manager." }), go);
  sh.card.append(
    h('span', { class: 'pf-sheet-ic', 'aria-hidden': 'true', html: ICON.key }),
    h('b', { text: 'Back up your identity' }),
    h('p', { class: 'pf-sheet-p', text: 'Your Nostr ID is how friends know you. This makes a copy of its secret key, locked with a password only you know, so you can bring the same ID to a new Wizard.' }),
    form,
    h('p', { class: 'pf-sheet-fine' }, 'Already have a backup? ', h('button', { type: 'button', class: 'pf-link-btn inline', onclick: () => { sh.close(); restoreSheet(); } }, 'Restore it')));
  pw.input.focus();
}
function savedStep(sh, code, npub) {
  const file = () => {
    const text = `Wizard Profiles identity backup\nNostr ID: ${npub}\nMade: ${new Date().toISOString().slice(0, 10)}\n\nLocked with your password (NIP-49). To restore: Profiles > Back up your identity > Restore.\n\n${code}\n`;
    const a = h('a', { href: 'data:text/plain;charset=utf-8,' + encodeURIComponent(text), download: `wizard-identity-${npub.slice(5, 13)}.txt` });
    document.body.append(a); a.click(); a.remove();
  };
  const done = h('button', { type: 'button', class: 'pf-btn go wide', disabled: true, onclick: async () => {
    try { ME = await api('api/identity/confirm', 'POST', {}); render(); sh.close(); say('Identity backed up.', 'note'); } catch (x) { say(x.message, 'error'); }
  } }, 'Done');
  const tick = h('input', { type: 'checkbox', onchange: () => { done.disabled = !tick.checked; } });
  sh.card.replaceChildren(sh.card.querySelector('.pf-x'),
    h('span', { class: 'pf-sheet-ic ok', 'aria-hidden': 'true', html: ICON.shieldOk }),
    h('b', { text: 'Your backup is ready' }),
    h('p', { class: 'pf-sheet-p', text: "Save it in your password manager, or anywhere off this server. You'll need your password to restore it." }),
    h('code', { class: 'pf-backup', text: code }),
    h('div', { class: 'pf-pair' },
      h('button', { type: 'button', class: 'pf-btn', onclick: e => copy(e.currentTarget, code, 'Copy') }, 'Copy'),
      h('button', { type: 'button', class: 'pf-btn', onclick: e => { file(); e.currentTarget.textContent = 'Saved'; } }, 'Save as file')),
    h('label', { class: 'pf-tick' }, tick, h('span', { text: 'I saved it, and I know the password' })),
    done);
}
function restoreSheet() {
  const sh = sheet('Restore your identity');
  const err = h('p', { class: 'pf-err', role: 'alert' });
  const code = h('textarea', { class: 'wz-input pf-code pf-paste', rows: 3, placeholder: 'Paste your backup (ncryptsec1…)', 'aria-label': 'Your backup', autocomplete: 'off', spellcheck: 'false' });
  const pick = h('input', { type: 'file', accept: '.txt,text/plain', class: 'pf-file', onchange: async () => {
    const f = pick.files?.[0]; if (!f) return; const t = await f.text(); const m = t.match(/ncryptsec1[0-9a-z]+/i); code.value = m ? m[0] : ''; if (!m) err.textContent = "That file doesn't hold a backup."; pick.value = '';
  } });
  const pw = pwField('Backup password', 'current-password');
  const go = h('button', { type: 'submit', class: 'pf-btn go wide' }, 'Restore');
  let armed = false;
  const form = h('form', { class: 'pf-sheet-form', novalidate: true, onsubmit: async e => {
    e.preventDefault(); err.textContent = '';
    if (!code.value.trim()) { err.textContent = 'Paste your backup or pick the file first.'; return code.focus(); }
    if (!armed) { armed = true; go.textContent = 'Yes, switch to that ID'; go.classList.add('warn'); warn.hidden = false; return; }
    go.disabled = true; go.textContent = 'Unlocking…';
    try {
      const r = await api('api/identity/restore', 'POST', { backup: code.value, password: pw.input.value }); pw.input.value = '';
      ME = r.me; render(); sh.close(); say(r.changed ? 'Restored. This Wizard now uses that Nostr ID.' : 'That backup is already this ID. Nothing changed.', 'note');
    } catch (x) { err.textContent = x.message; go.disabled = false; go.textContent = 'Yes, switch to that ID'; }
  } }, code, h('button', { type: 'button', class: 'pf-link-btn left', onclick: () => pick.click() }, 'Or pick the backup file'), pick, pw.el, err);
  const warn = h('p', { class: 'pf-warn', hidden: true, text: `This Wizard's current ID (${shortNpub(ME.npub)}) stops being used here. Friends who added it would need to add the restored one. The current key is kept on this Wizard in case you change your mind.` });
  form.append(warn, go);
  sh.card.append(
    h('span', { class: 'pf-sheet-ic', 'aria-hidden': 'true', html: ICON.key }),
    h('b', { text: 'Restore your identity' }),
    h('p', { class: 'pf-sheet-p', text: 'Bring back a Nostr ID you backed up, for example on a new Wizard.' }),
    form);
  code.focus();
}
async function toggleHidden(id) {
  const set = new Set(ME.hidden); set.has(id) ? set.delete(id) : set.add(id);
  try { ME = await api('api/me', 'PUT', { hidden: [...set] }); render(); } catch (e) { say(e.message, 'error'); }
}
function editName() {
  const box = h('form', { class: 'pf-edit', onsubmit: async e => {
    e.preventDefault();
    try { ME = await api('api/me', 'PUT', { name: n.value, bio: b.value, messenger: m.value.trim() }); render(); say('Saved.', 'note'); }
    catch (err) { say(err.message, 'error'); }
  } });
  const n = h('input', { class: 'wz-input', maxlength: 60, placeholder: 'Your name', 'aria-label': 'Your name' }); n.value = ME.name;
  const b = h('input', { class: 'wz-input', maxlength: 280, placeholder: 'A line about you (optional)', 'aria-label': 'About you' }); b.value = ME.bio;
  const m = h('input', { class: 'wz-input', placeholder: 'Messenger address, npub1… (optional)', 'aria-label': 'Messenger address', autocomplete: 'off', spellcheck: 'false' }); m.value = ME.messenger || '';
  box.append(h('div', { class: 'pf-photo-row' }, avatar(ME, 'lg'),
      h('button', { type: 'button', class: 'pf-chip on', onclick: pickPhoto }, ME.picture ? 'Change photo' : 'Add photo'),
      ME.picture ? h('button', { type: 'button', class: 'pf-chip', onclick: async () => { ME = await api('api/me', 'PUT', { picture: '' }); render(); editName(); } }, 'Remove') : null),
    n, b, m, h('p', { class: 'pf-hint', text: 'Friends see your Messenger address so they can message you.' }),
    h('div', { class: 'pf-row-acts' }, h('button', { type: 'submit', class: 'pf-btn go' }, 'Save'), h('button', { type: 'button', class: 'pf-btn', onclick: render }, 'Cancel')));
  $('view-me').querySelector('.pf-who').replaceWith(box); n.focus();
}
async function preview(as) {
  try { const p = await api('api/preview?as=' + as); FRIEND = { profile: { ...p, signed: false }, preview: as }; show('friend'); }
  catch (e) { say(e.message, 'error'); }
}

/* ---------- Friends ---------- */
function renderFriends() {
  const v = $('view-friends'); v.replaceChildren();
  const input = h('input', { class: 'wz-input pf-code', placeholder: 'Paste a Nostr ID (npub1…)', 'aria-label': "Your friend's Nostr ID", autocomplete: 'off', spellcheck: 'false' });
  const addBtn = h('button', { type: 'submit', class: 'pf-btn go' }, 'Add');
  v.append(h('form', { class: 'pf-card pf-add', onsubmit: async e => {
    e.preventDefault(); addBtn.disabled = true; addBtn.textContent = 'Adding…';
    try { await added(await api('api/friends', 'POST', { npub: input.value })); }
    catch (err) { say(err.message, 'error'); addBtn.disabled = false; addBtn.textContent = 'Add'; }
  } }, h('div', { class: 'pf-card-h' }, h('div', { class: 'wz-main' }, h('b', { text: 'Add a friend' }), h('small', { text: 'Their Nostr ID is all you need' }))),
    h('div', { class: 'pf-add-row' }, input, addBtn)));
  if (ME.requests.length) {
    const reqs = h('ul', { class: 'wz-list' });
    for (const r of ME.requests) reqs.append(h('li', { class: 'pf-item' }, avatar(r, 'sm'),
      h('div', { class: 'wz-main' }, h('b', { text: r.name }), h('small', { text: `Added you · ${shortNpub(r.npub)}` })),
      h('button', { type: 'button', class: 'pf-chip on', onclick: async e => { e.currentTarget.disabled = true; try { await added(await api('api/friends', 'POST', { npub: r.npub, name: r.name })); } catch (err) { say(err.message, 'error'); } } }, 'Add back'),
      h('button', { type: 'button', class: 'pf-chip', onclick: async () => { ME = await api('api/requests/dismiss', 'POST', { npub: r.npub }); render(); } }, 'Ignore')));
    v.append(h('section', { class: 'wz-sec' }, h('h2', { class: 'wz-sec-h' }, 'Added you'), reqs));
  }
  const list = h('ul', { class: 'wz-list' });
  for (const f of ME.friends) list.append(h('li', {},
    h('button', { type: 'button', class: 'wz-row pf-friend', onclick: () => openFriend(f) }, avatar(f, 'sm'),
      h('span', { class: 'wz-main' }, h('b', { text: f.name }), h('small', { text: shortNpub(f.npub) })), h('span', { class: 'pf-go', 'aria-hidden': 'true' }, '›'))));
  v.append(h('section', { class: 'wz-sec' }, h('h2', { class: 'wz-sec-h' }, 'Friends', ME.friends.length ? h('span', { class: 'wz-count', text: String(ME.friends.length) }) : null),
    ME.friends.length ? list : h('p', { class: 'pf-hint', text: 'No friends yet. Send someone your Nostr ID, or paste theirs above.' })));
  v.append(h('section', { class: 'wz-sec' }, h('h2', { class: 'wz-sec-h' }, 'Give friends your ID'), idCard(),
    h('p', { class: 'pf-hint', text: 'Nobody can reach your Wizard with it. Friends get only what you share, encrypted for them, through Nostr.' }),
    h('div', { class: 'pf-row-acts' }, h('button', { type: 'button', class: 'pf-btn', onclick: checkNow }, 'Check for new friends'),
      ME.requests_checked ? h('small', { class: 'pf-when', text: `Checked ${ago(ME.requests_checked)}` }) : null)));
}
async function checkNow(e) {
  const b = e.currentTarget; b.disabled = true; b.textContent = 'Checking…';
  try { ME = await api('api/requests/check', 'POST', {}); render(); say(ME.requests.length ? 'Someone added you.' : 'Nobody new yet.', 'note'); }
  catch (err) { say(err.message, 'error'); b.disabled = false; b.textContent = 'Check for new friends'; }
}
async function added(out) {
  ME = out.me; render();
  say(out.sent ? `${out.friend.name} added. They'll see you on their Friends tab.` : `${out.friend.name} added. Couldn't reach Nostr just now; your Wizard will try again.`, 'note');
}
async function openFriend(f) {
  FRIEND = { profile: null, friend: f }; show('friend');
  try { FRIEND.profile = await api(`api/friends/${f.id}/profile`); } catch (e) { FRIEND.error = e.message; }
  if (TAB === 'friend') renderFriend();
}
async function removeFriend(f) {
  if (!confirm(`Remove ${f.name}? They stop getting what you share with friends.`)) return;
  try { ME = await api('api/friends/' + f.id, 'DELETE'); show('friends'); } catch (e) { say(e.message, 'error'); }
}

/* ---------- A friend's profile (or your own preview) ---------- */
function renderFriend() {
  const v = $('view-friend'); v.replaceChildren();
  v.append(h('button', { type: 'button', class: 'pf-back', onclick: () => show(FRIEND?.preview ? 'me' : 'friends') }, '‹ ', FRIEND?.preview ? 'Your profile' : 'Friends'));
  if (!FRIEND) return;
  const p = FRIEND.profile, f = FRIEND.friend || {}, mine = !!FRIEND.preview;
  if (mine) v.append(h('p', { class: 'pf-banner', text: FRIEND.preview === 'friend' ? 'This is exactly what your friends see.' : 'This is exactly what anyone with your Nostr ID sees.' }));
  if (FRIEND.error) { v.append(h('div', { class: 'wz-empty' }, h('strong', {}, `Couldn't load ${f.name || 'their profile'}`), h('p', { text: FRIEND.error }))); return; }
  if (!p) { v.append(h('p', { class: 'pf-hint', text: 'Looking for their profile on Nostr…' })); return; }
  v.append(h('div', { class: 'pf-who' }, avatar(p, 'lg'),
    h('div', { class: 'wz-main' }, h('b', { text: p.name || f.name || 'Someone' }), h('small', { text: p.bio || (p.updated_at ? `Updated ${ago(p.updated_at)}` : '') }),
      p.npub ? h('code', { class: 'pf-npub sm', title: p.npub, text: shortNpub(p.npub) }) : null)));
  if (p.messenger && !mine) v.append(h('div', { class: 'pf-row-acts' }, h('a', { class: 'pf-btn go', href: '/messenger/' }, 'Message in Messenger'),
    h('button', { type: 'button', class: 'pf-chip', onclick: e => copy(e.currentTarget, p.messenger, 'Copy Messenger address') }, 'Copy Messenger address')));
  if (!p.build && !p.skin && !p.apps) {
    v.append(h('div', { class: 'wz-empty' }, h('strong', {}, mine ? 'Nothing shared here' : 'Nothing shared with you yet'),
      h('p', {}, mine ? 'Every part is set to Only you.' : p.viewer === 'none' ? "They haven't added you back yet, or their Wizard hasn't shared since." : "They haven't shared anything with friends.")));
  }
  if (p.skin) {
    const k = p.skin, wearing = ME.wearing?.friend === p.name;
    v.append(card('Look', k.name + (k.css ? ' + their touches' : ''), mine ? null : h('div', { class: 'pf-row-acts' },
      wearing ? h('button', { type: 'button', class: 'pf-btn', onclick: restoreLook }, 'Back to my look') : h('button', { type: 'button', class: 'pf-btn go', onclick: () => wearLook(k, p.name) }, 'Wear this look'),
      ME.look_saved && !wearing ? h('button', { type: 'button', class: 'pf-btn', onclick: restoreLook }, 'Back to my look') : null), null,
      mine ? null : 'Only colours and styling. Your own look is saved first.'));
  }
  if (p.build) {
    const b = p.build, t = TRY?.commit === b.commit ? TRY : null;
    v.append(card('Build', b.name, mine ? null : h('div', { class: 'pf-row-acts' },
      t?.state === 'ready' ? [h('a', { class: 'pf-btn go', href: t.url, target: '_blank', rel: 'noopener' }, 'Open it'), h('button', { type: 'button', class: 'pf-btn', onclick: stopTry }, 'Stop trying')]
        : t && ['queued', 'building', 'starting'].includes(t.state) ? h('button', { type: 'button', class: 'pf-btn', disabled: true }, 'Getting it ready…')
          : h('button', { type: 'button', class: 'pf-btn go', onclick: () => tryOn(b, p.name) }, 'Try it on')),
      b.changes.length ? h('ul', { class: 'pf-changes' }, b.changes.slice(0, 12).map(c => h('li', { text: c.title }))) : h('p', { class: 'pf-hint', text: 'Stock Wizard, no changes of their own.' }),
      mine ? null : 'Runs their exact build beside yours, with your own chats and apps. Yours is not changed.'));
  }
  if (p.apps) {
    const grid = appGroups(p.apps, a => {
      const have = INSTALLED.includes(a.id);
      return h(mine || have ? 'div' : 'a', { class: 'pf-tile' + (a.system ? ' sys' : ''), ...(mine || have ? {} : { href: `/wizard-os-home/store/index.html?app=${encodeURIComponent(a.store_id || a.id)}`, title: `Get ${a.name}` }) },
        appIcon(a), h('span', { class: 'pf-tile-n', text: a.name }), mine ? null : h('span', { class: 'pf-tile-x' + (have ? '' : ' get'), text: have ? 'You have it' : 'Get' }));
    });
    v.append(card('Apps', `${p.apps.length} App Store app${p.apps.length === 1 ? '' : 's'}`, null, p.apps.length ? grid : h('p', { class: 'pf-hint', text: 'No apps shared.' }), null));
  }
  if (!mine && f.id) v.append(h('div', { class: 'pf-row-acts center' }, h('button', { type: 'button', class: 'pf-btn danger', onclick: () => removeFriend(f) }, `Remove ${f.name}`)));
}

/* ---------- Wear a look: skin id + CSS through the shell's own My skin; undo restores both ---------- */
async function wearLook(k, who) {
  try {
    const f = await localFacts();
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
  const put = !!String(css || '').trim();
  const r = await fetch('/wizard/v1/my-skin', { method: put ? 'PUT' : 'DELETE', credentials: 'same-origin', headers: put ? { 'Content-Type': 'text/css' } : {}, body: put ? css : undefined });
  if (!r.ok) throw new Error('Could not change your look on this Wizard.');
  try { await shell()?.WosMySkin?.refresh?.(); } catch (_) {}
}
function applySkin(id) {
  const S = shell()?.WosSkin;
  if (S?.list?.some(s => s.id === id)) S.set(id);
  else try { localStorage.setItem('wos.skin', id); } catch (_) {}
}

/* ---------- Try on a build ---------- */
async function tryStatus() {
  try { TRY = await api(TRYON + 'status'); } catch (_) { TRY = null; }
  renderTry();
  clearTimeout(tryTimer);
  if (TRY && ['queued', 'building', 'starting'].includes(TRY.state)) tryTimer = setTimeout(tryStatus, 2500);
  if (TAB === 'friend' && FRIEND && !FRIEND.preview) renderFriend();
}
async function tryOn(b, who) {
  try { TRY = await api(TRYON + 'start', 'POST', { commit: b.commit, label: `${who}'s build` }); say(`Getting ${who}'s build ready…`, 'note'); tryStatus(); }
  catch (e) { say(/404|Not Found/.test(e.message) ? 'Trying on builds is not set up on this Wizard yet.' : e.message, 'error'); }
}
async function stopTry() {
  try { TRY = await api(TRYON + 'stop', 'POST', {}); say('Stopped. You are on your own build.', 'note'); tryStatus(); } catch (e) { say(e.message, 'error'); }
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
  $('title').textContent = tab === 'friends' ? 'Friends' : tab === 'friend' ? (FRIEND?.friend?.name || FRIEND?.profile?.name || 'Profile') : 'Profile';
  render(); $('scroll').scrollTop = 0;
}
function render() {
  if (!ME) return;
  $('req-dot').hidden = !ME.requests.length;
  $('sub').textContent = '';
  if (TAB === 'me') renderMe(); else if (TAB === 'friends') renderFriends(); else renderFriend();
}
for (const b of document.querySelectorAll('.pf-tabs button')) b.onclick = () => show(b.dataset.tab);
window.__wizardCloseOverlay = () => { if (TAB === 'friend') { show(FRIEND?.preview ? 'me' : 'friends'); return true; } return false; };

(async () => {
  try { ME = await api('api/me'); show('me'); tryStatus(); refresh(); }
  catch (e) { say(e.message, 'error'); }
})();
document.addEventListener('visibilitychange', () => { if (!document.hidden && ME) refresh(); });
addEventListener('wizard:theme', () => { if (ME && TAB === 'me') render(); });

// Run ONLY against a disposable offline Profiles instance on port 18850.
// No key values, response bodies, screenshots, or private files are logged.
const { chromium } = require('playwright');
const { execFileSync } = require('child_process');
const U = process.env.PROFILES_TEST_URL || 'http://127.0.0.1:18850/';
const python = process.env.PROFILES_PYTHON || 'python3';
const data = process.env.PROFILES_TEST_DATA;
function fixturePython(code) {
  if (!data) throw new Error('PROFILES_TEST_DATA must name disposable test state');
  return execFileSync(python, ['-c', code], { cwd: require('path').resolve(__dirname, '..'), env: { ...process.env, DATA_DIR: data }, encoding: 'utf8' });
}
let count = 0;
function check(value, label) { if (!value) throw new Error(label); count++; console.log('PASS ' + label); }
async function request(path, body, headers = {}) {
  const r = await fetch(U + path, { method: 'POST', headers: { 'Content-Type': 'application/json', ...headers }, body: JSON.stringify(body) });
  return { status: r.status, cache: r.headers.get('cache-control'), body: await r.json() };
}
(async () => {
  let browser;
  try {
    const original = (await (await fetch(U + 'api/me')).json()).npub;
    check((await request('api/identity/backup', {})).status === 400, 'omitted format and password never export raw key');
    check((await request('api/identity/backup', { format: 'wrong' })).status === 400, 'unknown format refused');
    check((await request('api/identity/backup', { format: 'nsec' }, { Origin: 'https://evil.invalid' })).status === 403, 'cross-origin export refused');
    check((await request('api/identity/backup', { format: 'nsec' }, { 'X-Forwarded-For': '100.100.100.100' })).status === 403, 'anonymous forwarded export refused');
    check((await fetch(U + 'api/identity/backup')).status === 404, 'GET cannot export key');
    const tools = await request('mcp', { jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} });
    check(!tools.body.result.tools.some(t => /identity|nsec|export|backup/.test(t.name)), 'MCP does not expose identity export');
    const raw = await request('api/identity/backup', { format: 'nsec' });
    check(raw.status === 200 && raw.body.backup.startsWith('nsec1') && raw.body.npub === original, 'explicit nsec exports without password');
    check(raw.cache === 'no-store', 'export response is no-store');
    const encrypted = await request('api/identity/backup', { password: 'throwaway testing password' });
    check(encrypted.status === 200 && encrypted.body.backup.startsWith('ncryptsec1'), 'old password-only caller remains encrypted');
    check((await request('api/identity/restore', { backup: encrypted.body.backup, password: 'wrong' })).status === 400, 'wrong encrypted password refused');
    check((await request('api/identity/restore', { backup: encrypted.body.backup, password: 'throwaway testing password' })).body.changed === false, 'encrypted restore round trip');
    check((await request('api/identity/restore', { backup: raw.body.backup })).body.changed === false, 'raw restore needs no password');
    check((await request('api/identity/restore', { backup: raw.body.backup.slice(0, -1) + (raw.body.backup.endsWith('q') ? 'p' : 'q') })).status === 400, 'bad checksum refused');
    browser = await chromium.launch({ executablePath: process.env.CHROME_PATH || '/usr/bin/google-chrome' });
    const ctx = await browser.newContext({ viewport: { width: 390, height: 844 }, permissions: ['clipboard-read', 'clipboard-write'], acceptDownloads: true });
    const p = await ctx.newPage(); const errors = [];
    p.on('pageerror', () => errors.push(true));
    await p.goto(U); await p.locator('.pf-safe').click();
    check(await p.locator('.pf-sheet input[type=password]').count() === 0, 'default sheet has no password fields');
    check(await p.getByRole('button', { name: 'Download private key', exact: true }).isVisible(), 'download is primary visible action');
    check(await p.locator('.pf-sheet').evaluate(e => e.scrollWidth <= e.clientWidth), 'mobile sheet fits viewport');
    const [download] = await Promise.all([p.waitForEvent('download'), p.getByRole('button', { name: 'Download private key', exact: true }).click()]);
    const stream = await download.createReadStream(); let text = ''; for await (const c of stream) text += c.toString();
    check(text.trim() === raw.body.backup, 'download contains exact raw key without password');
    check(!(await p.locator('.pf-sheet').innerText()).includes(raw.body.backup), 'private key never painted in backup sheet');
    check(await p.getByRole('button', { name: 'Done', exact: true }).isDisabled(), 'Done requires saved acknowledgement');
    await p.locator('.pf-sheet .pf-x').click();
    await p.locator('.pf-safe').click(); await p.getByRole('button', { name: 'Copy private key', exact: true }).click();
    await p.waitForFunction(() => document.querySelector('.pf-copy')?.textContent === 'Copied');
    check(await p.evaluate(() => navigator.clipboard.readText()) === raw.body.backup, 'direct copy writes exact raw key');
    await p.locator('.pf-tick input').check(); await p.getByRole('button', { name: 'Done', exact: true }).click();
    await p.waitForSelector('.pf-sheet', { state: 'detached' });
    check((await (await fetch(U + 'api/me')).json()).backed_up_at != null, 'acknowledgement persists');
    await p.locator('.pf-safe').click(); await p.getByRole('button', { name: 'Use a password-encrypted backup instead' }).click();
    await p.getByPlaceholder('Choose a password').fill('short'); await p.getByPlaceholder('Type it again').fill('short');
    await p.getByRole('button', { name: 'Make my backup' }).click();
    check((await p.locator('.pf-err').innerText()).includes('10 characters'), 'optional encryption validates password');
    await p.getByPlaceholder('Choose a password').fill('throwaway testing password'); await p.getByPlaceholder('Type it again').fill('throwaway testing password');
    await p.getByRole('button', { name: 'Make my backup' }).click(); await p.getByRole('button', { name: 'Save as file' }).waitFor();
    const [lockedDownload] = await Promise.all([p.waitForEvent('download'), p.getByRole('button', { name: 'Save as file' }).click()]);
    const lockedStream = await lockedDownload.createReadStream(); let lockedText = ''; for await (const c of lockedStream) lockedText += c.toString();
    check(lockedText.includes('ncryptsec1') && !lockedText.includes(raw.body.backup), 'optional encrypted download remains encrypted');
    await p.locator('.pf-sheet .pf-x').click();
    await p.locator('.pf-safe').click(); await p.getByRole('button', { name: 'Restore it' }).click();
    check(await p.getByPlaceholder('Backup password').isHidden(), 'restore initially needs no password');
    const [chooser] = await Promise.all([p.waitForEvent('filechooser'), p.getByRole('button', { name: 'Or pick the backup file' }).click()]);
    await chooser.setFiles({ name: 'key.txt', mimeType: 'text/plain', buffer: Buffer.from(text) });
    await p.waitForFunction(() => document.querySelector('.pf-paste').value.startsWith('nsec1'));
    check(await p.getByPlaceholder('Backup password').isHidden(), 'raw nsec file picking needs no password');
    await p.getByRole('button', { name: 'Restore', exact: true }).click();
    check(await p.getByRole('button', { name: 'Yes, switch to that ID' }).isVisible(), 'restore asks explicit confirmation');
    await p.getByRole('button', { name: 'Yes, switch to that ID' }).click(); await p.waitForSelector('.pf-sheet', { state: 'detached' });
    check((await (await fetch(U + 'api/me')).json()).npub === original, 'raw file restores exact identity');
    await p.locator('.pf-safe').click(); await p.getByRole('button', { name: 'Restore it' }).click();
    await p.getByRole('textbox', { name: 'Your backup', exact: true }).fill(encrypted.body.backup);
    check(await p.getByPlaceholder('Backup password').isVisible(), 'encrypted paste reveals password');
    await p.getByRole('textbox', { name: 'Your backup', exact: true }).fill(raw.body.backup);
    check(await p.getByPlaceholder('Backup password').isHidden(), 'raw paste hides password');
    const oldInput = await p.locator('.pf-paste').elementHandle();
    await p.keyboard.press('Escape');
    check(await oldInput.evaluate(e => e.value === ''), 'close scrubs private restore input');
    // Generate a second throwaway key in memory, never read any app key file.
    const other = JSON.parse(fixturePython("import json; from app import server as s; k=s.new_secret(); print(json.dumps({'key':s.b32_encode('nsec',k),'npub':s.npub_encode(s.pub_of(k)),'zero':s.b32_encode('nsec',bytes(32))}))"));
    check((await request('api/identity/restore', { backup: other.zero })).status === 400, 'zero scalar raw key refused');
    await p.locator('.pf-safe').click(); await p.getByRole('button', { name: 'Restore it' }).click();
    await p.getByRole('textbox', { name: 'Your backup', exact: true }).fill(other.key);
    await p.getByRole('button', { name: 'Restore', exact: true }).click();
    await p.getByRole('button', { name: 'Yes, switch to that ID' }).click(); await p.waitForSelector('.pf-sheet', { state: 'detached' });
    check((await (await fetch(U + 'api/me')).json()).npub === other.npub, 'raw paste switches to a different throwaway identity');
    const modes = fixturePython("import os; from pathlib import Path; print(all((p.stat().st_mode & 0o777)==0o600 for p in Path(os.environ['DATA_DIR']).glob('wizard-key*.json'))); print(len(list(Path(os.environ['DATA_DIR']).glob('wizard-key.before-*.json')))>0)").trim();
    check(modes === 'True\nTrue', 'current and replaced keys kept with owner-only permissions');
    check((await request('api/identity/restore', { backup: raw.body.backup })).body.changed === true, 'raw backup can undo identity replacement');
    check(errors.length === 0, 'no browser JavaScript errors');
    console.log(`${count} checks passed`);
  } catch (e) { console.error('FAIL ' + (e.message?.startsWith('Timeout') ? 'browser timeout (details suppressed)' : e.message?.split('\n')[0])); process.exitCode = 1; }
  finally { if (browser) await browser.close(); }
})();

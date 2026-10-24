'use strict';
const { chromium } = require('playwright');
const fs = require('fs');
const base = process.env.PROFILES_TEST_URL;
const checks = []; const check = (ok, name) => { checks.push({ name, ok: !!ok }); if (!ok) throw new Error(name); };
(async () => {
  const browser = await chromium.launch({ executablePath: process.env.CHROME_PATH || '/usr/bin/google-chrome' });
  const context = await browser.newContext({ viewport: { width: 390, height: 844 }, isMobile: true, hasTouch: true });
  const page = await context.newPage(), errors = [];
  page.on('pageerror', e => errors.push(e.message));
  try {
    await page.request.post(base + 'test-reset', { data: {} });
    await page.goto(base);
    await page.getByText('Set up your Wizard ID on your phone to claim this Wizard').waitFor();
    check(await page.getByText('Your Wizard · unclaimed').isVisible(), 'standalone remains unclaimed without phone');
    await page.goto(base + 'test-host');
    const frame = page.frameLocator('#app');
    await frame.getByRole('button', { name: 'Claim this Wizard', exact: true }).waitFor();
    check(await frame.getByRole('button', { name: 'Claim this Wizard', exact: true }).isVisible(), 'hosted real shared client exposes phone claim');
    await page.evaluate(() => { window.fixtureDenied = true; });
    await frame.getByRole('button', { name: 'Claim this Wizard', exact: true }).click();
    await frame.locator('#status').filter({ hasText: 'Phone approval denied' }).waitFor();
    check(!(await (await page.request.get(base + 'api/me')).json()).owner_npub, 'denied phone claim changes no state');
    await page.evaluate(() => { window.fixtureDenied = false; });
    await frame.getByRole('button', { name: 'Claim this Wizard', exact: true }).click();
    await frame.getByText('Your Wizard ID · phone').waitFor();
    let me = await (await page.request.get(base + 'api/me')).json();
    check(me.npub === me.owner_npub && me.npub !== me.box_npub, 'person ID is owner, inbox stays separate');
    check(!(await frame.getByRole('button', { name: 'Back up your identity', exact: true }).count()), 'claimed screen does not mislabel device backup as owner identity');
    await frame.getByRole('button', { name: 'Friends', exact: true }).click();
    const input = frame.getByPlaceholder('npub1…'); await input.fill(process.env.PROFILES_FRIEND_NPUB);
    await page.evaluate(() => { window.fixtureDenied = true; });
    await frame.getByRole('button', { name: 'Add', exact: true }).click();
    await frame.locator('#status').filter({ hasText: 'Phone approval denied' }).waitFor();
    check((await (await page.request.get(base + 'api/me')).json()).friends.length === 0, 'denied friend add changes no friends');
    await page.evaluate(() => { window.fixtureDenied = false; });
    await frame.getByRole('button', { name: 'Add', exact: true }).click();
    await frame.locator('.pf-friend').waitFor();
    me = await (await page.request.get(base + 'api/me')).json();
    check(me.friends.length === 1 && !me.friends[0].claimed, 'phone-signed add accepts legacy unclaimed peer');
    check((await frame.locator('.pf-friend').innerText()).includes('Wizard (unclaimed)'), 'legacy peer cannot appear as person');
    await frame.locator('.pf-friend').click();
    await frame.getByRole('button', { name: 'Friends', exact: true }).first().waitFor();
    const appFrame = page.frames().find(f => f.url() === base);
    check(await appFrame.evaluate(() => window.__wizardCloseOverlay()), 'nested friend Back handled');
    check(await frame.getByPlaceholder('npub1…').isVisible(), 'nested Back returns to Friends, not Home');
    await page.request.post(base + 'test-seed-request', { data: {} });
    await frame.getByRole('button', { name: 'Check for new friends', exact: true }).click();
    await frame.getByRole('button', { name: 'Open 1 sealed requests', exact: true }).waitFor();
    check((await (await page.request.get(base + 'api/me')).json()).sealed_requests === 1, 'stock reply to phone is queued, not box-decrypted');
    await frame.getByRole('button', { name: 'Open 1 sealed requests', exact: true }).click();
    const accept = frame.getByRole('button', { name: 'Add back', exact: true });
    await accept.waitFor();
    check((await (await page.request.get(base + 'api/me')).json()).sealed_requests === 0, 'explicit phone opening drains sealed queue');
    await page.evaluate(() => { window.fixtureDenied = true; });
    await accept.click();
    await frame.locator('#status').filter({ hasText: 'Phone approval denied' }).waitFor();
    check(await accept.isEnabled(), 'denied acceptance remains retryable');
    check((await (await page.request.get(base + 'api/me')).json()).friends.length === 1, 'denied acceptance does not add a friend');
    await page.evaluate(() => { window.fixtureDenied = false; });
    await accept.click();
    await frame.locator('.pf-friend').nth(1).waitFor();
    check((await (await page.request.get(base + 'api/me')).json()).friends.length === 2, 'phone-signed acceptance adds legacy requester');
    await frame.getByPlaceholder('npub1…').fill('unsent draft');
    for (const [skin, scheme, canvas, text, accent] of [['nebula', 'dark', '#171122', '#f7f1ff', '#cbb2ff'], ['tide', 'light', '#f2f8fa', '#12343d', '#147a91']]) {
      for (const width of [390, 1280]) {
        await page.setViewportSize({ width, height: 844 });
        await page.evaluate(({ skin, scheme, canvas, text, accent, width }) => {
          document.body.style.background = canvas;
          const tokens = Object.fromEntries(['canvas','base','chrome','overlay','surface','surface-raised','reader-surface'].map(k => [k, canvas]));
          Object.assign(tokens, { text, 'text-secondary': text, 'text-muted': text, border: accent, accent, 'accent-soft': canvas, 'on-accent': canvas });
          document.querySelector('#app').contentWindow.postMessage({ type: 'wizard:appearance', appearance: { version: 1, revision: width + (scheme === 'light' ? 5000 : 0), presentation: 'window', colorScheme: scheme, skin, tokens } }, location.origin);
        }, { skin, scheme, canvas, text, accent, width });
        await appFrame.waitForFunction(skin => document.documentElement.dataset.skin === skin, skin);
        check(await input.inputValue() === 'unsent draft', `${skin}/${width}: skin switch preserves input`);
        check(await appFrame.evaluate(() => document.documentElement.scrollWidth <= innerWidth), `${skin}/${width}: no horizontal overflow`);
        await appFrame.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
        await page.screenshot({ path: `owner-identity-${skin}-${width}.png`, fullPage: true });
      }
    }
    check(errors.length === 0, 'no browser page errors');
    console.log(JSON.stringify({ checks, errors }, null, 2));
  } finally { await browser.close(); }
})().catch(e => { console.error(JSON.stringify({ checks, error: e.message }, null, 2)); process.exit(1); });

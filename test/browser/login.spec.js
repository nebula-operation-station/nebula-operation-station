// SPDX-License-Identifier: AGPL-3.0-or-later
// Browser test of setup, login and logout with virtual authenticators
// (Chrome DevTools WebAuthn domain). Run with `make test-browser`.
'use strict';
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');

function check(cond, what) {
  if (!cond) throw new Error('check failed: ' + what);
  console.log('ok  ', what);
}
(async () => {
  const base = 'http://localhost:' + process.argv[2];
  const browser = await chromium.launch();
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  const cdp = await ctx.newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  const opts = { protocol: 'ctap2', transport: 'usb', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true };
  const { authenticatorId: first } = await cdp.send('WebAuthn.addVirtualAuthenticator', { options: opts });

  await page.goto(base + '/dashboard');
  check(new URL(page.url()).pathname === '/login', 'without a session the dashboard redirects to the login');
  await page.click('#login');
  await page.waitForFunction(() => /No security key/.test(document.getElementById('message').textContent));
  check(true, 'login before any registration points to the setup');

  const code = await (await page.request.get(base + '/__code')).text();
  await page.goto(base + '/setup');
  await page.fill('#code', code);
  await page.click('#setup button');
  await page.waitForFunction(() => /registered/i.test(document.getElementById('message').textContent));
  check(/registered/i.test(await page.textContent('#message')), 'first key registered with the one-time code');

  // Same key again -> friendly message.
  const codeDup = await (await page.request.get(base + '/__code')).text();
  await page.fill('#code', codeDup);
  await page.click('#setup button');
  await page.waitForFunction(() => /already|failed|not accepted/i.test(document.getElementById('message').textContent));
  check(/already registered/i.test(await page.textContent('#message')), 'the same key cannot be registered twice');

  // Second key: unplug the first, create with the second, then plug the first back for the confirmation.
  const { credentials } = await cdp.send('WebAuthn.getCredentials', { authenticatorId: first });
  await cdp.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId: first });
  const { authenticatorId: second } = await cdp.send('WebAuthn.addVirtualAuthenticator', { options: opts });
  let swapped = false;
  await page.exposeBinding('__swapKeys', async () => {
    await cdp.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId: second });
    const { authenticatorId: back } = await cdp.send('WebAuthn.addVirtualAuthenticator', { options: opts });
    for (const c of credentials) await cdp.send('WebAuthn.addCredential', { authenticatorId: back, credential: c });
    swapped = true;
  });
  await page.addInitScript(() => {
    const orig = navigator.credentials.create.bind(navigator.credentials);
    navigator.credentials.create = async (o) => { const c = await orig(o); await window.__swapKeys(); return c; };
  });
  const code2 = await (await page.request.get(base + '/__code')).text();
  await page.goto(base + '/setup');
  await page.fill('#code', code2);
  await page.click('#setup button');
  await page.waitForFunction(() => /registered\. You can|failed|not accepted|expired|Cancelled/i.test(document.getElementById('message').textContent), null, { timeout: 30000 });
  check(swapped && /registered\. You can/i.test(await page.textContent('#message')), 'second key registered, confirmed by the first');

  // Login with the first key, then logout from the dashboard.
  await page.goto(base + '/login');
  await page.click('#login');
  await page.waitForURL('**/dashboard', { timeout: 15000 });
  check(true, 'login with the first key opens the dashboard');
  // Privileged session from the dashboard, then lock.
  check(/Privileged session: none/.test(await page.textContent('main')), 'no privileged session after login');
  await Promise.all([page.waitForNavigation({ timeout: 15000 }), page.click('#session-open')]);
  check(/Privileged session: active/.test(await page.textContent('main')), 'privileged session opened with the security key');
  await Promise.all([page.waitForNavigation({ timeout: 15000 }), page.click('#executor-lock')]);
  check(/Privileged session: none/.test(await page.textContent('main')), 'lock ends the privileged session');

  const cookies = await ctx.cookies();
  const sc = cookies.find((c) => c.name === '__Host-nebula_session');
  check(sc && sc.secure && sc.httpOnly && sc.sameSite === 'Strict', 'session cookie is __Host-, Secure, HttpOnly, SameSite=Strict');
  await Promise.all([page.waitForURL('**/login', { timeout: 10000 }), page.click('#logout')]);
  await page.goto(base + '/dashboard');
  check(new URL(page.url()).pathname === '/login', 'after logout the dashboard redirects to the login');
  await browser.close();
})().catch(e => { console.error('E2E FAIL', e); process.exit(1); });

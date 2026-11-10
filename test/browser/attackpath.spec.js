// SPDX-License-Identifier: AGPL-3.0-or-later
// Browser acceptance test of the attack-path pages (ADR 0011 D10, Q6,
// VU-26). Run with `make test-browser` (test/browser/run.sh starts a fresh
// harness for it).
//
// It signs in once with a virtual authenticator. As admin it opens the
// paths list, a path's detail page and the traffic map with the attack-path
// overlay, and checks that the hostile labels and finding texts of the
// harness (test/browser/harness/attackpath.go) show as literal text, that
// no element or script came from them, that the overlay frame carries
// map IDs, ranks and flags only, and that the renderer accepted it. Then
// the harness hook /__paths/admin makes the same session a non-admin: every
// attack-path route answers 403 with nothing of the data, and the normal
// traffic map carries no overlay.
'use strict';
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');

// The hostile texts of test/browser/harness/attackpath.go.
const ENTRY = `<img src=x onerror="window.__pwned='paths-host'">AP host`;
const TARGET = `</td></tr><script>window.__pwned='paths-target'</script>AP jewel`;
const VULN = `CVE-2026-<svg onload="window.__pwned='paths-vuln'">`;
const PKG = `nginx"><iframe srcdoc="<script>parent.__pwned='paths-pkg'</script>">`;
const ALL = [ENTRY, TARGET, VULN, PKG];

// Markers of every text above; none may reach a non-admin.
const MARKERS = ['AP host', 'AP jewel', 'paths-host', 'paths-target', 'paths-vuln', 'paths-pkg', 'host:e2e-two'];

// Elements hostile text could create inside the page content.
const INJECTED = 'main img, main svg, main script, main iframe, main object, main embed, [onerror], [onload], [srcdoc]';

function check(cond, what) {
  if (!cond) throw new Error('check failed: ' + what);
  console.log('ok  ', what);
}

async function waitFor(fn, what, timeout = 15000) {
  const end = Date.now() + timeout;
  for (;;) {
    const v = await fn();
    if (v) return v;
    if (Date.now() > end) throw new Error('timed out waiting for ' + what);
    await new Promise((r) => setTimeout(r, 100));
  }
}

const authenticator = { protocol: 'ctap2', transport: 'usb', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true };

// signIn registers a key with a one-time code, logs in and returns the
// browser state with the session cookie.
async function signIn(base) {
  const browser = await chromium.launch();
  try {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    const cdp = await ctx.newCDPSession(page);
    await cdp.send('WebAuthn.enable');
    await cdp.send('WebAuthn.addVirtualAuthenticator', { options: authenticator });
    const code = await (await page.request.get(base + '/__code')).text();
    await page.goto(base + '/setup');
    await page.fill('#code', code);
    await page.click('#setup button');
    await page.waitForFunction(() => /registered/i.test(document.getElementById('message').textContent));
    await page.goto(base + '/login');
    await page.click('#login');
    await page.waitForURL('**/dashboard', { timeout: 15000 });
    check(true, 'signed in for the attack-path tests');
    return await ctx.storageState();
  } finally {
    await browser.close();
  }
}

// setAdmin flips the harness admin rule of the attack-path pages.
async function setAdmin(page, base, on) {
  const r = await page.request.get(base + '/__paths/admin?on=' + (on ? '1' : '0'));
  check(r.ok() && (await r.text()) === String(on), 'the harness admin rule is ' + (on ? 'on' : 'off'));
}

// frameAt returns the frame whose path is pathname.
function frameAt(page, pathname) {
  return waitFor(() => page.frames().find((f) => {
    try {
      return new URL(f.url()).pathname === pathname;
    } catch (e) {
      return false;
    }
  }), 'the frame ' + pathname);
}

// noScriptRan checks that no hostile text ran script in the page or frame.
async function noScriptRan(page, frame, tag) {
  check(await page.evaluate(() => window.__pwned) === undefined, tag + ': no hostile text ran script in the page');
  if (frame) check(await frame.evaluate(() => window.__pwned) === undefined, tag + ': no hostile text ran script in the renderer');
}

async function admin(page, base) {
  // --- List -----------------------------------------------------------
  const resp = await page.goto(base + '/vuln/paths');
  check(resp.status() === 200, 'admin: the paths list opens');
  const panel = page.locator('section[aria-label^="Paths to"]');
  check(await panel.count() === 1, 'admin: one crown-jewel panel');
  check((await panel.locator('h2').textContent()).includes(TARGET), 'admin: the crown jewel label shows as literal text in its heading');
  check(await panel.getAttribute('aria-label') === 'Paths to ' + TARGET, 'admin: the panel name carries the label as text');
  const route = await panel.locator('tbody tr').first().textContent();
  check(route.includes(ENTRY) && route.includes(TARGET), 'admin: the route in the paths list shows both labels as literal text');
  const chokes = await page.locator('section[aria-label="Choke points"]').textContent();
  check(chokes.includes(VULN) && chokes.includes(PKG), 'admin: the choke point shows the hostile finding texts as literal text');
  check(await page.locator('section[aria-label="Choke points"] a[href^="javascript:"]').count() === 0, 'admin: the javascript: fix link is not rendered');
  check(await page.locator(INJECTED).count() === 0, 'admin: no element was created from a hostile text on the list');
  await noScriptRan(page, null, 'admin list');

  // --- Detail -------------------------------------------------------------
  await Promise.all([page.waitForURL('**/vuln/paths/p/*'), panel.locator('a:has-text("Explain")').first().click()]);
  const detail = await page.locator('main').textContent();
  for (const s of ALL) check(detail.includes(s), 'admin: the detail page shows ' + JSON.stringify(s.slice(0, 24)) + '… as literal text');
  check(await page.locator(INJECTED).count() === 0, 'admin: no element was created from a hostile text on the detail page');
  check(await page.locator('main a[href^="javascript:"]').count() === 0, 'admin: no javascript: link on the detail page');
  await noScriptRan(page, null, 'admin detail');

  // --- Traffic map overlay -------------------------------------------------
  await page.goto(base + '/vuln/paths/map?target=host:e2e-two');
  await page.waitForFunction(() => /^Drawn with /.test(document.getElementById('trafficmap-status').textContent), null, { timeout: 20000 });
  const frame = await frameAt(page, '/vuln/paths/map/frame');
  await waitFor(() => frame.evaluate(() => {
    const s = document.querySelector('#trafficmap [role=status]');
    return s && /^Rendering with /.test(s.textContent);
  }), 'the overlay renderer status');
  const hint = await page.locator('#trafficmap-page .hint').first().textContent();
  check(hint.includes('All top paths to ' + TARGET), 'admin: the overlay page names the crown jewel as literal text');
  check(await page.locator('#trafficmap-page img, #trafficmap-page svg, #trafficmap-page script, #trafficmap-page iframe:not(#trafficmap-frame), [onerror], [onload]').count() === 0,
    'admin: no element was created from a hostile text on the overlay page');
  check(await frame.evaluate(() => document.querySelectorAll('img, svg, iframe, object, embed, script:not([src]), [onerror], [onload]').length) === 0,
    'admin: no element was created from a hostile text in the overlay renderer');
  await noScriptRan(page, frame, 'admin overlay');

  const raw = await frame.evaluate(() => document.getElementById('trafficmap').getAttribute('data-paths'));
  check(typeof raw === 'string' && raw.length > 0, 'admin: the overlay renderer document carries the overlay');
  check(MARKERS.slice(0, 6).every((m) => !raw.includes(m)), 'admin: the overlay carries no label or finding text');
  const o = JSON.parse(raw);
  check(JSON.stringify(Object.keys(o).sort()) === '["beams","marks","truncated","version"]', 'admin: the overlay has the label-free schema');
  check(o.beams.length === 1 && o.beams[0].from === 'e2e-host' && o.beams[0].to === 'e2e-two' && o.truncated === false,
    'admin: the overlay holds the beam between the two harness hosts');
  check(o.marks.every((m) => Object.keys(m).sort().join() === 'id,role'), 'admin: overlay marks hold an ID and a role only');
  const accepted = await frame.evaluate(async () => {
    const m = await import('/static/trafficmap/paths.js');
    const p = m.readPaths(document.getElementById('trafficmap'));
    return p !== null && p !== m.REJECTED && p.beams.length === 1;
  });
  check(accepted, 'admin: the renderer accepted the overlay');
}

async function nonAdmin(page, base) {
  await setAdmin(page, base, false);
  for (const p of ['/vuln/paths', '/vuln/paths/map', '/vuln/paths/map?target=host:e2e-two', '/vuln/paths/map/frame', '/vuln/paths/map/frame?target=host:e2e-two']) {
    const resp = await page.goto(base + p);
    check(resp.status() === 403, 'non-admin: GET ' + p + ' is refused (403)');
    const body = await resp.text();
    check(MARKERS.every((m) => !body.includes(m)) && !body.includes('data-paths') && !body.includes('<iframe'),
      'non-admin: GET ' + p + ' shows nothing of the attack paths');
  }

  // The normal traffic map never carries the overlay, admin or not.
  await page.goto(base + '/traffic?window=24h');
  await page.waitForFunction(() => /^Drawn with /.test(document.getElementById('trafficmap-status').textContent), null, { timeout: 20000 });
  const frame = await frameAt(page, '/traffic/frame');
  check(await page.locator('iframe[src^="/vuln/paths"]').count() === 0, 'non-admin: the traffic map frames no overlay document');
  check(await frame.evaluate(() => document.querySelector('[data-paths]') === null), 'non-admin: the traffic map renderer has no overlay attribute');
  const html = await page.content();
  check(MARKERS.every((m) => !html.includes(m)), 'non-admin: the traffic map page carries no attack-path text');
  await noScriptRan(page, frame, 'non-admin traffic map');
  await setAdmin(page, base, true);
}

(async () => {
  const base = 'http://localhost:' + process.argv[2];
  const state = await signIn(base);
  const browser = await chromium.launch({ args: ['--use-angle=swiftshader', '--enable-unsafe-swiftshader', '--ignore-gpu-blocklist'] });
  try {
    const ctx = await browser.newContext({ storageState: state, viewport: { width: 1280, height: 1000 } });
    const page = await ctx.newPage();
    const pageErrors = [];
    page.on('pageerror', (e) => pageErrors.push(e.message));
    await admin(page, base);
    await nonAdmin(page, base);
    check(pageErrors.length === 0, 'no script errors' + (pageErrors.length ? ': ' + pageErrors.join('; ') : ''));
  } finally {
    await browser.close();
  }
  console.log('attack-path browser test passed');
})().catch((e) => {
  console.error(e);
  process.exit(1);
});

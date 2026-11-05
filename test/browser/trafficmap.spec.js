// SPDX-License-Identifier: AGPL-3.0-or-later
// Browser acceptance test of the traffic map (ADR 0009 D4, TM21). Run with
// `make test-browser` (test/browser/run.sh starts a fresh harness for it).
//
// It signs in once with a virtual authenticator, then opens /traffic in two
// browsers: one with WebGL2 (SwiftShader, no GPU needed) and one with WebGL
// disabled, where the renderer must fall back to Canvas 2D. In both it
// checks that the map is drawn, that the hostile names of the harness
// inventory (test/browser/harness/trafficmap.go) stay text, that the
// sandboxed renderer cannot read cookies, the parent DOM or the network,
// and that focus and navigation work with keyboard and mouse.
'use strict';
const zlib = require('zlib');
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');

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

// distinctColours decodes an 8-bit RGB(A) PNG (a Playwright screenshot)
// and counts its distinct RGB values, to tell a drawn map from an empty
// canvas without an image library.
function distinctColours(buf) {
  let off = 8;
  let w = 0, h = 0, depth = 0, type = 0;
  const idat = [];
  while (off + 8 <= buf.length) {
    const len = buf.readUInt32BE(off);
    const kind = buf.toString('ascii', off + 4, off + 8);
    const data = buf.subarray(off + 8, off + 8 + len);
    if (kind === 'IHDR') {
      w = data.readUInt32BE(0);
      h = data.readUInt32BE(4);
      depth = data[8];
      type = data[9];
      if (data[12] !== 0) throw new Error('interlaced PNG');
    } else if (kind === 'IDAT') {
      idat.push(data);
    } else if (kind === 'IEND') {
      break;
    }
    off += 12 + len;
  }
  if (depth !== 8 || (type !== 2 && type !== 6)) throw new Error('unexpected PNG format ' + depth + '/' + type);
  const bpp = type === 6 ? 4 : 3;
  const stride = w * bpp;
  const raw = zlib.inflateSync(Buffer.concat(idat));
  let prev = Buffer.alloc(stride);
  let cur = Buffer.alloc(stride);
  const seen = new Set();
  for (let y = 0; y < h; y++) {
    const base = y * (stride + 1);
    const filter = raw[base];
    for (let i = 0; i < stride; i++) {
      const a = i >= bpp ? cur[i - bpp] : 0;
      const b = prev[i];
      const c = i >= bpp ? prev[i - bpp] : 0;
      let x = raw[base + 1 + i];
      switch (filter) {
        case 0: break;
        case 1: x += a; break;
        case 2: x += b; break;
        case 3: x += (a + b) >> 1; break;
        case 4: {
          const p = a + b - c, pa = Math.abs(p - a), pb = Math.abs(p - b), pc = Math.abs(p - c);
          x += pa <= pb && pa <= pc ? a : pb <= pc ? b : c;
          break;
        }
        default: throw new Error('bad PNG filter ' + filter);
      }
      cur[i] = x & 0xff;
    }
    for (let i = 0; i < stride; i += bpp) seen.add((cur[i] << 16) | (cur[i + 1] << 8) | cur[i + 2]);
    [prev, cur] = [cur, prev];
  }
  return seen.size;
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
    check(true, 'signed in for the traffic map tests');
    return await ctx.storageState();
  } finally {
    await browser.close();
  }
}

// rendererFrame returns the sandboxed renderer's frame.
function rendererFrame(page) {
  return waitFor(() => page.frames().find((f) => {
    try {
      return new URL(f.url()).pathname === '/traffic/frame';
    } catch (e) {
      return false;
    }
  }), 'the renderer frame');
}

// openMap loads the map page and waits until the renderer reported its
// backend and the model is loaded.
async function openMap(page, base, query) {
  await page.goto(base + '/traffic?' + query);
  await page.waitForFunction(() => /^Drawn with /.test(document.getElementById('trafficmap-status').textContent), null, { timeout: 20000 });
  const frame = await rendererFrame(page);
  await waitFor(() => frame.evaluate(() => {
    const s = document.querySelector('#trafficmap [role=status]');
    return s && /^Rendering with /.test(s.textContent) ? s.textContent : '';
  }), 'the renderer status');
  return frame;
}

// tabIntoMap presses Tab until the renderer's map element has the focus.
async function tabIntoMap(page, frame) {
  for (let i = 0; i < 120; i++) {
    await page.keyboard.press('Tab');
    const inMap = await frame.evaluate(() => document.hasFocus() && document.activeElement !== null && document.activeElement.id === 'trafficmap');
    if (inMap) return true;
  }
  return false;
}

async function suite(base, state, s) {
  const browser = await chromium.launch({ args: s.args });
  try {
    const ctx = await browser.newContext({ storageState: state, viewport: { width: 1280, height: 1000 } });
    const page = await ctx.newPage();
    const pageErrors = [];
    page.on('pageerror', (e) => pageErrors.push(e.message));
    const tag = '[' + s.name + '] ';

    // --- Rendering -----------------------------------------------------
    let frame = await openMap(page, base, 'window=24h');
    const probe = await page.evaluate(() => document.createElement('canvas').getContext('webgl2') !== null);
    check(probe === s.webgl2, tag + 'the browser ' + (s.webgl2 ? 'has' : 'lacks') + ' WebGL2');
    const parentStatus = await page.textContent('#trafficmap-status');
    check(s.parentStatus.test(parentStatus), tag + 'the page reports the backend: ' + parentStatus);
    const frameStatus = await frame.evaluate(() => document.querySelector('#trafficmap [role=status]').textContent);
    check(frameStatus === s.frameStatus, tag + 'the renderer draws with ' + frameStatus);
    check(/3 nodes/.test(await page.textContent('#trafficmap-summary')), tag + 'the summary counts the three nodes');
    await page.waitForTimeout(800);
    const colours = distinctColours(await page.locator('#trafficmap-frame').screenshot());
    check(colours >= 16, tag + 'the map is drawn (' + colours + ' distinct colours)');

    // --- Hostile names stay text ----------------------------------------
    check(await page.evaluate(() => window.__pwned) === undefined, tag + 'no hostile name ran script in the page');
    check(await frame.evaluate(() => window.__pwned) === undefined, tag + 'no hostile name ran script in the renderer');
    check(await page.locator('#trafficmap-page img, #trafficmap-page svg, #trafficmap-page script, #trafficmap-page iframe:not(#trafficmap-frame), [onerror], [onload]').count() === 0,
      tag + 'no element was created from a hostile name in the page');
    check(await frame.evaluate(() => document.querySelectorAll('img, svg, iframe, object, embed, script:not([src]), [onerror], [onload]').length) === 0,
      tag + 'no element was created from a hostile name in the renderer');

    // --- Isolation -------------------------------------------------------
    const iso = await frame.evaluate(async () => {
      const r = { origin: self.origin };
      try { r.cookie = document.cookie === '' ? 'empty' : 'readable'; } catch (e) { r.cookie = 'blocked'; }
      try { r.parentDOM = window.parent.document ? 'readable' : 'blocked'; } catch (e) { r.parentDOM = 'blocked'; }
      try { r.topURL = window.top.location.href ? 'readable' : 'blocked'; } catch (e) { r.topURL = 'blocked'; }
      try { localStorage.setItem('tm21', '1'); r.storage = 'open'; } catch (e) { r.storage = 'blocked'; }
      // The module is served with Access-Control-Allow-Origin: *, so only
      // connect-src 'none' can stop this fetch from an opaque origin.
      try { await fetch('/static/trafficmap/boot.js?tm21'); r.fetch = 'open'; } catch (e) { r.fetch = 'blocked'; }
      // A valid data: PNG loads unless img-src 'none' forbids it.
      r.image = await new Promise((resolve) => {
        const img = document.createElement('img');
        img.onload = () => resolve('loaded');
        img.onerror = () => resolve('blocked');
        setTimeout(() => resolve('blocked'), 2000);
        img.src = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==';
      });
      return r;
    });
    check(iso.origin === 'null', tag + 'the renderer runs in an opaque origin');
    check(iso.cookie !== 'readable', tag + 'the renderer cannot read cookies (' + iso.cookie + ')');
    check(iso.parentDOM === 'blocked', tag + 'the renderer cannot reach the parent DOM');
    check(iso.topURL === 'blocked', tag + 'the renderer cannot read the top URL');
    check(iso.storage === 'blocked', tag + 'the renderer has no storage');
    check(iso.fetch === 'blocked', tag + 'the renderer cannot use the network (connect-src)');
    check(iso.image === 'blocked', tag + 'the renderer cannot load images (img-src)');
    const cookies = await ctx.cookies();
    const httpOnly = cookies.filter((c) => c.httpOnly);
    const docCookie = await page.evaluate(() => document.cookie);
    check(httpOnly.length > 0 && httpOnly.every((c) => !docCookie.includes(c.value)), tag + 'the session cookie is HttpOnly');

    // --- Focus and navigation with the keyboard -------------------------
    frame = await openMap(page, base, 'window=24h&focus=e2e-host');
    check(await page.locator('a:has-text("Back to the overview")').count() === 1, tag + 'the focus view links back to the overview');
    check(await tabIntoMap(page, frame), tag + 'Tab reaches the map inside the sandboxed iframe');
    await page.keyboard.press('=');
    await page.keyboard.press('ArrowLeft');
    await Promise.all([page.waitForURL('**/hosts/e2e-host', { timeout: 10000 }), page.keyboard.press('Enter')]);
    check(new URL(page.url()).pathname === '/hosts/e2e-host', tag + 'Enter on the focused node opens its host page');

    frame = await openMap(page, base, 'window=24h&focus=e2e-host');
    check(await tabIntoMap(page, frame), tag + 'Tab reaches the map again');
    await page.keyboard.press('Escape');
    await page.keyboard.press('Enter');
    await page.waitForTimeout(800);
    check(new URL(page.url()).pathname === '/traffic', tag + 'after Escape clears the focus, Enter navigates nowhere');

    // --- Selection and navigation with the mouse ------------------------
    frame = await openMap(page, base, 'window=24h&focus=e2e-host');
    await page.waitForTimeout(300);
    const box = await page.locator('#trafficmap-frame').boundingBox();
    const cx = box.x + box.width / 2, cy = box.y + box.height / 2;
    await page.mouse.click(cx, cy);
    await page.waitForFunction(() => !document.getElementById('trafficmap-selection').hidden, null, { timeout: 10000 });
    const label = await page.textContent('#trafficmap-selection-label');
    check(label.includes('<img src=x onerror='), tag + 'clicking the centred node selects it and shows its hostile name as text');
    check(await page.getAttribute('#trafficmap-selection-open', 'href') === '/hosts/e2e-host', tag + 'the selection links to the host page');
    check(await page.evaluate(() => window.__pwned) === undefined && await page.locator('#trafficmap-selection img').count() === 0,
      tag + 'the selection box did not turn the name into markup');
    await Promise.all([page.waitForURL('**/hosts/e2e-host', { timeout: 10000 }), page.mouse.dblclick(cx, cy)]);
    check(new URL(page.url()).pathname === '/hosts/e2e-host', tag + 'double-clicking a node opens its host page');

    check(pageErrors.length === 0, tag + 'no script errors in the page' + (pageErrors.length ? ': ' + pageErrors.join('; ') : ''));
  } finally {
    await browser.close();
  }
}

(async () => {
  const base = 'http://localhost:' + process.argv[2];
  const state = await signIn(base);
  await suite(base, state, {
    name: 'webgl2',
    // SwiftShader gives headless Chromium WebGL2 without a GPU.
    args: ['--use-angle=swiftshader', '--enable-unsafe-swiftshader', '--ignore-gpu-blocklist'],
    webgl2: true,
    parentStatus: /^Drawn with webgl2( \(no bloom\))?\.$/,
    frameStatus: 'Rendering with WebGL2.',
  });
  await suite(base, state, {
    name: 'canvas2d',
    args: ['--disable-webgl', '--disable-webgl2', '--disable-3d-apis'],
    webgl2: false,
    parentStatus: /^Drawn with canvas2d \(fallback\)\.$/,
    frameStatus: 'Rendering with Canvas 2D (fallback).',
  });
  console.log('traffic map browser test passed');
})().catch((e) => {
  console.error(e);
  process.exit(1);
});

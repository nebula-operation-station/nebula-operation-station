// SPDX-License-Identifier: AGPL-3.0-or-later
// Browser acceptance test of the vulnerabilities pages (ADR 0011 D6, D8;
// VU-16 part 2; rules V7 and V9). Run with `make test-browser`
// (test/browser/run.sh starts a fresh harness for it).
//
// It signs in with a virtual authenticator and opens the list (by CVE and
// by subject), the per-CVE page, every subject page and the finding pages
// of the harness backend (test/browser/harness/vuln.go), whose IDs,
// package names, versions, subject names, feed IDs, run IDs and assessment
// texts are hostile. On every page it checks that no hostile value ran
// script or became markup, that the values arrive as literal text, that
// every link and form target is built by NOS (relative paths only; vendor
// advisories are not part of this fixture), and that a stale, not assessed,
// unconfirmed or feed-affected subject is never shown green. It never
// submits a form.
'use strict';
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');

function check(cond, what) {
  if (!cond) throw new Error('check failed: ' + what);
  console.log('ok  ', what);
}

const authenticator = { protocol: 'ctap2', transport: 'usb', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true };

// Values of test/browser/harness/vuln.go.
const hostile = {
  hostName: '<img src=x onerror="window.__pwned=\'subject\'">E2E host',
  twoName: '</script><script>window.__pwned=\'two\'</script>',
  assessment: "<script>window.__pwned='assessment'</script>\nSecond line: <b>bold?</b>\n\t<a href=\"https://evil.example/a\">evil link</a>",
  markdown: "[click me](javascript:window.__pwned='markdown') and https://evil.example/plain and <a href=\"javascript:window.__pwned='a'\">a</a>",
  // Escape and bidi override are shown as U+FFFD (internal/web/ui vulnText).
  control: "<iframe srcdoc=\"<script>parent.__pwned='iframe'</script>\"></iframe> esc" + String.fromCharCode(0xfffd) + "[31m bidi" + String.fromCharCode(0xfffd) + "evil",
  id: '<svg onload="window.__pwned=\'id\'">',
  pkg: 'openssl<img src=x onerror="window.__pwned=\'pkg\'">',
  alias: '<b onmouseover="window.__pwned=\'alias\'">DSA</b>',
  source: "evil<script>window.__pwned='feed'</script>",
  run: '<b>run</b>"><script>window.__pwned=\'run\'</script>',
  version: '3.0.15<img src=x onerror="window.__pwned=\'version\'">',
};
const digest = 'sha256:' + 'ab12'.repeat(16);
const key = (b) => b.repeat(32);

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
    check(true, 'signed in for the vulnerabilities tests');
    return await ctx.storageState();
  } finally {
    await browser.close();
  }
}

// open loads path, fails on a non-200 answer and returns the text of the
// page's main element (textContent: CSS text-transform does not apply).
async function open(page, base, path) {
  const resp = await page.goto(base + path);
  check(resp.status() === 200, path + ' answers 200');
  return page.evaluate(() => document.querySelector('main').textContent);
}

// inert checks that nothing hostile became script, markup, a link or a
// form target on the current page.
async function inert(page, path) {
  check(await page.evaluate(() => window.__pwned) === undefined, path + ': no hostile value ran script');
  const made = await page.evaluate(() => document.querySelectorAll(
    'main img, main svg, main iframe, main object, main embed, main script, main b, main [onerror], main [onload], main [onmouseover], main [srcdoc]').length);
  check(made === 0, path + ': no element was created from a hostile value (' + made + ')');
  const hrefs = await page.evaluate(() => Array.from(document.querySelectorAll('a[href]'), (a) => a.getAttribute('href')));
  const foreign = hrefs.filter((h) => !h.startsWith('/') || h.startsWith('//') || /javascript:|evil|pwned|[<>"]/i.test(h));
  check(hrefs.length > 0 && foreign.length === 0, path + ': all ' + hrefs.length + ' links are NOS paths' + (foreign.length ? ': ' + foreign.join(' ') : ''));
  // The layout's search form (GET /search) is outside main.
  const forms = await page.evaluate(() => Array.from(document.querySelectorAll('main form'), (f) => ({
    method: (f.getAttribute('method') || 'get').toLowerCase(), action: f.getAttribute('action') || '' })));
  const bad = forms.filter((f) => !(f.method === 'get' && f.action === '') && !(f.method === 'post' && /^\/vulnerabilities\/decide\/begin$/.test(f.action)));
  check(bad.length === 0, path + ': every form is the filter or a maintainer decision (' + forms.length + ' forms)' +
    (bad.length ? ': ' + JSON.stringify(bad) : ''));
  const jsAttr = await page.evaluate(() => Array.from(document.querySelectorAll('*')).some((el) =>
    Array.from(el.attributes).some((a) => /^\s*javascript:/i.test(a.value) || a.value.includes('evil.example'))));
  check(!jsAttr, path + ': no attribute carries a hostile URL');
}

// statuses returns the subject status badges of the list by subject.
async function statuses(page) {
  return page.evaluate(() => Array.from(document.querySelectorAll('tr.vuln-subject'), (tr) => ({
    id: tr.querySelector('.hint.mono').textContent,
    name: tr.querySelector('a').textContent,
    text: tr.querySelector('.vuln-status').textContent,
    green: tr.querySelector('.vuln-status').classList.contains('badge--ok'),
  })));
}

async function subjectStatus(page) {
  return page.evaluate(() => {
    const b = document.querySelector('.vuln-subject-summary .vuln-status');
    return { text: b.textContent, green: b.classList.contains('badge--ok') };
  });
}

(async () => {
  const base = 'http://localhost:' + process.argv[2];
  const state = await signIn(base);
  const browser = await chromium.launch();
  try {
    const ctx = await browser.newContext({ storageState: state, viewport: { width: 1280, height: 1000 } });
    const page = await ctx.newPage();
    const pageErrors = [];
    const cspReports = [];
    page.on('pageerror', (e) => pageErrors.push(e.message));
    page.on('console', (m) => { if (/Content Security Policy/i.test(m.text())) cspReports.push(m.text()); });

    // --- List by CVE ------------------------------------------------------
    let text = await open(page, base, '/vulnerabilities?state=all');
    await inert(page, '/vulnerabilities');
    check(text.includes('Advisory only: nothing here proposes, approves or runs a change.'), 'the list says findings are advisory');
    const cves = await page.evaluate(() => Array.from(document.querySelectorAll('tr.vuln-cve td:first-child'), (td) => ({
      text: td.textContent, link: td.querySelector('a') ? td.querySelector('a').getAttribute('href') : null })));
    const hostileRow = cves.find((c) => c.text.includes(hostile.id));
    check(hostileRow !== undefined, 'the hostile vulnerability ID is listed as literal text');
    check(hostileRow.link === null, 'an ID failing the pattern gets no link');
    const critRow = cves.find((c) => c.text.startsWith('CVE-2026-1111'));
    check(critRow && critRow.link === '/vulnerabilities/cve/CVE-2026-1111', 'a valid ID links to its NOS-built CVE page');
    const staleNote = await page.evaluate(() => Array.from(document.querySelectorAll('tr.vuln-cve')).some((tr) =>
      tr.textContent.includes('CVE-2026-1111') && tr.textContent.includes('stale, not assessed or feed issue')));
    check(staleNote, 'the CVE with a stale image finding is marked stale');
    check(await page.locator('main .badge--ok').count() === 0, 'the list by CVE shows nothing green');
    const banners = await page.evaluate(() => Array.from(document.querySelectorAll('.vuln-banner'), (b) => b.textContent).join('\n'));
    check(banners.includes(hostile.source), 'the unlisted hostile feed ID appears as literal text in a banner');

    // --- List by subject --------------------------------------------------
    text = await open(page, base, '/vulnerabilities?view=subject');
    await inert(page, '/vulnerabilities?view=subject');
    const subs = await statuses(page);
    check(subs.length === 5, 'every subject is listed, also those without findings (' + subs.length + ')');
    check(subs.every((s) => !s.green), 'no subject is green while a feed on the page has an issue: ' + subs.map((s) => s.id + '=' + s.text).join(', '));
    const byID = (id) => subs.find((s) => s.id === id);
    check(byID('e2e-host').name === hostile.hostName, 'the hostile subject name is literal text in the list');
    check(subs.some((s) => s.name === hostile.twoName && s.text === 'not assessed'), 'the never assessed subject is "not assessed"');
    check(subs.some((s) => s.id === 'e2e-host' && s.text.includes('open, critical')), 'the subject with a critical finding says so');
    check(subs.some((s) => /^stale since /.test(s.text)), 'the image assessed 72 h ago is "stale since …"');
    check(byID('e2e-unconf').text.includes('closed by Hermes, not confirmed by NOS'), 'an unconfirmed closure keeps its subject off green');
    check(byID('e2e-clean').text === 'feed issue', 'even the clean subject is not green while a feed has an issue');

    // --- Per-CVE page -----------------------------------------------------
    text = await open(page, base, '/vulnerabilities/cve/CVE-2026-1111');
    await inert(page, '/vulnerabilities/cve/CVE-2026-1111');
    const rows = await page.evaluate(() => Array.from(document.querySelectorAll('tr.vuln-finding'), (tr) => tr.textContent));
    check(rows.length === 2, 'the CVE page lists the host and the image finding');
    check(rows.some((r) => r.includes(hostile.hostName) && r.includes(hostile.pkg)), 'subject name and package name are literal text on the CVE page');
    check(rows.some((r) => r.includes('feed ' + hostile.source + ' not on NOS\'s source list')), 'the finding on the unlisted feed is labelled');
    check(rows.some((r) => /stale since /.test(r)), 'the stale image finding is labelled stale');

    // --- Subject pages ----------------------------------------------------
    const subjectPages = [
      { path: '/vulnerabilities/subject/host/e2e-host', want: /open, critical$/, literal: [hostile.hostName, hostile.id, hostile.version, hostile.pkg] },
      { path: '/vulnerabilities/subject/host/e2e-two', want: /^not assessed$/, literal: [hostile.twoName] },
      { path: '/vulnerabilities/subject/image/e2e-host?digest=' + digest, want: /^stale since /, literal: [] },
      { path: '/vulnerabilities/subject/host/e2e-unconf', want: /closed by Hermes, not confirmed by NOS$/, literal: [] },
    ];
    for (const s of subjectPages) {
      text = await open(page, base, s.path);
      await inert(page, s.path);
      const st = await subjectStatus(page);
      check(s.want.test(st.text) && !st.green, s.path + ': status "' + st.text + '", not green');
      for (const l of s.literal) check(text.includes(l), s.path + ': shows ' + JSON.stringify(l) + ' as text');
    }
    // Control: the clean, fresh subject with no feed issue on its own page
    // is the one place green appears, so the checks above can see green.
    text = await open(page, base, '/vulnerabilities/subject/host/e2e-clean');
    await inert(page, '/vulnerabilities/subject/host/e2e-clean');
    const clean = await subjectStatus(page);
    check(clean.green && clean.text === 'no open findings', 'control: the clean, fresh subject is green on its page');
    // An unknown subject is "not assessed", never green.
    text = await open(page, base, '/vulnerabilities/subject/host/e2e-unknown');
    const unknown = await subjectStatus(page);
    check(unknown.text === 'not assessed' && !unknown.green, 'a subject NOS knows nothing about is "not assessed", not green');

    // --- Finding pages ----------------------------------------------------
    text = await open(page, base, '/vulnerabilities/f/' + key('11'));
    await inert(page, 'finding ' + key('11'));
    const assessment = await page.evaluate(() => document.querySelector('pre.vuln-assessment').textContent);
    check(assessment === hostile.assessment, 'the assessment is shown byte for byte as text, line breaks kept');
    check(text.includes('Hermes assessment (LLM, unverified)'), 'the assessment is labelled as unverified LLM output');
    check(text.includes(hostile.alias), 'the hostile alias is literal text');
    check(text.includes(hostile.run) && text.includes(hostile.version), 'run ID and NOS version of the hold are literal text');
    const runField = await page.evaluate(() => {
      const i = document.querySelector('form.vuln-decision input[name=run_id]');
      return i ? i.value : null;
    });
    check(runField === hostile.run, 'the hostile run ID sits in the hold form field as a plain value');
    check(await page.locator('.vuln-contradicted').count() === 1, 'the contradicted hold is marked');
    check(await page.evaluate(() => Array.from(document.querySelectorAll('form.vuln-decision')).every((f) => !f.querySelector('[autofocus]'))),
      'no decision form focuses or submits itself');

    text = await open(page, base, '/vulnerabilities/f/' + key('22'));
    await inert(page, 'finding ' + key('22'));
    check(await page.evaluate(() => document.querySelector('pre.vuln-assessment').textContent) === hostile.markdown,
      'Markdown, a bare URL and an <a> tag in the assessment stay text');
    check(await page.locator('pre.vuln-assessment a').count() === 0, 'no link is made from the assessment');
    check(text.includes(hostile.id) && text.includes(hostile.version), 'the hostile ID and version are literal text');

    text = await open(page, base, '/vulnerabilities/f/' + key('33'));
    await inert(page, 'finding ' + key('33'));
    const ctrl = await page.evaluate(() => document.querySelector('pre.vuln-assessment').textContent);
    check(ctrl === hostile.control, 'control and bidi characters are shown as U+FFFD, the iframe markup as text');
    check(!ctrl.includes(String.fromCharCode(0x202e)) && !ctrl.includes('\x1b'), 'no bidi override or escape reaches the page');
    check(text.includes('not assessed'), 'the finding of the never assessed subject says "not assessed"');

    text = await open(page, base, '/vulnerabilities/f/' + key('44'));
    await inert(page, 'finding ' + key('44'));
    check(/stale since /.test(text) && text.includes('feed ' + hostile.source + ' not on NOS\'s source list'),
      'the stale image finding on the unlisted feed carries both labels');

    text = await open(page, base, '/vulnerabilities/f/' + key('55'));
    await inert(page, 'finding ' + key('55'));
    check(await page.evaluate(() => {
      const b = document.querySelector('.vuln-state');
      return b.textContent === 'closed by Hermes, not confirmed by NOS' && !b.classList.contains('badge--ok');
    }), 'the unconfirmed closure is labelled and not green');

    check(await page.evaluate(() => window.__pwned) === undefined, 'no hostile value ran script on any page');
    check(cspReports.length === 0, 'no Content Security Policy violation' + (cspReports.length ? ': ' + cspReports.join('; ') : ''));
    check(pageErrors.length === 0, 'no script errors' + (pageErrors.length ? ': ' + pageErrors.join('; ') : ''));
  } finally {
    await browser.close();
  }
  console.log('vulnerabilities browser test passed');
})().catch((e) => {
  console.error(e);
  process.exit(1);
});

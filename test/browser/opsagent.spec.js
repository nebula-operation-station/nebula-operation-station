// SPDX-License-Identifier: AGPL-3.0-or-later
// Browser acceptance test of the Assistant's Ops tab, the suggestion cards
// and the forms they open (ADR 0016 D8, D9, D11, D12; AG-25). Run with
// `make test-browser` (test/browser/run.sh starts a fresh harness for it).
//
// It signs in with a virtual authenticator and checks, in a real browser:
//   1. an admin sees the tabs "Help" and "Ops", a non-admin only "Help";
//      every Ops route answers 404 to a non-admin;
//   2. hostile model text on a card (HTML, script, Markdown links, URLs,
//      bidi controls) arrives as literal text: no element, no link, no
//      script runs, and no Content Security Policy violation is reported;
//   3. a step button opens the normal form with action and host from the
//      stored step, empty parameters and the banner, and nothing is
//      submitted without a further click (the operation list is unchanged);
//   4. submitting a LOW action from a suggestion asks for the security key
//      (risk raised to MEDIUM); without an assertion it stays pending;
//   5. an interim measure has no button, Dismiss hides the card and changes
//      nothing else, and the Ops-Agent settings save only with an assertion.
// Data: test/browser/harness/opsagent.go.
'use strict';
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');

function check(cond, what) {
  if (!cond) throw new Error('check failed: ' + what);
  console.log('ok  ', what);
}

const authenticator = { protocol: 'ctap2', transport: 'usb', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true };

// Values of test/browser/harness/opsagent.go.
const hostile = {
  summary: "<script>window.__pwned='summary'</script><img src=x onerror=\"window.__pwned='summary-img'\">Upgrade openssl now",
  urgency: 'high ' + String.fromCharCode(0x202e) + 'evil' + String.fromCharCode(0x202c) + ' [now](https://evil.example/urgent)',
  whyRestart: "<a href=\"javascript:window.__pwned='why'\">restart</a> **bold** [docs](https://evil.example/docs) https://evil.example/plain",
  whyRefresh: "Refresh lists first <iframe srcdoc=\"<script>parent.__pwned='iframe'</script>\"></iframe>",
  mitigation: "Block port 443: `iptables -I INPUT -p tcp --dport 443 -j DROP` <button onclick=\"window.__pwned='mit'\">run</button>",
  mitigForm: '<form action="https://evil.example/f" method="post"><input type="submit" value="apply"></form>',
  citation: "<svg onload=\"window.__pwned='cite'\">",
  citeMD: "[handbook](javascript:window.__pwned='cite-md')",
  pkg: "openssl<img src=x onerror=\"window.__pwned='pkg'\">",
  fleet: "<b>Fleet</b> summary <script>window.__pwned='fleet'</script>",
};
const banner = 'Opened from an agent suggestion. This execution needs a security-key touch.';

// Every link the Ops tab may carry: the tabs, the step buttons, the card
// details and, on the detail page, the way back to /help. All are NOS paths.
const opsLink = /^\/(help|assistant\/(help|ops|panel)|assistant\/ops\/notes\/\d+|operations\/new\?suggestion=\d+\.\d+)$/;

// Counts navigator.credentials.get calls and CSP violations across page
// loads of the tab (sessionStorage). Init scripts run outside the page's
// CSP, so this adds no inline script to the pages under test.
function instrument() {
  const bump = (k, v) => {
    try {
      const a = JSON.parse(sessionStorage.getItem(k) || '[]');
      a.push(v);
      sessionStorage.setItem(k, JSON.stringify(a));
    } catch (_) { /* storage unavailable: counted as zero */ }
  };
  document.addEventListener('securitypolicyviolation', (e) => bump('__csp', e.violatedDirective + ' ' + e.blockedURI));
  if (navigator.credentials && navigator.credentials.get) {
    const orig = navigator.credentials.get.bind(navigator.credentials);
    navigator.credentials.get = (o) => { bump('__gets', location.pathname); return orig(o); };
  }
}

async function gets(page) {
  return page.evaluate(() => JSON.parse(sessionStorage.getItem('__gets') || '[]').length);
}

async function cspViolations(page) {
  return page.evaluate(() => JSON.parse(sessionStorage.getItem('__csp') || '[]'));
}

async function status(page, base, path) {
  const resp = await page.goto(base + path);
  return resp.status();
}

// opIDs returns the IDs of the operations in the list.
async function opIDs(page, base) {
  check(await status(page, base, '/operations') === 200, '/operations answers 200');
  const ids = await page.evaluate(() => Array.from(document.querySelectorAll('main a[href^="/operations/"]'), (a) => a.getAttribute('href'))
    .filter((h) => /^\/operations\/[0-9a-f-]{36}$/.test(h)));
  return Array.from(new Set(ids)).sort();
}

// tabs returns the tab labels of the Assistant panel on the page.
async function tabs(page) {
  await page.waitForSelector('#assistant-panel .assistant-tabs');
  return page.evaluate(() => Array.from(document.querySelectorAll('#assistant-panel .assistant-tab'), (a) => a.textContent.trim()));
}

// openOpsTab loads /help and switches the inline panel to the Ops tab
// (htmx swap, as a user does).
async function openOpsTab(page, base) {
  check(await status(page, base, '/help') === 200, '/help answers 200');
  await page.waitForSelector('#assistant-panel a.assistant-tab[href="/assistant/ops"]');
  await page.click('#assistant-panel a.assistant-tab[href="/assistant/ops"]');
  await page.waitForSelector('#assistant-panel .assistant-ops');
}

// inert checks that nothing hostile became script, markup, a link, a
// button or a form in the Assistant panel.
async function inert(page, where) {
  check(await page.evaluate(() => window.__pwned) === undefined, where + ': no hostile value ran script');
  const made = await page.evaluate(() => {
    const root = document.querySelector('#assistant-panel') || document.querySelector('main');
    return Array.from(root.querySelectorAll('img, svg, iframe, object, embed, b, strong, em, [onerror], [onload], [onclick], [onmouseover], [srcdoc], script'))
      .filter((el) => !(el.tagName === 'SCRIPT' && el.getAttribute('src') === '/static/assistant-ops.js'))
      .map((el) => el.outerHTML.slice(0, 80));
  });
  check(made.length === 0, where + ': no element was created from model text' + (made.length ? ': ' + made.join(' | ') : ''));
  const hrefs = await page.evaluate(() => {
    const root = document.querySelector('#assistant-panel') || document.querySelector('main');
    return Array.from(root.querySelectorAll('a[href]'), (a) => a.getAttribute('href'));
  });
  const foreign = hrefs.filter((h) => !opsLink.test(h));
  check(foreign.length === 0, where + ': all ' + hrefs.length + ' links are NOS paths' + (foreign.length ? ': ' + foreign.join(' ') : ''));
  const forms = await page.evaluate(() => {
    const root = document.querySelector('#assistant-panel') || document.querySelector('main');
    return Array.from(root.querySelectorAll('form'), (f) => ({ method: (f.getAttribute('method') || 'get').toLowerCase(), action: f.getAttribute('action') || '' }));
  });
  const badForms = forms.filter((f) => !(f.method === 'post' && /^\/assistant\/ops\/(questions|notes\/\d+\/dismiss)$/.test(f.action)) &&
    !(f.method === 'get' && f.action === '/assistant/help'));
  check(badForms.length === 0, where + ': every form is the question form, a dismiss form or the handbook search' + (badForms.length ? ': ' + JSON.stringify(badForms) : ''));
  const buttons = await page.evaluate(() => {
    const root = document.querySelector('#assistant-panel') || document.querySelector('main');
    return Array.from(root.querySelectorAll('button, input[type=submit], input[type=button]'), (b) => (b.textContent || b.value).trim());
  });
  check(buttons.every((b) => ['Ask', 'Dismiss', 'Search'].includes(b)), where + ': the only buttons are Ask, Dismiss and Search (' + buttons.join(', ') + ')');
  const hostileAttr = await page.evaluate(() => Array.from(document.querySelectorAll('*')).some((el) =>
    Array.from(el.attributes).some((a) => /^\s*javascript:/i.test(a.value) || a.value.includes('evil.example') || a.value.includes('__pwned'))));
  check(!hostileAttr, where + ': no attribute carries model text');
}

// checkHostileCard checks card 1 of the harness: every model text is
// literal text, each step has its NOS-built button or none, the interim
// measures are text only.
async function checkHostileCard(page, where) {
  const card = await page.evaluate(() => {
    const c = document.getElementById('note-1');
    if (!c) return null;
    const text = (sel) => Array.from(c.querySelectorAll(sel), (e) => ({ text: e.textContent, children: e.children.length }));
    return {
      llm: text('.assistant-llm p.llm-text'),
      steps: Array.from(c.querySelectorAll('ol.assistant-steps > li'), (li) => ({
        why: li.querySelector('p.llm-text') ? li.querySelector('p.llm-text').textContent : null,
        whyChildren: li.querySelector('p.llm-text') ? li.querySelector('p.llm-text').children.length : 0,
        links: Array.from(li.querySelectorAll('a'), (a) => a.getAttribute('href')),
        text: li.textContent,
      })),
      mitigations: text('ul.assistant-mitigations > li'),
      mitigationElements: c.querySelectorAll('ul.assistant-mitigations a, ul.assistant-mitigations button, ul.assistant-mitigations form, ul.assistant-mitigations input').length,
      citations: Array.from(c.querySelectorAll('section.assistant-citations li'), (li) => ({ text: li.textContent.trim(), links: li.querySelectorAll('a').length })),
      facts: Array.from(c.querySelectorAll('.assistant-what dd'), (d) => d.textContent),
      label: c.textContent.includes('Generated by an LLM – unverified. NOS checked only that each step is a catalog action on this host.'),
      runButtons: c.querySelectorAll('button:not([type=submit]), [data-action], [hx-post]:not(form)').length,
    };
  });
  check(card !== null, where + ': the hostile fix card is shown');
  check(card.label, where + ': the card carries the LLM label');
  check(card.llm.length === 2 && card.llm[0].text === hostile.summary && card.llm[0].children === 0,
    where + ': the summary with <script> and <img> is literal text');
  check(card.llm[1].text === 'Urgency: ' + hostile.urgency && card.llm[1].children === 0,
    where + ': the urgency with bidi controls and a Markdown link is literal text');
  check(card.steps.length === 4, where + ': all four steps are listed');
  check(card.steps[0].why === hostile.whyRestart && card.steps[0].whyChildren === 0, where + ': an <a> tag, Markdown and a bare URL in a step reason stay text');
  check(card.steps[1].why === hostile.whyRefresh && card.steps[1].whyChildren === 0, where + ': an <iframe> in a step reason stays text');
  check(JSON.stringify(card.steps[0].links) === JSON.stringify(['/operations/new?suggestion=1.1']), where + ': step 1 has exactly its NOS-built form link');
  check(JSON.stringify(card.steps[1].links) === JSON.stringify(['/operations/new?suggestion=1.2']), where + ': step 2 has exactly its NOS-built form link');
  check(card.steps[2].links.length === 0 && /No button/.test(card.steps[2].text), where + ': a step on a host that left the inventory has no button');
  check(card.steps[3].links.length === 0 && /No button/.test(card.steps[3].text), where + ': a step whose action is not in the catalog has no button');
  check(card.mitigations.length === 2 && card.mitigations[0].text === hostile.mitigation && card.mitigations[1].text === hostile.mitigForm &&
    card.mitigations.every((m) => m.children === 0), where + ': the interim measures are literal text, the <button> and <form> in them too');
  check(card.mitigationElements === 0, where + ': an interim measure has no button, link, form or input');
  check(card.citations.length === 2 && card.citations[0].text === hostile.citation && card.citations[1].text === hostile.citeMD &&
    card.citations.every((c) => c.links === 0), where + ': citations that are not handbook anchors are text, not links');
  check(card.facts[0] === hostile.pkg, where + ': the package fact is literal text');
  check(card.runButtons === 0, where + ': the card has no run or propose control');
}

(async () => {
  const base = 'http://localhost:' + process.argv[2];
  const browser = await chromium.launch();
  try {
    const ctx = await browser.newContext({ viewport: { width: 1280, height: 1000 } });
    await ctx.addInitScript(instrument);
    const page = await ctx.newPage();
    const pageErrors = [];
    const cspReports = [];
    const creates = [];
    page.on('pageerror', (e) => pageErrors.push(e.message));
    page.on('console', (m) => { if (/Content Security Policy/i.test(m.text())) cspReports.push(m.text()); });
    page.on('request', (r) => { if (r.method() === 'POST' && new URL(r.url()).pathname === '/operations/create') creates.push(r.url()); });
    const cdp = await ctx.newCDPSession(page);
    await cdp.send('WebAuthn.enable');
    await cdp.send('WebAuthn.addVirtualAuthenticator', { options: authenticator });

    // --- Sign in -----------------------------------------------------------
    const code = await (await page.request.get(base + '/__code')).text();
    await page.goto(base + '/setup');
    await page.fill('#code', code);
    await page.click('#setup button');
    await page.waitForFunction(() => /registered/i.test(document.getElementById('message').textContent));
    await page.goto(base + '/login');
    await page.click('#login');
    await page.waitForURL('**/dashboard', { timeout: 15000 });
    check(true, 'signed in with the virtual authenticator');

    // --- 1. Tabs: admin and non-admin (D11) ---------------------------------
    await page.goto(base + '/help');
    check(JSON.stringify(await tabs(page)) === JSON.stringify(['Help', 'Ops']), 'an admin sees the tabs Help and Ops');
    check(await status(page, base, '/assistant/panel') === 200 && JSON.stringify(await tabs(page)) === JSON.stringify(['Help', 'Ops']),
      'the full-page panel shows both tabs to an admin');

    check(await (await page.request.get(base + '/__ops/admin?on=0')).text() === 'false', 'the user is no longer an admin');
    await page.goto(base + '/help');
    check(JSON.stringify(await tabs(page)) === JSON.stringify(['Help']), 'a non-admin sees only the Help tab');
    const panelHTML = () => page.evaluate(() => document.getElementById('assistant-panel').outerHTML);
    check(!(await panelHTML()).includes('/assistant/ops'), 'the Ops tab is not in the markup for a non-admin');
    check(await status(page, base, '/assistant/panel') === 200 && JSON.stringify(await tabs(page)) === JSON.stringify(['Help']) &&
      !(await panelHTML()).includes('/assistant/ops'), 'the full-page panel has no Ops tab for a non-admin');
    const frag = await page.request.get(base + '/assistant/panel', { headers: { 'HX-Request': 'true' } });
    check(frag.status() === 200 && !(await frag.text()).includes('/assistant/ops'), 'the panel fragment has no Ops tab for a non-admin');
    for (const path of ['/assistant/ops', '/assistant/ops/notes/1', '/assistant/ops/notes/2', '/assistant/ops/questions', '/operations/new?suggestion=1.1']) {
      check(await status(page, base, path) === 404, 'a non-admin gets 404 for ' + path);
    }
    const hx = await page.request.get(base + '/assistant/ops', { headers: { 'HX-Request': 'true' } });
    check(hx.status() === 404, 'a non-admin gets 404 for the Ops tab fragment');
    await page.goto(base + '/help');
    const posts = await page.evaluate(async () => {
      const out = {};
      for (const p of ['/assistant/ops/notes/1/dismiss', '/assistant/ops/questions']) {
        const r = await fetch(p, { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: 'question=hi' });
        out[p] = r.status;
      }
      const s = await fetch('/settings/ops-agent/begin', { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' }, body: '{}' });
      out.settings = s.status;
      return out;
    });
    check(posts['/assistant/ops/notes/1/dismiss'] === 404 && posts['/assistant/ops/questions'] === 404,
      'a non-admin gets 404 for the Ops POST routes (dismiss, question): ' + JSON.stringify(posts));
    check(posts.settings === 403, 'a non-admin cannot begin an Ops-Agent settings change');
    await page.goto(base + '/settings');
    check(await page.locator('#ops-agent-submit').count() === 0, 'a non-admin sees the Ops-Agent settings without a save button');

    check(await (await page.request.get(base + '/__ops/admin?on=1')).text() === 'true', 'the user is an admin again');

    // --- 2. Hostile model text on the cards (D8) ----------------------------
    const before = await opIDs(page, base);
    await openOpsTab(page, base);
    check(JSON.stringify(await tabs(page)) === JSON.stringify(['Help', 'Ops']), 'the Ops tab is active in the panel');
    await inert(page, 'Ops tab');
    await checkHostileCard(page, 'Ops tab');
    const panel = await page.evaluate(() => ({
      summary: document.querySelector('#assistant-panel .assistant-summary p.llm-text').textContent,
      summaryChildren: document.querySelector('#assistant-panel .assistant-summary p.llm-text').children.length,
      cards: Array.from(document.querySelectorAll('#assistant-panel article.assistant-card'), (c) => c.id),
      outdated: !!document.querySelector('#note-2 .assistant-card__outdated'),
    }));
    check(panel.summary === hostile.fleet && panel.summaryChildren === 0, 'the fleet summary with <b> and <script> is literal text');
    check(JSON.stringify(panel.cards) === JSON.stringify(['note-1', 'note-2']), 'the two fix cards are shown, most urgent first');
    check(panel.outdated, 'a card whose findings changed is marked outdated');

    check(await status(page, base, '/assistant/ops') === 200, 'the full-page Ops tab answers 200');
    await inert(page, '/assistant/ops');
    await checkHostileCard(page, '/assistant/ops');
    check(await status(page, base, '/assistant/ops/notes/1') === 200, 'the card detail page answers 200');
    await inert(page, '/assistant/ops/notes/1');
    await checkHostileCard(page, '/assistant/ops/notes/1');

    // --- 3. A step button opens the form, prefilled, never submitted --------
    await openOpsTab(page, base);
    await Promise.all([page.waitForURL(/\/operations\/new\?suggestion=1\.1$/, { timeout: 15000 }),
      page.click('#note-1 a.button[href="/operations/new?suggestion=1.1"]')]);
    const checkForm = async (where, action) => {
      const f = await page.evaluate(() => {
        const b = document.querySelector('#operation-form p.banner[role=note]');
        const act = document.querySelector('input[name="action"]:checked');
        return {
          banner: b ? b.textContent : '',
          action: act ? act.value : null,
          hosts: Array.from(document.querySelectorAll('input[name="host"]:checked'), (c) => c.value),
          params: Array.from(document.querySelectorAll('#operation-form input[data-param], #operation-form input[data-secret]'), (i) => i.value),
          shownParams: Array.from(document.querySelectorAll('#operation-form label.param'), (l) => ({ hidden: l.hidden, action: l.dataset.action, value: l.querySelector('input').value }))
            .filter((p) => !p.hidden),
          ref: document.getElementById('operation-suggestion') ? document.getElementById('operation-suggestion').value : null,
          autofocus: document.querySelectorAll('[autofocus]').length,
        };
      });
      check(f.banner.includes(banner), where + ': the form shows the agent-suggestion banner');
      check(f.action === action, where + ': the action of the stored step is chosen (' + f.action + ')');
      check(JSON.stringify(f.hosts) === JSON.stringify(['e2e-host']), where + ': only the host of the stored step is chosen (' + f.hosts.join(', ') + ')');
      check(f.params.every((v) => v === ''), where + ': every parameter field is empty');
      check(f.shownParams.every((p) => p.action === action && p.value === ''), where + ': the shown parameter fields belong to the action and are empty');
      check(f.autofocus === 0, where + ': nothing on the form focuses itself');
      return f;
    };
    let f = await checkForm('step 1', 'service.restart');
    check(f.ref === '1.1', 'the form carries the suggestion reference 1.1');
    check(f.shownParams.length === 1, 'the unit field of service.restart is shown, empty, for the human to fill');
    await page.waitForTimeout(1500);
    check(/\/operations\/new\?suggestion=1\.1$/.test(page.url()), 'the form stays open: nothing navigated away');
    check(creates.length === 0, 'opening the form sent no create request');
    // action=, host= and param= next to the reference are ignored.
    check(await status(page, base, '/operations/new?suggestion=1.1&action=core.facts&host=e2e-two&param=unit%3Devil.service') === 200,
      'the suggestion form with extra parameters answers 200');
    f = await checkForm('step 1 with action=, host=, param=', 'service.restart');
    await page.waitForTimeout(1000);
    check(creates.length === 0, 'still no create request');
    check(JSON.stringify(await opIDs(page, base)) === JSON.stringify(before), 'the operation list is unchanged after opening the forms');
    for (const ref of ['99.1', '1.3', '1.4', '1.0', '01.1', 'abc', '1.1.1']) {
      check(await status(page, base, '/operations/new?suggestion=' + encodeURIComponent(ref)) === 404,
        'suggestion ' + JSON.stringify(ref) + ' (unknown, host gone, not an action or malformed) opens no form');
    }

    // --- 4. A LOW action from a suggestion needs the security key (D9) -----
    await page.goto(base + '/dashboard');
    await Promise.all([page.waitForNavigation({ timeout: 15000 }), page.click('#session-open')]);
    check(/Privileged session: active/.test(await page.textContent('main')), 'privileged session opened with the security key');
    // Control: the same trusted LOW class without a suggestion runs inside
    // the session without a per-execution assertion.
    await page.goto(base + '/operations/new?action=service.list&host=e2e-host');
    check(await page.locator('#operation-form p.banner').count() === 0, 'a plain form has no suggestion banner');
    let g = await gets(page);
    await Promise.all([page.waitForURL(/\/operations\/[0-9a-f-]{36}$/, { timeout: 15000 }), page.click('#operation-create')]);
    let main = await page.textContent('main');
    check(/Risk \(decided by the executor\): LOW/.test(main) && !/State: pending/.test(main) && await page.locator('#operation-approve').count() === 0,
      'control: a LOW action not from a suggestion needs no security key in the session');
    check(await gets(page) === g, 'control: no security key prompt');

    await openOpsTab(page, base);
    await Promise.all([page.waitForURL(/\/operations\/new\?suggestion=1\.2$/, { timeout: 15000 }),
      page.click('#note-1 a.button[href="/operations/new?suggestion=1.2"]')]);
    f = await checkForm('step 2', 'package.refresh');
    check(f.ref === '1.2', 'the form carries the suggestion reference 1.2');
    check(await page.evaluate(() => /declared LOW/.test(document.querySelector('#operation-form input[name="action"][value="package.refresh"]').closest('label').textContent)),
      'the catalog declares package.refresh LOW');
    g = await gets(page);
    const createsBefore = creates.length;
    await Promise.all([page.waitForURL(/\/operations\/[0-9a-f-]{36}$/, { timeout: 15000 }), page.click('#operation-create')]);
    check(creates.length === createsBefore + 1, 'the human click sent exactly one create request');
    const suggestedURL = page.url();
    main = await page.textContent('main');
    check(/Risk \(decided by the executor\): MEDIUM/.test(main), 'the LOW action from a suggestion is raised to MEDIUM');
    check(/State: pending/.test(main), 'the execution is pending');
    check(await page.locator('#operation-approve').isVisible(), 'the page asks for the security key (Approve with security key)');
    const opts = await page.evaluate(() => JSON.parse(document.getElementById('approval').dataset.options));
    const challenge = (opts.publicKey || opts).challenge;
    check(typeof challenge === 'string' && challenge.length > 0, 'the approval carries a WebAuthn challenge');
    check(await gets(page) === g, 'no security key prompt started by itself');
    await page.waitForTimeout(2000);
    await page.reload();
    check(/State: pending/.test(await page.textContent('main')), 'without an assertion the execution stays pending');
    // The key is asked when the human clicks; an assertion that never
    // reaches the server leaves the execution pending.
    await page.route('**/operations/approve', (r) => r.abort());
    await page.click('#operation-approve');
    await page.waitForFunction((n) => JSON.parse(sessionStorage.getItem('__gets') || '[]').length > n, g, { timeout: 15000 });
    await page.waitForFunction(() => /\S/.test(document.getElementById('message').textContent) && !/Touch your security key/.test(document.getElementById('message').textContent), null, { timeout: 15000 });
    check(true, 'clicking approve asks the security key for an assertion');
    await page.unroute('**/operations/approve');
    await page.goto(suggestedURL);
    main = await page.textContent('main');
    check(/State: pending/.test(main) && !/success/.test(main), 'with the assertion withheld the execution is still pending and nothing ran');

    // Omitting the reference changes nothing: the server matches the stored
    // step (same family, same host).
    await page.goto(base + '/operations/new?action=package.refresh&host=e2e-host');
    check(await page.locator('#operation-form p.banner').count() === 0, 'the plain form has no banner and no reference');
    await Promise.all([page.waitForURL(/\/operations\/[0-9a-f-]{36}$/, { timeout: 15000 }), page.click('#operation-create')]);
    main = await page.textContent('main');
    check(/Risk \(decided by the executor\): MEDIUM/.test(main) && /State: pending/.test(main) && await page.locator('#operation-approve').count() === 1,
      'the same action without the reference is still raised to MEDIUM and pending (match rule)');
    // A forged reference is refused, never planned unmarked.
    const afterSuggest = await opIDs(page, base);
    await page.goto(base + '/operations/new');
    const forged = await page.evaluate(async () => {
      try {
        await nebulaWebAuthn.post('/operations/create', { action: 'package.refresh', hosts: ['e2e-host'], params: {}, suggestion: '99.1' });
        return 'created';
      } catch (e) {
        return e.message;
      }
    });
    check(forged === 'unknown agent suggestion', 'a forged suggestion reference is refused (' + forged + ')');
    check(JSON.stringify(await opIDs(page, base)) === JSON.stringify(afterSuggest), 'the refused reference created no operation');

    // --- 5. Interim measures, dismiss, settings ------------------------------
    await openOpsTab(page, base);
    check(await page.locator('#note-1 ul.assistant-mitigations a, #note-1 ul.assistant-mitigations button, #note-1 ul.assistant-mitigations form').count() === 0,
      'an interim measure has no button');
    const beforeDismiss = await opIDs(page, base);
    await openOpsTab(page, base);
    check(await page.locator('#note-2').count() === 1, 'card 2 is shown before the dismiss');
    await page.click('#note-2 footer form button[type=submit]');
    await page.waitForSelector('#note-2', { state: 'detached', timeout: 15000 });
    check(await page.locator('#note-1').count() === 1, 'dismissing card 2 leaves card 1');
    check(await status(page, base, '/assistant/ops') === 200 && await page.locator('#note-2').count() === 0 && await page.locator('#note-1').count() === 1,
      'the dismissed card stays hidden after a reload');
    check(await status(page, base, '/assistant/ops/notes/2') === 200, 'the dismissed card detail page answers 200');
    const ro = await page.evaluate(() => ({
      text: document.querySelector('#note-2 .assistant-card__readonly') ? document.querySelector('#note-2 .assistant-card__readonly').textContent : '',
      buttons: document.querySelectorAll('#note-2 a.button, #note-2 form, #note-2 button').length,
    }));
    check(/dismissed/.test(ro.text) && ro.buttons === 0, 'the dismissed card is read only: no step button, no dismiss form');
    check(JSON.stringify(await opIDs(page, base)) === JSON.stringify(beforeDismiss), 'dismissing changed no operation');

    // Ops-Agent settings (D12): saved only with a security key assertion.
    check(await status(page, base, '/settings') === 200, '/settings answers 200');
    const readSettings = () => page.evaluate(() => ({
      version: document.getElementById('ops-agent-form').dataset.version,
      model: document.getElementById('ops-agent-model').value,
    }));
    const s0 = await readSettings();
    // a) The prompt is shown, but the assertion never reaches the server.
    await page.route('**/settings/ops-agent/commit', (r) => r.abort());
    await page.fill('#ops-agent-model', 'harness-model-1');
    g = await gets(page);
    await page.click('#ops-agent-submit');
    await page.waitForFunction(() => !document.getElementById('ops-agent-submit').disabled &&
      /\S/.test(document.getElementById('ops-agent-message').textContent) &&
      !/Touch your security key/.test(document.getElementById('ops-agent-message').textContent), null, { timeout: 15000 });
    check(await gets(page) === g + 1, 'saving the Ops-Agent settings asks the security key');
    await page.unroute('**/settings/ops-agent/commit');
    await page.reload();
    let s = await readSettings();
    check(s.version === s0.version && s.model === s0.model, 'without the assertion nothing was saved');
    // b) No or a forged assertion is refused by the server.
    const refused = await page.evaluate(async (v) => {
      const body = {
        enabled: false, base_url: document.getElementById('ops-agent-url').value.trim(), model: 'harness-model-forged',
        allow_plain_http: document.getElementById('ops-agent-plain').checked, data_class: document.getElementById('ops-agent-data-class').value,
        language: document.getElementById('ops-agent-language').value, operator_instructions: document.getElementById('ops-agent-instructions').value,
        base_version: Number(v), confirm_url_change: false,
      };
      const out = [];
      const begin = await nebulaWebAuthn.post('/settings/ops-agent/begin', body);
      for (const assertion of [undefined, null, { id: 'AAAA', rawId: 'AAAA', type: 'public-key', response: {} }]) {
        try {
          await nebulaWebAuthn.post('/settings/ops-agent/commit', { id: begin.id, assertion });
          out.push('saved');
        } catch (e) {
          out.push(e.message);
        }
      }
      return out;
    }, s0.version);
    check(refused[0] === 'a fresh security key assertion is required' && refused[1] === 'a fresh security key assertion is required',
      'a commit without an assertion is refused (' + refused.slice(0, 2).join('; ') + ')');
    check(refused[2] === 'the security key assertion was refused', 'a forged assertion is refused (' + refused[2] + ')');
    await page.reload();
    s = await readSettings();
    check(s.version === s0.version && s.model === s0.model, 'the refused commits saved nothing');
    // c) With the key the change is saved.
    await page.fill('#ops-agent-model', 'harness-model-2');
    g = await gets(page);
    await Promise.all([page.waitForNavigation({ timeout: 15000 }), page.click('#ops-agent-submit')]);
    s = await readSettings();
    check(await gets(page) === g + 1 && Number(s.version) === Number(s0.version) + 1 && s.model === 'harness-model-2',
      'with the security key assertion the change is saved (version ' + s.version + ')');

    check(await page.evaluate(() => window.__pwned) === undefined, 'no hostile value ran script on any page');
    const csp = await cspViolations(page);
    check(csp.length === 0 && cspReports.length === 0, 'no Content Security Policy violation' +
      (csp.length || cspReports.length ? ': ' + csp.concat(cspReports).join('; ') : ''));
    const errs = pageErrors.filter((e) => !/Failed to fetch|aborted/i.test(e));
    check(errs.length === 0, 'no script errors' + (errs.length ? ': ' + errs.join('; ') : ''));
  } finally {
    await browser.close();
  }
  console.log('ops agent browser test passed');
})().catch((e) => {
  console.error(e);
  process.exit(1);
});

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

  // Operation: collect facts on the enrolled test host, approved with the key.
  await page.goto(base + '/operations/new');
  await page.check('input[name="host"][value="e2e-host"]');
  await Promise.all([page.waitForURL(/\/operations\/[0-9a-f-]{36}$/, { timeout: 15000 }), page.click('#operation-create')]);
  check(/Risk \(decided by the executor\): HIGH/.test(await page.textContent('main')), 'the executor raises the untrusted built-in script to HIGH');
  await Promise.all([page.waitForNavigation({ timeout: 15000 }), page.click('#operation-approve')]);
  let finished = false;
  for (let i = 0; i < 30 && !finished; i++) {
    finished = /State: finished/.test(await page.textContent('main'));
    if (!finished) { await new Promise((r) => setTimeout(r, 500)); await page.reload(); }
  }
  const main = await page.textContent('main');
  check(finished && /success/.test(main) && /Kernel/.test(main) && /Linux/.test(main), 'approved operation ran on the host and shows its facts');
  await page.goto(base + '/operations');
  check(/core\.facts/.test(await page.textContent('main')), 'the operation is listed');

  // Staged operation: the canary first; the second host only after the
  // gate, which a HIGH rollout opens with the security key.
  await page.goto(base + '/operations/new');
  check(await page.locator('#plan-size').isHidden(), 'rollout options stay hidden for "all at once"');
  await page.check('input[name="host"][value="e2e-host"]');
  await page.check('input[name="host"][value="e2e-two"]');
  await page.check('input[name="preset"][value="canary"]');
  check(await page.locator('#plan-size').isVisible(), 'choosing a canary rollout shows its options');
  await Promise.all([page.waitForURL(/\/operations\/[0-9a-f-]{36}$/, { timeout: 15000 }), page.click('#operation-create')]);
  let staged = await page.textContent('main');
  check(/1\. canary/.test(staged) && /2\. rest/.test(staged) && /e2e-two/.test(staged), 'the planned rollout shows its stages before approval');
  await Promise.all([page.waitForNavigation({ timeout: 15000 }), page.click('#operation-approve')]);
  let gate = false;
  for (let i = 0; i < 40 && !gate; i++) {
    gate = (await page.locator('.gate-button[data-kind="open"]').count()) > 0;
    if (!gate) { await new Promise((r) => setTimeout(r, 500)); await page.reload(); }
  }
  staged = await page.textContent('main');
  check(gate && /continue to stage 2/.test(staged) && /Continue to stage 2 with security key/.test(staged),
    'the canary ran and the rollout waits at the gate');
  await Promise.all([page.waitForNavigation({ timeout: 15000 }), page.click('.gate-button[data-kind="open"]')]);
  finished = false;
  for (let i = 0; i < 40 && !finished; i++) {
    finished = /State: finished/.test(await page.textContent('main'));
    if (!finished) { await new Promise((r) => setTimeout(r, 500)); await page.reload(); }
  }
  check(finished && (await page.locator('td:text-is("success")').count()) === 2, 'stage 2 ran after the gate was opened with the key');

  // Scheduled checks: only actions the executor rates LOW can be
  // scheduled; a schedule is approved once with the security key.
  await page.goto(base + '/schedules');
  await page.check('input[name="action"][value="core.facts"]');
  await page.check('input[name="host"][value="e2e-host"]');
  await page.click('#schedule-create');
  await page.waitForFunction(() => /refused|LOW/.test(document.getElementById('message').textContent), null, { timeout: 15000 });
  check(/not LOW/.test(await page.textContent('#message')), 'an action the executor does not trust as LOW cannot be scheduled');
  await page.uncheck('input[name="action"][value="core.facts"]');
  await page.check('input[name="action"][value="service.list"]');
  await Promise.all([page.waitForNavigation({ timeout: 15000 }), page.click('#schedule-create')]);
  const schedRow = await page.textContent('section[aria-label="Scheduled checks"] tbody');
  check(/service\.list/.test(schedRow) && /active/.test(schedRow) && /e2e-host/.test(schedRow), 'a schedule of a trusted LOW action is approved with the key');

  // Check updates on the same host (a real apt simulation on the test machine).
  await page.goto(base + '/operations/new');
  await page.check('input[name="action"][value="package.list_updates"]');
  await page.check('input[name="host"][value="e2e-host"]');
  await Promise.all([page.waitForURL(/\/operations\/[0-9a-f-]{36}$/, { timeout: 15000 }), page.click('#operation-create')]);
  await Promise.all([page.waitForNavigation({ timeout: 15000 }), page.click('#operation-approve')]);
  finished = false;
  for (let i = 0; i < 60 && !finished; i++) {
    finished = /State: finished/.test(await page.textContent('main'));
    if (!finished) { await new Promise((r) => setTimeout(r, 500)); await page.reload(); }
  }
  check(finished && /\d+ updates, \d+ security/.test(await page.textContent('main')), 'update check ran and shows the update list');
  await page.goto(base + '/inventory');
  check(/checked \d{4}-\d{2}-\d{2}/.test(await page.textContent('tr[data-id="e2e-host"]')), 'the inventory shows the update status');
  check(/(READY|WARNING)/.test(await page.textContent('tr[data-id="e2e-host"]')), 'the inventory shows the Ops State');
  // Runbooks: write one, save it as version 1, plan it with a parameter;
  // the executor does not know the script, so it needs the key (HIGH).
  await page.goto(base + '/runbooks/new');
  await page.fill('#runbook-slug', 'hello');
  await page.fill('#runbook-title', 'Say hello');
  await page.selectOption('#runbook-risk', 'LOW');
  await page.click('#runbook-param-add');
  await page.fill('.param-row .param-name', 'who');
  await page.fill('.param-row .param-label', 'Who');
  await page.fill('#runbook-body', 'echo "hello $NEBULA_P_WHO from runbook"\n');
  await Promise.all([page.waitForURL(/\/runbooks\/hello$/, { timeout: 15000 }), page.click('#runbook-save')]);
  check(/Runbook hello, version 1/.test(await page.textContent('main')), 'a saved runbook shows its first version');
  await Promise.all([page.waitForNavigation({ timeout: 15000 }), page.click('a[href="/operations/new?action=runbook.hello"]')]);
  check(await page.isChecked('input[name="action"][value="runbook.hello"]'), 'planning from the runbook preselects it');
  await page.check('input[name="host"][value="e2e-host"]');
  await page.fill('label.param[data-action="runbook.hello"] input', 'nebula');
  await Promise.all([page.waitForURL(/\/operations\/[0-9a-f-]{36}$/, { timeout: 15000 }), page.click('#operation-create')]);
  check(/Risk \(decided by the executor\): HIGH/.test(await page.textContent('main')), 'an untrusted runbook script is HIGH');
  await Promise.all([page.waitForNavigation({ timeout: 15000 }), page.click('#operation-approve')]);
  finished = false;
  for (let i = 0; i < 60 && !finished; i++) {
    finished = /State: finished/.test(await page.textContent('main'));
    if (!finished) { await new Promise((r) => setTimeout(r, 500)); await page.reload(); }
  }
  check(finished && /hello nebula from runbook/.test(await page.textContent('main')), 'the runbook ran with its parameter');
  // Trust that version on the executor with the key: it then runs LOW.
  await page.goto(base + '/runbooks/hello');
  check(/not trusted/.test(await page.textContent('main')), 'the runbook version is not trusted yet');
  await Promise.all([page.waitForNavigation({ timeout: 15000 }), page.click('#runbook-trust')]);
  check(/Executor: trusted as LOW/.test(await page.textContent('main')), 'the runbook version is trusted with the security key');
  await page.goto(base + '/operations/new?action=runbook.hello');
  await page.check('input[name="host"][value="e2e-host"]');
  await page.fill('label.param[data-action="runbook.hello"] input', 'again');
  await Promise.all([page.waitForURL(/\/operations\/[0-9a-f-]{36}$/, { timeout: 15000 }), page.click('#operation-create')]);
  check(/Risk \(decided by the executor\): LOW/.test(await page.textContent('main')), 'a trusted runbook runs at its declared risk');
  // Service actions take a unit name; the server refuses anything but a plain unit name.
  await page.goto(base + '/operations/new');
  check(await page.locator('label.param[data-action="service.restart"]').isHidden(), 'parameter fields stay hidden until their action is chosen');
  await page.check('input[name="action"][value="service.restart"]');
  await page.check('input[name="host"][value="e2e-host"]');
  check(await page.locator('label.param[data-action="service.restart"]').isVisible(), 'choosing a service action shows its unit field');
  await page.fill('label.param[data-action="service.restart"] input', '-x');
  await page.click('#operation-create');
  await page.waitForFunction(() => /unit/.test(document.getElementById('message').textContent), null, { timeout: 15000 });
  check(/\/operations\/new$/.test(page.url()), 'an invalid unit name is refused before anything is proposed');
  await page.fill('label.param[data-action="service.restart"] input', 'cron.service');
  await Promise.all([page.waitForURL(/\/operations\/[0-9a-f-]{36}$/, { timeout: 15000 }), page.click('#operation-create')]);
  check(/service\.restart .*with \{"unit":"cron\.service"\}/.test(await page.textContent('main')), 'the planned service operation shows its parameters');
  // Re-pin a host whose key changed, from the dashboard, with the key (UV).
  await page.goto(base + '/dashboard');
  check(/e2e-moved/.test(await page.textContent('section[aria-label="Host key mismatch"]')), 'the dashboard shows the host with a changed key');
  await page.click('.repin-start[data-host="e2e-moved"]');
  await page.waitForSelector('#repin-panel:not([hidden])', { timeout: 15000 });
  check(/SHA256:/.test(await page.textContent('#repin-presented')) && /HIGH|CRITICAL/.test(await page.textContent('#repin-risk')),
    'the re-pin proposal shows the new key and a HIGH risk');
  await page.click('#repin-approve');
  await page.waitForFunction(() => /compared the fingerprint/.test(document.getElementById('message').textContent), null, { timeout: 15000 });
  check(true, 're-pin needs the fingerprint comparison to be confirmed');
  await page.check('#repin-confirm');
  await page.click('#repin-approve');
  await page.waitForFunction(() => /Re-pinned|failed|refused|not accepted/.test(document.getElementById('message').textContent), null, { timeout: 30000 });
  check(/Re-pinned e2e-moved/.test(await page.textContent('#message')), 'host re-pinned after the security key approval');
  await page.goto(base + '/dashboard');
  check(!/e2e-moved/.test(await page.textContent('main')), 'the re-pinned host is no longer blocked');
  // Bulk enrollment: read the new host's key, approve the table, pin.
  await page.goto(base + '/inventory/enroll');
  check(await page.locator('tr.enroll-row[data-host="e2e-new"]').count() === 1 &&
    await page.locator('tr.enroll-row[data-host="e2e-host"]').count() === 0, 'the enrollment page lists only hosts without a pinned key');
  await page.check('tr.enroll-row[data-host="e2e-new"] .enroll-pick');
  await page.click('#enroll-read');
  await page.waitForFunction(() => /SHA256:/.test(document.querySelector('tr.enroll-row[data-host="e2e-new"] .enroll-fp').textContent), null, { timeout: 30000 });
  check(true, 'the executor read the new host key');
  await page.check('#enroll-confirm');
  await page.click('#enroll-approve');
  await page.waitForFunction(() => /enrolled|failed|refused|not accepted/.test(document.getElementById('message').textContent), null, { timeout: 30000 });
  check(/1 of 1 hosts enrolled/.test(await page.textContent('#message')) &&
    /pinned, login works/.test(await page.textContent('tr.enroll-row[data-host="e2e-new"] .enroll-result')), 'host enrolled after the security key approval, login works');
  await page.goto(base + '/dashboard');
  await Promise.all([page.waitForNavigation({ timeout: 15000 }), page.click('#executor-lock')]);
  check(/Privileged session: none/.test(await page.textContent('main')), 'lock ends the privileged session');

  // Inventory: add, edit, reject a duplicate, delete (JSON POSTs with a real Origin).
  await page.goto(base + '/inventory');
  await page.fill('#host-id', 'web-01');
  await page.fill('#host-display-name', 'Web 1');
  await page.selectOption('#host-environment', 'PROD');
  await page.fill('#host-endpoints', '192.168.0.10\n[fd00::10]:2222');
  await page.fill('#host-tags', 'role=web');
  await Promise.all([page.waitForNavigation({ timeout: 15000 }), page.click('#host-submit')]);
  const row = () => page.locator('tr[data-id="web-01"]');
  check(/Web 1/.test(await row().textContent()) && /\[fd00::10\]:2222/.test(await row().textContent()), 'host added from the inventory page');
  await row().locator('.inventory__edit').click();
  check(await page.inputValue('#host-tags') === 'role=web' && await page.$eval('#host-id', (e) => e.readOnly), 'edit fills the form and locks the ID');
  await page.fill('#host-display-name', 'Web one');
  await Promise.all([page.waitForNavigation({ timeout: 15000 }), page.click('#host-submit')]);
  check(/Web one/.test(await row().textContent()), 'host edited');
  await page.fill('#host-id', 'web-01');
  await page.fill('#host-endpoints', '192.168.0.11');
  await page.click('#host-submit');
  await page.waitForFunction(() => /already exists/.test(document.getElementById('message').textContent), null, { timeout: 15000 });
  check(true, 'a duplicate host ID is refused');
  await row().locator('.inventory__delete').click();
  await page.waitForFunction(() => /Type the host ID/.test(document.getElementById('message').textContent));
  await row().locator('.inventory__delete-confirm').fill('web-01');
  await Promise.all([page.waitForNavigation({ timeout: 15000 }), row().locator('.inventory__delete').click()]);
  check(await row().count() === 0, 'host deleted after typing its ID');

  // CSV import: map columns, preview, import the importable rows.
  await page.goto(base + '/inventory/import');
  await page.setInputFiles('#csv-file', { name: 'hosts.csv', mimeType: 'text/csv',
    buffer: Buffer.from('server_name,ip,vpn_ip,env\ncsv-01,10.0.0.1,10.8.0.1,PROD\ncsv-02,10.0.0.2,,DEV\ncsv-bad,not an ip,,DEV\n') });
  await page.waitForSelector('#mapping-panel:not([hidden])', { timeout: 15000 });
  await page.selectOption('select[data-field="id"]', 'server_name');
  await page.selectOption('select[data-field="endpoint1"]', 'ip');
  await page.selectOption('select[data-field="endpoint2"]', 'vpn_ip');
  await page.selectOption('select[data-field="environment"]', 'env');
  await page.click('#import-preview');
  await page.waitForSelector('#preview-panel:not([hidden])', { timeout: 15000 });
  check(await page.isDisabled('.import-row[value="3"]') && await page.isChecked('.import-row[value="1"]'), 'CSV preview marks the bad row as not importable');
  await page.click('#import-commit');
  await page.waitForSelector('#result-panel:not([hidden])', { timeout: 15000 });
  check((await page.textContent('#results')).split('created').length === 3, 'two rows imported');
  await page.goto(base + '/inventory');
  check(await page.locator('tr[data-id="csv-01"]').count() === 1 && await page.locator('tr[data-id="csv-02"]').count() === 1, 'imported hosts are in the inventory');
  await page.goto(base + '/dashboard');

  const cookies = await ctx.cookies();
  const sc = cookies.find((c) => c.name === '__Host-nebula_session');
  check(sc && sc.secure && sc.httpOnly && sc.sameSite === 'Strict', 'session cookie is __Host-, Secure, HttpOnly, SameSite=Strict');
  await Promise.all([page.waitForURL('**/login', { timeout: 10000 }), page.click('#logout')]);
  await page.goto(base + '/dashboard');
  check(new URL(page.url()).pathname === '/login', 'after logout the dashboard redirects to the login');

  // TOTP recovery: reading session, privileged work blocked.
  await page.request.get(base + '/__totp/setup');
  const rcode = await (await page.request.get(base + '/__totp/next')).text();
  await page.goto(base + '/login');
  await page.click('details.recovery summary');
  await page.fill('#recovery-code', rcode);
  await Promise.all([page.waitForURL('**/dashboard', { timeout: 15000 }), page.click('#recovery button')]);
  check(/Recovery login: privileged work is blocked/.test(await page.textContent('main')), 'recovery login opens the dashboard with the recovery notice');
  await page.click('#session-open');
  await page.waitForFunction(() => /blocked after a recovery login/.test(document.getElementById('message').textContent), null, { timeout: 15000 });
  check(true, 'privileged session refused after a recovery login');
  await browser.close();
})().catch(e => { console.error('E2E FAIL', e); process.exit(1); });

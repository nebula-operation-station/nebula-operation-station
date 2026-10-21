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
  const schedCard = await page.textContent('section[aria-label="Scheduled checks"] .schedule-card');
  check(/service\.list/.test(schedCard) && /active/.test(schedCard) && /e2e-host/.test(schedCard), 'a schedule of a trusted LOW action is approved with the key');

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
  check(/checked \S/.test(await page.textContent('tr[data-id="e2e-host"]')) && await page.locator('tr[data-id="e2e-host"] .host-updates time[datetime]').count() === 1, 'the inventory shows the update status');
  check(/(ready|warning|ok)/i.test(await page.textContent('tr[data-id="e2e-host"]')), 'the inventory shows the Ops State');
  // Selection: the bulk bar appears; reboot opens the operation form with
  // the hosts preselected; refresh creates the read operations.
  check(await page.locator('#bulkbar').isHidden(), 'no bulk bar without a selection');
  await page.check('tr[data-id="e2e-host"] input.host-select');
  check(/1 selected/.test(await page.textContent('#bulkbar')), 'selecting a host shows the bulk bar');
  await page.fill('#inventory-filter', 'no-such-host');
  check(await page.locator('#bulkbar').isHidden(), 'a host hidden by the filter is unselected');
  await page.fill('#inventory-filter', '');
  await page.check('tr[data-id="e2e-host"] input.host-select');
  await Promise.all([page.waitForURL(/\/operations\/new\?/, { timeout: 15000 }), page.click('#bulk-reboot')]);
  check(await page.isChecked('input[name="action"][value="system.reboot"]') && await page.isChecked('input[name="host"][value="e2e-host"]'),
    'reboot opens the operation form with the action and the host preselected');
  await page.goto(base + '/inventory');
  await page.check('tr[data-id="e2e-host"] input.host-select');
  const opsBefore = await page.request.get(base + '/operations').then((r) => r.text()).then((t) => (t.match(/core\.facts/g) || []).length);
  await Promise.all([page.waitForURL(/\/operations$/, { timeout: 15000 }), page.click('#bulk-refresh')]);
  check((((await page.content()).match(/core\.facts/g)) || []).length > opsBefore && /service\.list/.test(await page.textContent('main')),
    'refresh of the selection creates the read operations');
  // The bulk bar can open the schedules page with the four reads and the
  // selection preselected; the More menu offers to keep all hosts fresh.
  await page.goto(base + '/inventory');
  check(await page.locator('a[href*="/schedules?all=1"]').count() === 1, 'the inventory offers to keep all hosts fresh');
  await page.check('tr[data-id="e2e-host"] input.host-select');
  await Promise.all([page.waitForURL(/\/schedules\?/, { timeout: 15000 }), page.click('#bulk-schedule')]);
  check(await page.isChecked('input[name="host"][value="e2e-host"]') &&
    (await page.locator('input[name="action"]:checked').count()) === 4 &&
    (await page.inputValue('#schedule-interval')) === '360' &&
    (await page.inputValue('#schedule-days')) === '30',
    'the bulk bar opens the schedules page with the four reads, the host and the 6 h preset preselected');
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

  // Inventory: add (dialog, JSON POST), edit and delete (host page settings
  // tab, form POSTs), reject a duplicate ID. All with a real Origin.
  await page.goto(base + '/inventory');
  await page.click('a.add-host');
  await page.waitForSelector('#add-host-dialog[open]');
  await page.fill('#host-id', 'web-01');
  await page.fill('#host-display-name', 'Web 1');
  await page.selectOption('#host-environment', 'PROD');
  await page.fill('#host-endpoints', '192.168.0.10\n[fd00::10]:2222');
  await page.fill('#host-tags', 'role=web');
  await Promise.all([page.waitForURL(/\/hosts\/web-01/, { timeout: 15000 }), page.click('#host-submit')]);
  check(/Next: read and pin the host key/.test(await page.textContent('main')) && /\[fd00::10\]:2222/.test(await page.textContent('main')),
    'host added from the inventory dialog; its page points to enrollment');
  const row = () => page.locator('tr[data-id="web-01"]');
  await page.goto(base + '/hosts/web-01?tab=settings');
  check(await page.inputValue('textarea[name="tags"]') === 'role=web' && await page.$eval('form[action$="/settings"] input[name="id"]', (e) => e.readOnly),
    'the settings tab shows the host and locks the ID');
  await page.fill('input[name="display_name"]', 'Web one');
  await Promise.all([page.waitForNavigation({ timeout: 15000 }), page.click('form[action$="/settings"] button[type="submit"]')]);
  await page.goto(base + '/inventory');
  check(/Web one/.test(await row().textContent()), 'host edited');
  await page.click('a.add-host');
  await page.waitForSelector('#add-host-dialog[open]');
  await page.fill('#host-id', 'web-01');
  await page.fill('#host-endpoints', '192.168.0.11');
  await page.click('#host-submit');
  await page.waitForFunction(() => /already exists/.test(document.getElementById('message').textContent), null, { timeout: 15000 });
  check(true, 'a duplicate host ID is refused');
  await page.goto(base + '/hosts/web-01?tab=settings');
  const del = page.locator('form[action$="/delete"] button[type="submit"]');
  check(await del.isDisabled(), 'delete stays disabled until the ID is typed');
  await page.fill('input[name="confirm_id"]', 'web-01');
  await Promise.all([page.waitForNavigation({ timeout: 15000 }), del.click()]);
  await page.goto(base + '/inventory');
  check(await row().count() === 0, 'host deleted after typing its ID');

  // Network (M9-1): a network with its address grid, a reservation, an
  // asset that becomes a managed host.
  await page.goto(base + '/network');
  check(/Scan a network/.test(await page.textContent('main')), 'the network page opens in quick mode');
  await page.goto(base + '/network?mode=expert');
  await page.click('summary:has-text("Add network")');
  await page.fill('#net-id', 'lan');
  await page.fill('#net-name', 'LAN');
  await page.fill('#net-prefix', '192.168.10.0/24');
  await page.fill('#net-gateway', '192.168.10.1');
  await page.fill('#net-pools', 'servers 192.168.10.10-192.168.10.19');
  await Promise.all([page.waitForURL(/\/network\/n\/lan$/, { timeout: 15000 }), page.click('#network-form button[type="submit"]')]);
  check(await page.locator('.ipgrid__cell').count() === 256 && await page.locator('.ipgrid__cell.ip--ASSIGNED').count() === 1,
    'a /24 shows every address, the gateway as assigned');
  await page.fill('#entry-address', '192.168.10.40');
  await page.fill('#entry-note', 'new switch');
  await Promise.all([page.waitForNavigation({ timeout: 15000 }), page.click('#entry-form button[type="submit"]')]);
  check(await page.getAttribute('.ipgrid__cell.ip--RESERVED', 'title') === '192.168.10.40 RESERVED: new switch', 'an address is reserved with a note');
  check(/192\.168\.10\.2\b/.test(await page.textContent('section[aria-label="Network"]')), 'a free address is suggested');
  await page.goto(base + '/network');
  check(/seg-item--active[^>]*>Expert/.test(await page.innerHTML('main')), 'the expert mode is remembered');
  await page.click('summary:has-text("Add asset")');
  await page.fill('#asset-id', 'nas');
  await page.fill('#asset-name', 'NAS');
  await page.selectOption('#asset-kind', 'nas');
  await page.fill('#asset-addresses', '192.168.10.21');
  await Promise.all([page.waitForURL(/\/network\/a\/nas$/, { timeout: 15000 }), page.click('#asset-form button[type="submit"]')]);
  await Promise.all([page.waitForNavigation({ timeout: 15000 }), page.click('a[href="/inventory?asset=nas"]')]);
  check(await page.inputValue('#host-id') === 'nas' && await page.inputValue('#host-endpoints') === '192.168.10.21',
    'add to managed hosts prefills the inventory form');
  await Promise.all([page.waitForURL(/\/network\/a\/nas$/, { timeout: 15000 }), page.click('#host-submit')]);
  check(await page.locator('a[href="/hosts/nas"]').count() === 1, 'the asset is linked to the new managed host');
  // Discovery (M9-2): queue a host discovery, let the test hook answer it
  // like nebula-discovery, review the staging and import.
  await page.goto(base + '/network/discovery');
  await page.fill('#scan-targets', '10.99.0.0/24');
  await page.click('#scan-form button[type="submit"]');
  await page.waitForFunction(() => /not inside a known network/.test(document.getElementById('message').textContent), null, { timeout: 15000 });
  check(true, 'a scan outside the known networks is refused');
  await page.fill('#scan-targets', '192.168.10.0/24');
  await Promise.all([page.waitForURL(/\/network\/discovery\/[0-9a-f-]{36}$/, { timeout: 15000 }), page.click('#scan-form button[type="submit"]')]);
  check(/Waiting for nebula-discovery/.test(await page.textContent('main')), 'the queued scan waits for nebula-discovery');
  check(await (await page.request.get(base + '/__discovery/answer')).text() === '1', 'the queued job reached the spool');
  await page.reload();
  check(/POSSIBLE MATCH/.test(await page.textContent('#staging')) && /NEW/.test(await page.textContent('#staging')) &&
    await page.locator('#staging b').count() === 0, 'the staging classifies the hosts and shows network text as text');
  await page.click('#import-all');
  await page.waitForFunction(() => /imported as/.test(document.getElementById('staging').textContent), null, { timeout: 15000 });
  check(await page.locator('#staging a[href="/network/a/printer"]').count() === 1, 'a new host is imported as an asset');
  await page.goto(base + '/network/a/nas');
  check(/aa:bb:cc:dd:ee:21/.test(await page.textContent('main')), 'the import adds the MAC the asset lacked');
  // Global search (M9-3) from the navigation.
  await page.fill('.nav__search input[name="q"]', '192.168.10.21');
  await Promise.all([page.waitForNavigation({ timeout: 15000 }), page.press('.nav__search input[name="q"]', 'Enter')]);
  check(await page.locator('main a[href="/network/a/nas"]').count() === 1 && /Address/.test(await page.textContent('main')) &&
    await page.locator('main a[href="/hosts/nas"]').count() >= 1, 'search by IP finds the asset, the managed host and the address');
  await page.goto(base + '/search?q=e2e-host');
  await Promise.all([page.waitForNavigation({ timeout: 15000 }), page.click('main a[href="/operations/new?host=e2e-host"]')]);
  check(await page.isChecked('input[name="host"][value="e2e-host"]'), 'the quick action opens the planner with the host selected');
  // History (M10-1): signed executor events and the server audit.
  await page.goto(base + '/history');
  check(/the newest page verified/.test(await page.textContent('main')) && /unlocked/.test(await page.textContent('section[aria-label="Executor events"]')),
    'history shows the verified executor events');
  check(/asset_saved/.test(await page.textContent('section[aria-label="Server audit"]')) && /hash chain intact/.test(await page.textContent('main')),
    'history shows the server audit with its hash chain');

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

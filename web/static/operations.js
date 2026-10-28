// SPDX-License-Identifier: AGPL-3.0-or-later
// Operations pages: plan an operation, approve it with the security key,
// follow it. Requests go through nebulaWebAuthn.post (fetch with a real
// Origin, decision 36); server text is shown with textContent only.
'use strict';

(() => {
  const w = nebulaWebAuthn;

  const form = document.getElementById('operation-form');
  if (form) {
    // Show the parameter fields of the chosen action only.
    const showParams = () => {
      const chosen = form.querySelector('input[name="action"]:checked');
      for (const l of form.querySelectorAll('.param')) l.hidden = !chosen || l.dataset.action !== chosen.value;
    };
    for (const r of form.querySelectorAll('input[name="action"]')) r.addEventListener('change', showParams);
    showParams();
    // Show the options of the chosen rollout preset only.
    const showPlan = () => {
      const preset = form.querySelector('input[name="preset"]:checked');
      for (const l of form.querySelectorAll('.stage-option')) {
        l.hidden = !preset || !l.dataset.for.split(' ').includes(preset.value);
      }
    };
    for (const r of form.querySelectorAll('input[name="preset"]')) r.addEventListener('change', showPlan);
    showPlan();
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const action = form.querySelector('input[name="action"]:checked');
      const hosts = Array.from(form.querySelectorAll('input[name="host"]:checked')).map((c) => c.value);
      if (!action) {
        w.show('Choose an action.', true);
        return;
      }
      if (hosts.length === 0) {
        w.show('Choose at least one host.', true);
        return;
      }
      const params = {};
      const secrets = {};
      for (const l of form.querySelectorAll('.param')) {
        if (l.dataset.action !== action.value) continue;
        const input = l.querySelector('input');
        if (input.dataset.secret) {
          secrets[input.dataset.secret] = input.value.trim();
        } else {
          params[input.dataset.param] = input.value.trim();
        }
      }
      const button = document.getElementById('operation-create');
      button.disabled = true;
      try {
        const body = { action: action.value, hosts, params };
        if (Object.keys(secrets).length > 0) body.secrets = secrets;
        const preset = form.querySelector('input[name="preset"]:checked');
        if (preset && preset.value !== 'single') {
          body.plan = {
            preset: preset.value,
            size: parseInt(document.getElementById('plan-size').value, 10) || 0,
            max_failed: parseInt(document.getElementById('plan-max-failed').value, 10) || 0,
            continue: document.getElementById('plan-continue').value,
          };
        }
        const r = await w.post('/operations/create', body);
        window.location.assign('/operations/' + encodeURIComponent(r.id));
      } catch (err) {
        w.show(err.message || 'Could not plan the operation.', true);
      } finally {
        button.disabled = false;
      }
    });
  }

  // List page: client-side text filter over action and host names (the
  // row's search text is built server side and lowercased there).
  const opsFilter = document.getElementById('operations-filter');
  if (opsFilter) {
    opsFilter.addEventListener('input', () => {
      const q = opsFilter.value.trim().toLowerCase();
      for (const row of document.querySelectorAll('tbody tr[data-search]')) {
        row.hidden = q !== '' && !row.dataset.search.includes(q);
      }
    });
  }

  const op = document.getElementById('operation');
  if (!op) return;

  const approve = document.getElementById('operation-approve');
  if (approve) {
    approve.addEventListener('click', async () => {
      approve.disabled = true;
      try {
        const options = JSON.parse(document.getElementById('approval').dataset.options);
        const typed = document.getElementById('typed-count');
        w.show('Touch your security key…', false);
        const cred = await navigator.credentials.get(w.requestOptions(options));
        await w.post('/operations/approve', {
          id: op.dataset.id,
          assertion: w.assertionJSON(cred),
          typed_count: typed ? parseInt(typed.value, 10) || 0 : 0,
        });
        window.location.reload();
      } catch (err) {
        w.show(err.name === 'NotAllowedError' ? 'Cancelled or timed out.' : (err.message || 'Could not approve.'), true);
      } finally {
        approve.disabled = false;
      }
    });
  }

  // "Check approval": the operation is approved on the executor host
  // (hardened path); ask the server to ask the executor, and reload when
  // the state changed (approved and dispatched).
  const check = document.getElementById('operation-check');
  if (check) {
    check.addEventListener('click', async () => {
      check.disabled = true;
      try {
        const r = await w.post('/operations/' + encodeURIComponent(op.dataset.id) + '/check', {});
        if (r.state !== 'pending') {
          window.location.reload();
          return;
        }
        w.show('Still pending on the executor host.', false);
      } catch (err) {
        w.show(err.message || 'Could not check the approval.', true);
      } finally {
        check.disabled = false;
      }
    });
  }

  // Gates of a staged operation: continue to the next stage or skip a
  // host. The executor says what is needed: nothing beyond the session
  // (done at once), or the security key over its gate challenge.
  for (const b of document.querySelectorAll('.gate-button')) {
    b.addEventListener('click', async () => {
      const gate = {
        id: op.dataset.id,
        kind: b.dataset.kind,
        stage: parseInt(b.dataset.stage || '0', 10),
        host: b.dataset.host || '',
      };
      b.disabled = true;
      try {
        const r = await w.post('/operations/gate', gate);
        if (!r.done) {
          w.show('Touch your security key…', false);
          const cred = await navigator.credentials.get(w.requestOptions(r.options));
          await w.post('/operations/gate/commit', Object.assign({ assertion: w.assertionJSON(cred) }, gate));
        }
        window.location.reload();
      } catch (err) {
        w.show(err.name === 'NotAllowedError' ? 'Cancelled or timed out.' : (err.message || 'Could not continue.'), true);
        b.disabled = false;
      }
    });
  }

  for (const b of document.querySelectorAll('.retry-button')) {
    b.addEventListener('click', async () => {
      b.disabled = true;
      try {
        await w.post('/operations/retry', { id: op.dataset.id, host: b.dataset.host });
        window.location.reload();
      } catch (err) {
        w.show(err.message || 'Could not retry.', true);
        b.disabled = false;
      }
    });
  }

  // Abort asks once more on the button itself (no browser dialogs).
  const abort = document.getElementById('rollout-abort');
  if (abort) {
    abort.addEventListener('click', async () => {
      if (!abort.dataset.armed) {
        abort.dataset.armed = '1';
        abort.textContent = 'Really abort? No further host will run.';
        return;
      }
      abort.disabled = true;
      try {
        await w.post('/operations/abort', { id: op.dataset.id });
        window.location.reload();
      } catch (err) {
        w.show(err.message || 'Could not abort.', true);
        abort.disabled = false;
      }
    });
  }

  // Follow a running operation.
  if (op.dataset.live) {
    setTimeout(() => window.location.reload(), 3000);
  }
})();

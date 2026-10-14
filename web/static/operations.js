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
      for (const l of form.querySelectorAll('.param')) {
        if (l.dataset.action !== action.value) continue;
        const input = l.querySelector('input');
        params[input.dataset.param] = input.value.trim();
      }
      const button = document.getElementById('operation-create');
      button.disabled = true;
      try {
        const r = await w.post('/operations/create', { action: action.value, hosts, params });
        window.location.assign('/operations/' + encodeURIComponent(r.id));
      } catch (err) {
        w.show(err.message || 'Could not plan the operation.', true);
      } finally {
        button.disabled = false;
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

  // Follow a running operation.
  if (op.dataset.live) {
    setTimeout(() => window.location.reload(), 3000);
  }
})();

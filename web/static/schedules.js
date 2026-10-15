// SPDX-License-Identifier: AGPL-3.0-or-later
// Scheduled checks: propose a schedule grant, approve it with the security
// key, revoke it. Server text is shown with textContent only.
'use strict';

(() => {
  const w = nebulaWebAuthn;

  const approve = async (id, options) => {
    w.show('Touch your security key…', false);
    const cred = await navigator.credentials.get(w.requestOptions(options));
    await w.post('/schedules/approve', { id, assertion: w.assertionJSON(cred) });
  };

  const form = document.getElementById('schedule-form');
  if (form) {
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const actions = Array.from(form.querySelectorAll('input[name="action"]:checked')).map((c) => c.value);
      const hosts = Array.from(form.querySelectorAll('input[name="host"]:checked')).map((c) => c.value);
      if (actions.length === 0 || hosts.length === 0) {
        w.show('Choose at least one action and one host.', true);
        return;
      }
      const button = document.getElementById('schedule-create');
      button.disabled = true;
      try {
        const r = await w.post('/schedules/create', {
          actions,
          hosts,
          interval_minutes: parseInt(document.getElementById('schedule-interval').value, 10),
          days: parseInt(document.getElementById('schedule-days').value, 10) || 0,
        });
        if (r.cli) {
          w.show('Approve it on the executor host: ' + r.command, false);
          return;
        }
        await approve(r.id, r.options);
        window.location.reload();
      } catch (err) {
        w.show(err.name === 'NotAllowedError' ? 'Cancelled or timed out; approve it from the list.' : (err.message || 'Could not propose the schedule.'), true);
      } finally {
        button.disabled = false;
      }
    });
  }

  for (const b of document.querySelectorAll('.schedule-approve')) {
    b.addEventListener('click', async () => {
      b.disabled = true;
      try {
        await approve(b.dataset.id, JSON.parse(b.dataset.options));
        window.location.reload();
      } catch (err) {
        w.show(err.name === 'NotAllowedError' ? 'Cancelled or timed out.' : (err.message || 'Could not approve.'), true);
        b.disabled = false;
      }
    });
  }

  for (const b of document.querySelectorAll('.schedule-revoke')) {
    b.addEventListener('click', async () => {
      if (!b.dataset.armed) {
        b.dataset.armed = '1';
        b.textContent = 'Really revoke?';
        return;
      }
      b.disabled = true;
      try {
        await w.post('/schedules/revoke', { id: b.dataset.id });
        window.location.reload();
      } catch (err) {
        w.show(err.message || 'Could not revoke.', true);
        b.disabled = false;
      }
    });
  }
})();

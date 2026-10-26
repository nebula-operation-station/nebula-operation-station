// SPDX-License-Identifier: AGPL-3.0-or-later
// "Pin to hosts…" (job ui5): the runbook and module pages pin one
// catalog action to the chosen inventory hosts (POST /actions/pin,
// fetch with a real Origin, decision 36). Pinning changes no risk and
// no approval. Server text is shown with textContent only.
'use strict';

(() => {
  const w = nebulaWebAuthn;
  for (const form of document.querySelectorAll('form.pin-to-hosts')) {
    const submit = form.querySelector('button[type="submit"]');
    const msg = form.parentElement.querySelector('.pin-to-hosts-message');
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      submit.disabled = true;
      msg.textContent = '';
      msg.classList.remove('message--error');
      const hosts = Array.from(form.querySelectorAll('input[name="pin-host"]:checked')).map((c) => c.value);
      if (hosts.length === 0) {
        msg.textContent = 'Choose at least one host.';
        msg.classList.add('message--error');
        submit.disabled = false;
        return;
      }
      try {
        await w.post('/actions/pin', { action: form.dataset.action, hosts });
        msg.textContent = 'Pinned to ' + hosts.length + ' host' + (hosts.length === 1 ? '' : 's') + '.';
        for (const c of form.querySelectorAll('input[name="pin-host"]:checked')) c.checked = false;
      } catch (err) {
        msg.textContent = err.message || 'Could not pin the action.';
        msg.classList.add('message--error');
      } finally {
        submit.disabled = false;
      }
    });
  }
})();

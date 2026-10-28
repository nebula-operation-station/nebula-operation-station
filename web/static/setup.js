// SPDX-License-Identifier: AGPL-3.0-or-later
'use strict';

(() => {
  const w = nebulaWebAuthn;
  const form = document.getElementById('setup');
  form.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const submit = form.querySelector('button');
    submit.disabled = true;
    try {
      const code = document.getElementById('code').value.trim();
      const done = await w.register(code, document.getElementById('message'));
      if (done.recovery_confirmation_required) {
        w.show('Security key registered. To end the recovery, confirm it on the executor host: nebula totp finish-recovery', false);
      } else {
        w.show('Security key registered. You can log in now.', false);
      }
      form.reset();
    } catch (e) {
      if (e.name === 'NotAllowedError') {
        w.show('Cancelled or timed out.', true);
      } else if (e.name === 'InvalidStateError') {
        w.show('This security key is already registered.', true);
      } else {
        w.show(e.message || 'Registration failed.', true);
      }
    } finally {
      submit.disabled = false;
    }
  });
})();

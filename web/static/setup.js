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
      const begin = await w.post('/setup/begin', { code });
      w.show('Touch the new security key…', false);
      const created = await navigator.credentials.create(w.creationOptions(begin.creation_options));
      const body = { registration_id: begin.registration_id, attestation: w.attestationJSON(created) };
      if (begin.authorization_options) {
        w.show('Now confirm with a security key that is already registered…', false);
        const confirm = await navigator.credentials.get(w.requestOptions(begin.authorization_options));
        body.assertion = w.assertionJSON(confirm);
      }
      await w.post('/setup/finish', body);
      w.show('Security key registered. You can log in now.', false);
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

// SPDX-License-Identifier: AGPL-3.0-or-later
'use strict';

(() => {
  const w = nebulaWebAuthn;
  const button = document.getElementById('login');
  button.addEventListener('click', async () => {
    button.disabled = true;
    try {
      w.show('Touch your security key…', false);
      const begin = await w.post('/login/begin');
      const cred = await navigator.credentials.get(w.requestOptions(begin.options));
      const done = await w.post('/login/finish', { login_id: begin.login_id, assertion: w.assertionJSON(cred) });
      window.location.assign(done.redirect === '/dashboard' ? '/dashboard' : '/');
    } catch (e) {
      if (e.data && e.data.setup) {
        w.show('No security key is registered yet. Register one first.', true);
      } else if (e.name === 'NotAllowedError') {
        w.show('Cancelled or timed out.', true);
      } else {
        w.show(e.message || 'Login failed.', true);
      }
    } finally {
      button.disabled = false;
    }
  });

  const recovery = document.getElementById('recovery');
  if (recovery) {
    recovery.addEventListener('submit', async (ev) => {
      ev.preventDefault();
      const submit = recovery.querySelector('button');
      submit.disabled = true;
      try {
        const code = document.getElementById('recovery-code').value.trim();
        const done = await w.post('/login/recovery', { code });
        window.location.assign(done.redirect === '/dashboard' ? '/dashboard' : '/');
      } catch (e) {
        w.show(e.message || 'Recovery login failed.', true);
      } finally {
        submit.disabled = false;
      }
    });
  }
})();

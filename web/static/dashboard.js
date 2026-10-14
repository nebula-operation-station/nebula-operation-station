// SPDX-License-Identifier: AGPL-3.0-or-later
// Dashboard actions: open the executor's privileged session with a
// user-verified assertion, and lock the executor.
'use strict';

(() => {
  const w = nebulaWebAuthn;
  const open = document.getElementById('session-open');
  const lock = document.getElementById('executor-lock');

  open.addEventListener('click', async () => {
    open.disabled = true;
    try {
      const begin = await w.post('/privileged/begin');
      w.show('Touch your security key…', false);
      const cred = await navigator.credentials.get(w.requestOptions(begin.options));
      await w.post('/privileged/finish', { assertion: w.assertionJSON(cred) });
      window.location.reload();
    } catch (e) {
      w.show(e.name === 'NotAllowedError' ? 'Cancelled or timed out.' : (e.message || 'Could not open the session.'), true);
    } finally {
      open.disabled = false;
    }
  });

  lock.addEventListener('click', async () => {
    lock.disabled = true;
    try {
      await w.post('/executor/lock');
      window.location.reload();
    } catch (e) {
      w.show(e.message || 'Could not lock the executor.', true);
    } finally {
      lock.disabled = false;
    }
  });
})();

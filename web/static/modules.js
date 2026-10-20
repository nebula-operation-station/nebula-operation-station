// SPDX-License-Identifier: AGPL-3.0-or-later
// Module import (raw .tar.gz body) and re-verification. Server text is
// shown with textContent only.
'use strict';

(() => {
  const w = nebulaWebAuthn;
  const form = document.getElementById('module-import');
  if (form) {
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const file = document.getElementById('module-file').files[0];
      if (!file) {
        w.show('Choose a module archive.', true);
        return;
      }
      const button = document.getElementById('module-import-button');
      button.disabled = true;
      try {
        const r = await fetch('/modules/import', { method: 'POST', headers: { 'Content-Type': 'application/gzip' }, body: file, credentials: 'same-origin' });
        const body = await r.json().catch(() => ({}));
        if (!r.ok) {
          throw new Error(body.error || 'Could not import the module.');
        }
        window.location.assign('/modules/' + encodeURIComponent(body.name));
      } catch (err) {
        w.show(err.message || 'Could not import the module.', true);
        button.disabled = false;
      }
    });
  }
  const verify = document.getElementById('module-verify');
  if (verify) {
    verify.addEventListener('click', async () => {
      verify.disabled = true;
      try {
        await w.post('/modules/verify', { name: verify.dataset.name, version: verify.dataset.version });
        window.location.reload();
      } catch (err) {
        w.show(err.message || 'Could not verify the module.', true);
        verify.disabled = false;
      }
    });
  }
})();

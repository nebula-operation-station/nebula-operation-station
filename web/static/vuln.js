// SPDX-License-Identifier: AGPL-3.0-or-later
// Maintainer decisions on findings (ADR 0011, VU-11): every form posts its
// fields to /vulnerabilities/decide/begin, signs the returned challenge
// with the security key and commits the assertion. Server text is shown
// with textContent only (nebulaWebAuthn.show).
'use strict';

(() => {
  const w = nebulaWebAuthn;
  for (const form of document.querySelectorAll('form.vuln-decision')) {
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const body = { kind: form.dataset.kind };
      for (const [k, v] of new FormData(form).entries()) {
        // The server rejects '\r'; send textarea line breaks as '\n'.
        if (typeof v === 'string') body[k] = v.replace(/\r\n?/g, '\n');
      }
      const buttons = form.querySelectorAll('button');
      buttons.forEach((b) => { b.disabled = true; });
      try {
        const begin = await w.post('/vulnerabilities/decide/begin', body);
        w.show('Touch your security key…', false);
        const cred = await navigator.credentials.get(w.requestOptions(begin.options));
        await w.post('/vulnerabilities/decide/commit', { id: begin.id, assertion: w.assertionJSON(cred) });
        w.show('Done.', false);
        window.location.reload();
      } catch (err) {
        w.show(err.name === 'NotAllowedError' ? 'Cancelled or timed out.' : (err.message || 'The decision failed.'), true);
      } finally {
        buttons.forEach((b) => { b.disabled = false; });
      }
    });
  }
})();

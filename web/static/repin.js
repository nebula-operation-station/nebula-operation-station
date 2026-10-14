// SPDX-License-Identifier: AGPL-3.0-or-later
// Re-pin a host blocked by a host key mismatch: the executor proposes the
// change from its own records, the user approves it with the security key
// (user verification), the executor commits it. Every value is shown with
// textContent only.
'use strict';

(() => {
  const w = nebulaWebAuthn;
  const panel = document.getElementById('repin-panel');
  if (!panel) return;
  let current = null;
  const set = (id, text) => { document.getElementById(id).textContent = text; };

  for (const b of document.querySelectorAll('.repin-start')) {
    b.addEventListener('click', async () => {
      try {
        const r = await w.post('/hostkeys/repin/propose', { host: b.dataset.host });
        current = r;
        set('repin-host', r.host);
        set('repin-pinned', r.pinned);
        set('repin-presented', r.presented);
        set('repin-endpoint', r.endpoint);
        set('repin-since', r.since);
        set('repin-risk', r.risk);
        document.getElementById('repin-confirm').checked = false;
        document.getElementById('repin-typed-label').hidden = r.requirement !== 'typed_count';
        document.getElementById('repin-cli').hidden = r.requirement !== 'cli';
        set('repin-cli-cmd', 'nebula approve ' + r.digest.slice(0, 12));
        set('repin-approve', r.requirement === 'cli' ? 'Re-pin' : 'Re-pin with security key');
        panel.hidden = false;
        w.show('Compare the new fingerprint on the host console before you continue.', false);
      } catch (err) {
        w.show(err.message || 'Could not propose the re-pin.', true);
      }
    });
  }

  document.getElementById('repin-cancel').addEventListener('click', () => {
    panel.hidden = true;
    current = null;
  });

  document.getElementById('repin-approve').addEventListener('click', async () => {
    if (!current) return;
    if (!document.getElementById('repin-confirm').checked) {
      w.show('Confirm that you compared the fingerprint on the host console.', true);
      return;
    }
    const button = document.getElementById('repin-approve');
    button.disabled = true;
    try {
      const body = { host: current.host, digest: current.digest };
      if (current.requirement !== 'cli') {
        if (!current.options) throw new Error('No approval challenge; propose again.');
        w.show('Touch your security key…', false);
        const cred = await navigator.credentials.get(w.requestOptions(current.options));
        body.assertion = w.assertionJSON(cred);
        body.typed_count = parseInt(document.getElementById('repin-typed').value, 10) || 0;
      }
      const r = await w.post('/hostkeys/repin/commit', body);
      w.show('Re-pinned ' + r.host + ' to ' + r.fingerprint + '.', false);
      setTimeout(() => window.location.reload(), 1500);
    } catch (err) {
      w.show(err.name === 'NotAllowedError' ? 'Cancelled or timed out.' : (err.message || 'Re-pin failed.'), true);
    } finally {
      button.disabled = false;
    }
  });
})();

// SPDX-License-Identifier: AGPL-3.0-or-later
// Bulk enrollment: the executor reads the host keys of the selected hosts,
// the user compares and approves the table with the security key, the
// executor pins what still matches. Values are shown with textContent only.
'use strict';

(() => {
  const w = nebulaWebAuthn;
  const read = document.getElementById('enroll-read');
  if (!read) return;
  const rows = () => Array.from(document.querySelectorAll('.enroll-row'));
  const rowOf = (host) => rows().find((r) => r.dataset.host === host);
  let proposal = null;

  document.getElementById('enroll-all').addEventListener('change', (e) => {
    for (const b of document.querySelectorAll('.enroll-pick')) b.checked = e.target.checked;
  });

  read.addEventListener('click', async () => {
    const hosts = rows().filter((r) => r.querySelector('.enroll-pick').checked).map((r) => ({
      host: r.dataset.host,
      endpoint: r.querySelector('.enroll-endpoint').value,
      ssh_user: r.querySelector('.enroll-user').value.trim(),
      credential: '',
    }));
    if (hosts.length === 0) {
      w.show('Select at least one host.', true);
      return;
    }
    read.disabled = true;
    w.show('Reading host keys…', false);
    try {
      const r = await w.post('/inventory/enroll/propose', { hosts });
      proposal = r;
      for (const row of rows()) {
        row.querySelector('.enroll-type').textContent = '';
        row.querySelector('.enroll-fp').textContent = '';
        row.querySelector('.enroll-result').textContent = '';
      }
      for (const h of r.hosts) {
        const row = rowOf(h.host);
        if (!row) continue;
        row.querySelector('.enroll-type').textContent = h.key_type || '';
        row.querySelector('.enroll-fp').textContent = h.fingerprint || '';
        row.querySelector('.enroll-result').textContent = h.error ? 'not included: ' + h.error : 'to be approved';
      }
      const panel = document.getElementById('enroll-approval');
      if (!r.digest) {
        panel.hidden = true;
        w.show('No host key could be read.', true);
        return;
      }
      document.getElementById('enroll-risk').textContent = r.risk;
      document.getElementById('enroll-confirm').checked = false;
      document.getElementById('enroll-typed-label').hidden = r.requirement !== 'typed_count';
      document.getElementById('enroll-cli').hidden = r.requirement !== 'cli';
      document.getElementById('enroll-cli-cmd').textContent = 'nebula approve ' + r.digest.slice(0, 12);
      document.getElementById('enroll-approve').textContent = r.requirement === 'cli' ? 'Enroll' : 'Enroll with security key';
      panel.hidden = false;
      w.show('Compare every fingerprint on the host console before you approve.', false);
    } catch (err) {
      w.show(err.message || 'Could not read the host keys.', true);
    } finally {
      read.disabled = false;
    }
  });

  document.getElementById('enroll-approve').addEventListener('click', async () => {
    if (!proposal || !proposal.digest) return;
    if (!document.getElementById('enroll-confirm').checked) {
      w.show('Confirm that you compared the fingerprints on the host consoles.', true);
      return;
    }
    const button = document.getElementById('enroll-approve');
    button.disabled = true;
    try {
      const body = { digest: proposal.digest, hosts: proposal.hosts.filter((h) => !h.error) };
      if (proposal.requirement !== 'cli') {
        if (!proposal.options) throw new Error('No approval challenge; read the keys again.');
        w.show('Touch your security key…', false);
        const cred = await navigator.credentials.get(w.requestOptions(proposal.options));
        body.assertion = w.assertionJSON(cred);
        body.typed_count = parseInt(document.getElementById('enroll-typed').value, 10) || 0;
      }
      const r = await w.post('/inventory/enroll/commit', body);
      let pinned = 0;
      for (const x of r.results) {
        const row = rowOf(x.host);
        if (!row) continue;
        let text = x.pinned ? 'pinned' : 'not pinned: ' + x.error;
        if (x.pinned) {
          pinned++;
          text += x.login_ok ? ', login works' : (x.login_detail ? ', ' + x.login_detail : '');
        }
        row.querySelector('.enroll-result').textContent = text;
      }
      document.getElementById('enroll-approval').hidden = true;
      proposal = null;
      w.show(pinned + ' of ' + r.results.length + ' hosts enrolled.', pinned !== r.results.length);
    } catch (err) {
      w.show(err.name === 'NotAllowedError' ? 'Cancelled or timed out.' : (err.message || 'Enrollment failed.'), true);
    } finally {
      button.disabled = false;
    }
  });
})();

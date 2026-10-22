// SPDX-License-Identifier: AGPL-3.0-or-later
// Host page: the quick-action bar (job ui5) runs actions in place
// through nebulaRunOp — no navigation, the status follows in the bar —
// and the settings tab manages the pins of this host. The delete
// button stays disabled until the typed host ID matches (the server
// re-checks the value; this is only for clarity). Server text is shown
// with textContent only.
'use strict';

(() => {
  const w = nebulaWebAuthn;

  // ---- Quick actions -------------------------------------------------
  const bar = document.getElementById('quick-actions');
  if (bar) {
    const host = bar.dataset.host;
    const msg = document.getElementById('quick-message');
    const status = document.getElementById('quick-status');
    const rebootConfirm = document.getElementById('quick-reboot-confirm');
    const rebootGo = document.getElementById('quick-reboot-go');
    const rebootCancel = document.getElementById('quick-reboot-cancel');

    // "Refresh" runs the four reads behind the inventory columns, one
    // operation each; LOW reads approve themselves while the session
    // is open, so this is one click.
    const runRefresh = async () => {
      await nebulaRunOp.ensureSession(msg);
      msg.textContent = 'Refreshing…';
      const ids = [];
      for (const a of ['core.facts', 'package.list_updates', 'docker.list', 'service.list']) {
        ids.push(await nebulaRunOp.runOperation({ action: a, hosts: [host] }, msg, status));
      }
      nebulaRunOp.followStatus(status, ids, { reloadWhenDone: true });
    };

    for (const b of bar.querySelectorAll('button.quickaction')) {
      b.addEventListener('click', async () => {
        const action = b.dataset.action;
        if (b.dataset.params) return; // link, not a button
        if (action === 'system.reboot') {
          rebootConfirm.hidden = false;
          rebootGo.disabled = false;
          return;
        }
        b.disabled = true;
        msg.textContent = '';
        msg.classList.remove('message--error');
        try {
          if (action === 'refresh') {
            await runRefresh();
            return; // the status line owns the bar now
          }
          await nebulaRunOp.ensureSession(msg);
          const id = await nebulaRunOp.runOperation({ action, hosts: [host] }, msg, status);
          nebulaRunOp.followStatus(status, [id], { reloadWhenDone: true });
        } catch (err) {
          msg.textContent = err.name === 'NotAllowedError' ? 'Cancelled or timed out.' : (err.message || 'Could not run the action.');
          msg.classList.add('message--error');
          b.disabled = false;
        }
      });
    }
    rebootCancel.addEventListener('click', () => {
      rebootConfirm.hidden = true;
    });
    rebootGo.addEventListener('click', async () => {
      rebootGo.disabled = true;
      msg.textContent = '';
      msg.classList.remove('message--error');
      try {
        await nebulaRunOp.ensureSession(msg);
        const id = await nebulaRunOp.runOperation({ action: 'system.reboot', hosts: [host] }, msg, status);
        nebulaRunOp.followStatus(status, [id], { reloadWhenDone: true });
      } catch (err) {
        msg.textContent = err.name === 'NotAllowedError' ? 'Cancelled or timed out.' : (err.message || 'Could not reboot.');
        msg.classList.add('message--error');
        rebootGo.disabled = false;
      }
    });
  }

  // ---- Pin management (settings tab) ---------------------------------
  const pinsForm = document.getElementById('pins-form');
  if (pinsForm) {
    const submit = document.getElementById('pins-submit');
    const msg = document.getElementById('pins-message');
    pinsForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      submit.disabled = true;
      msg.textContent = '';
      msg.classList.remove('message--error');
      // The checkboxes are rendered in the wanted order (pinned first,
      // in pin order); the checked ones, in DOM order, are the new list.
      const actions = Array.from(pinsForm.querySelectorAll('input[name="pin"]:checked')).map((c) => c.value);
      try {
        await w.post('/hosts/' + encodeURIComponent(pinsForm.dataset.host) + '/pins', { actions });
        msg.textContent = 'Pins saved.';
      } catch (err) {
        msg.textContent = err.message || 'Could not save the pins.';
        msg.classList.add('message--error');
      } finally {
        submit.disabled = false;
      }
    });
  }

  // ---- Delete host -----------------------------------------------------
  const form = document.querySelector('form[action$="/delete"]');
  if (!form) return;
  const input = form.querySelector('input[name="confirm_id"]');
  const button = form.querySelector('button[type="submit"]');
  const id = form.querySelector('input[name="id"]')?.value ?? '';
  if (!input || !button || !id) return;
  button.disabled = true;
  input.addEventListener('input', () => {
    button.disabled = input.value !== id;
  });
})();

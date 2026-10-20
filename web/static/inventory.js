// SPDX-License-Identifier: AGPL-3.0-or-later
// Inventory page: create, edit and delete hosts through the JSON
// endpoints. Every request goes through nebulaWebAuthn.post (fetch with
// a real Origin, decision 36); server text is shown with textContent
// only, never innerHTML.
'use strict';

(() => {
  const w = nebulaWebAuthn;
  const form = document.getElementById('host-form');
  if (!form) return; // read-only page: no inventory store configured

  const idInput = document.getElementById('host-id');
  const nameInput = document.getElementById('host-display-name');
  const envSelect = document.getElementById('host-environment');
  const critSelect = document.getElementById('host-criticality');
  const endpointsInput = document.getElementById('host-endpoints');
  const tagsInput = document.getElementById('host-tags');
  const submit = document.getElementById('host-submit');
  const cancel = document.getElementById('host-cancel');
  let editing = null; // host ID being edited, or null for "add host"
  // "Add to managed hosts" from a network asset: prefill, and link the
  // asset to the host once it exists.
  let prefillAsset = null;
  if (form.dataset.prefill) {
    try {
      const p = JSON.parse(form.dataset.prefill);
      prefillAsset = p.asset;
      idInput.value = p.id || '';
      nameInput.value = p.display_name || '';
      endpointsInput.value = (p.endpoints || []).join('\n');
    } catch (_) { /* no prefill */ }
  }

  function readForm() {
    const endpoints = endpointsInput.value
      .split('\n')
      .map((s) => s.trim())
      .filter((s) => s !== '');
    const tags = {};
    for (const line of tagsInput.value.split('\n')) {
      const t = line.trim();
      if (t === '') continue;
      const i = t.indexOf('=');
      if (i <= 0 || i === t.length - 1) throw new Error('Tags must be one key=value per line.');
      tags[t.slice(0, i).trim()] = t.slice(i + 1).trim();
    }
    return {
      id: idInput.value.trim(),
      display_name: nameInput.value.trim(),
      environment: envSelect.value,
      criticality: critSelect.value,
      endpoints,
      tags,
    };
  }

  function resetForm() {
    editing = null;
    form.reset();
    idInput.readOnly = false;
    submit.textContent = 'Add host';
    cancel.hidden = true;
    w.show('', false);
  }

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    let body;
    try {
      body = readForm();
    } catch (err) {
      w.show(err.message, true);
      return;
    }
    submit.disabled = true;
    try {
      await w.post(editing === null ? '/inventory/hosts' : '/inventory/hosts/update', body);
      if (editing === null && prefillAsset) {
        await w.post('/network/a/link', { asset: prefillAsset, host: body.id });
        window.location.assign('/network/a/' + encodeURIComponent(prefillAsset));
        return;
      }
      window.location.reload();
    } catch (err) {
      w.show(err.message || 'The change failed.', true);
    } finally {
      submit.disabled = false;
    }
  });

  cancel.addEventListener('click', resetForm);

  for (const btn of document.querySelectorAll('.inventory__edit')) {
    btn.addEventListener('click', () => {
      const row = btn.closest('tr');
      editing = row.dataset.id;
      idInput.value = row.dataset.id;
      idInput.readOnly = true;
      nameInput.value = row.dataset.displayName;
      envSelect.value = row.dataset.environment;
      critSelect.value = row.dataset.criticality;
      endpointsInput.value = JSON.parse(row.dataset.endpoints).join('\n');
      tagsInput.value = Object.entries(JSON.parse(row.dataset.tags))
        .map(([k, v]) => k + '=' + v)
        .join('\n');
      submit.textContent = 'Save changes';
      cancel.hidden = false;
      w.show('', false);
      form.scrollIntoView();
    });
  }

  for (const btn of document.querySelectorAll('.inventory__delete')) {
    btn.addEventListener('click', async () => {
      const row = btn.closest('tr');
      const id = row.dataset.id;
      const typed = row.querySelector('.inventory__delete-confirm').value.trim();
      if (typed !== id) {
        w.show('Type the host ID (' + id + ') to confirm the deletion.', true);
        return;
      }
      btn.disabled = true;
      try {
        await w.post('/inventory/hosts/delete', { id });
        window.location.reload();
      } catch (err) {
        w.show(err.message || 'Could not delete the host.', true);
      } finally {
        btn.disabled = false;
      }
    });
  }
})();

// SPDX-License-Identifier: AGPL-3.0-or-later
// Runbook editor: fills the form from the draft, edits the parameter rows
// and saves the runbook as a new version. Only DOM APIs and textContent;
// no HTML is built from strings.
'use strict';

(() => {
  const w = nebulaWebAuthn;

  // Trust a version on the executor with the security key (M7-4).
  const trust = document.getElementById('runbook-trust');
  if (trust) {
    trust.addEventListener('click', async () => {
      trust.disabled = true;
      try {
        const b = await w.post('/runbooks/trust/begin', { slug: trust.dataset.slug, version: parseInt(trust.dataset.version, 10) });
        w.show('Touch your security key…', false);
        const cred = await navigator.credentials.get(w.requestOptions(b.options));
        await w.post('/runbooks/trust/commit', { trust_id: b.trust_id, assertion: w.assertionJSON(cred) });
        window.location.reload();
      } catch (err) {
        w.show(err.name === 'NotAllowedError' ? 'Cancelled or timed out.' : (err.message || 'Could not trust this version.'), true);
        trust.disabled = false;
      }
    });
  }

  const form = document.getElementById('runbook-form');
  if (!form) {
    return;
  }
  const $ = (id) => document.getElementById(id);
  const rows = $('runbook-params');
  const types = ['name', 'int', 'path', 'choice'];

  const field = (labelText, input) => {
    const l = document.createElement('label');
    l.textContent = labelText + ' ';
    l.appendChild(input);
    return l;
  };

  const addRow = (p) => {
    const row = document.createElement('div');
    row.className = 'param-row';
    const name = document.createElement('input');
    name.type = 'text';
    name.className = 'param-name';
    name.maxLength = 32;
    name.value = p.name || '';
    const label = document.createElement('input');
    label.type = 'text';
    label.className = 'param-label';
    label.maxLength = 100;
    label.value = p.label || '';
    const type = document.createElement('select');
    type.className = 'param-type';
    for (const t of types) {
      const o = document.createElement('option');
      o.value = t;
      o.textContent = t;
      o.selected = t === (p.type || 'name');
      type.appendChild(o);
    }
    const choices = document.createElement('input');
    choices.type = 'text';
    choices.className = 'param-choices';
    choices.placeholder = 'soft, hard';
    choices.value = (p.choices || []).join(', ');
    const remove = document.createElement('button');
    remove.type = 'button';
    remove.className = 'button button--small button--danger';
    remove.textContent = 'Remove';
    remove.addEventListener('click', () => row.remove());
    row.append(field('Name', name), field('Label', label), field('Type', type), field('Choices', choices), remove);
    rows.appendChild(row);
  };

  let draft = {};
  try {
    draft = JSON.parse(form.dataset.draft || '{}');
  } catch (e) {
    draft = {};
  }
  $('runbook-slug').value = draft.slug || '';
  $('runbook-slug').readOnly = form.dataset.existing === '1';
  $('runbook-title').value = draft.title || '';
  $('runbook-description').value = draft.description || '';
  $('runbook-risk').value = draft.risk || 'HIGH';
  $('runbook-durable').checked = !!draft.durable;
  $('runbook-timeout').value = draft.timeout_s || 300;
  $('runbook-body').value = draft.body || '';
  $('runbook-secrets').value = (draft.secrets || []).join(', ');
  for (const p of draft.params || []) {
    addRow(p);
  }
  $('runbook-param-add').addEventListener('click', () => addRow({}));

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const params = Array.from(rows.querySelectorAll('.param-row')).map((r) => {
      const p = {
        name: r.querySelector('.param-name').value.trim(),
        label: r.querySelector('.param-label').value.trim(),
        type: r.querySelector('.param-type').value,
      };
      if (p.type === 'choice') {
        p.choices = r.querySelector('.param-choices').value.split(',').map((c) => c.trim()).filter((c) => c !== '');
      }
      return p;
    });
    const body = {
      slug: $('runbook-slug').value.trim(),
      title: $('runbook-title').value.trim(),
      description: $('runbook-description').value,
      risk: $('runbook-risk').value,
      durable: $('runbook-durable').checked,
      timeout_s: parseInt($('runbook-timeout').value, 10) || 0,
      params,
      secrets: $('runbook-secrets').value.split(',').map((c) => c.trim()).filter((c) => c !== ''),
      body: $('runbook-body').value,
    };
    const button = $('runbook-save');
    button.disabled = true;
    try {
      const r = await w.post('/runbooks/save', body);
      window.location.href = '/runbooks/' + encodeURIComponent(r.slug);
    } catch (err) {
      w.show(err.message || 'Could not save the runbook.', true);
      button.disabled = false;
    }
  });
})();

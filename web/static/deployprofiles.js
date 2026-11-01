// SPDX-License-Identifier: AGPL-3.0-or-later
// Deploy profile editor (ADR 0008 section 1): fills the form from the
// draft, edits the size, bootstrap, runbook and vault rows, and saves
// the profile as a new version. Only DOM APIs and textContent; no HTML
// is built from strings.
'use strict';

(() => {
  const w = nebulaWebAuthn;
  const form = document.getElementById('deploy-profile-form');
  if (!form) {
    return;
  }
  const $ = (id) => document.getElementById(id);
  const modules = JSON.parse(form.dataset.modules || '[]');
  const presets = JSON.parse(form.dataset.presets || '[]');

  let draft = {};
  try {
    draft = JSON.parse(form.dataset.draft || '{}');
  } catch (e) {
    draft = {};
  }

  // --- fixed fields -----------------------------------------------------
  $('dp-slug').value = draft.slug || '';
  $('dp-title').value = draft.title || '';
  $('dp-description').value = draft.description || '';
  $('dp-image').value = draft.image || '';
  $('dp-storage').value = draft.storage_class || '';
  const size = draft.size || {};
  // A draft without a preset but with values is a custom size; keep the
  // custom fields visible instead of falling back to the default preset.
  $('dp-size-preset').value = size.preset || ((size.vcpu || size.ram_gib || size.disk_gib) ? '' : 'M');
  $('dp-vcpu').value = size.vcpu || '';
  $('dp-ram').value = size.ram_gib || '';
  $('dp-disk').value = size.disk_gib || '';
  const net = draft.network || {};
  $('dp-bridge').value = net.bridge || '';
  $('dp-vlan').value = net.vlan || 0;
  $('dp-dhcp').checked = !!net.dhcp;
  $('dp-ipam').value = net.ipam_pool || '';
  const dns = draft.dns || {};
  $('dp-nameservers').value = (dns.nameservers || []).join(', ');
  $('dp-search').value = dns.search_domain || '';

  const custom = $('dp-size-custom');
  const sizePreset = $('dp-size-preset');
  const syncSize = () => {
    custom.hidden = sizePreset.value !== '';
  };
  sizePreset.addEventListener('change', syncSize);
  syncSize();

  // --- bootstrap modules -------------------------------------------------
  const bootstrap = $('dp-bootstrap');
  const checked = new Set(draft.bootstrap ? draft.bootstrap.map((m) => m.name) : []);

  const addModule = (name) => {
    const box = document.createElement('div');
    box.className = 'dp-module';
    box.dataset.module = name;
    const label = document.createElement('label');
    label.className = 'choice';
    const cb = document.createElement('input');
    cb.type = 'checkbox';
    cb.checked = checked.has(name);
    label.append(cb, document.createTextNode(' ' + name));
    const params = document.createElement('div');
    params.className = 'dp-module-params';
    const draftModule = (draft.bootstrap || []).find((m) => m.name === name);
    for (const [k, v] of Object.entries((draftModule && draftModule.params) || {})) {
      addParamRow(params, k, v);
    }
    const add = document.createElement('button');
    add.type = 'button';
    add.className = 'button button--small';
    add.textContent = 'Add parameter';
    add.addEventListener('click', () => {
      if (params.children.length >= 8) {
        w.show('A module takes at most 8 parameters.', true);
        return;
      }
      addParamRow(params, '', '');
    });
    const sync = () => { params.hidden = !cb.checked; };
    cb.addEventListener('change', sync);
    sync();
    box.append(label, params, add);
    bootstrap.appendChild(box);
  };

  const addParamRow = (parent, k, v) => {
    const row = document.createElement('div');
    row.className = 'param-row';
    const key = document.createElement('input');
    key.type = 'text';
    key.maxLength = 32;
    key.value = k;
    key.setAttribute('aria-label', 'parameter name');
    const val = document.createElement('input');
    val.type = 'text';
    val.maxLength = 200;
    val.value = v;
    val.setAttribute('aria-label', 'parameter value');
    const remove = document.createElement('button');
    remove.type = 'button';
    remove.className = 'button button--small button--danger';
    remove.textContent = 'Remove';
    remove.addEventListener('click', () => row.remove());
    row.append(key, val, remove);
    parent.appendChild(row);
  };

  for (const m of modules) {
    addModule(m);
  }

  // --- runbook references -------------------------------------------------
  const runbooks = $('dp-runbooks');
  const addRunbook = (slug, version) => {
    const row = document.createElement('div');
    row.className = 'param-row';
    const s = document.createElement('input');
    s.type = 'text';
    s.maxLength = 40;
    s.value = slug || '';
    s.setAttribute('aria-label', 'runbook slug');
    const v = document.createElement('input');
    v.type = 'number';
    v.min = 1;
    v.inputMode = 'numeric';
    v.value = version || '';
    v.setAttribute('aria-label', 'runbook version');
    const remove = document.createElement('button');
    remove.type = 'button';
    remove.className = 'button button--small button--danger';
    remove.textContent = 'Remove';
    remove.addEventListener('click', () => row.remove());
    row.append(s, v, remove);
    runbooks.appendChild(row);
  };
  for (const r of draft.runbooks || []) {
    addRunbook(r.slug, r.version);
  }
  $('dp-runbook-add').addEventListener('click', () => {
    if (runbooks.children.length >= 10) {
      w.show('A profile references at most 10 runbooks.', true);
      return;
    }
    addRunbook('', '');
  });

  // --- vault references ----------------------------------------------------
  const vault = $('dp-vault');
  const addVault = (slot, id) => {
    const row = document.createElement('div');
    row.className = 'param-row';
    const s = document.createElement('input');
    s.type = 'text';
    s.maxLength = 32;
    s.value = slot || '';
    s.setAttribute('aria-label', 'slot name');
    const v = document.createElement('input');
    v.type = 'text';
    v.maxLength = 64;
    v.value = id || '';
    v.setAttribute('aria-label', 'vault entry id');
    const remove = document.createElement('button');
    remove.type = 'button';
    remove.className = 'button button--small button--danger';
    remove.textContent = 'Remove';
    remove.addEventListener('click', () => row.remove());
    row.append(s, v, remove);
    vault.appendChild(row);
  };
  for (const r of draft.vault_refs || []) {
    addVault(r.slot, r.vault_id);
  }
  $('dp-vault-add').addEventListener('click', () => {
    if (vault.children.length >= 8) {
      w.show('A profile carries at most 8 vault references.', true);
      return;
    }
    addVault('', '');
  });

  // --- save ----------------------------------------------------------------
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const preset = sizePreset.value;
    const sizeOut = preset
      ? { preset }
      : {
          vcpu: parseInt($('dp-vcpu').value, 10) || 0,
          ram_gib: parseInt($('dp-ram').value, 10) || 0,
          disk_gib: parseInt($('dp-disk').value, 10) || 0,
        };
    const bootstrapOut = Array.from(bootstrap.children)
      .filter((box) => box.querySelector('input[type=checkbox]').checked)
      .map((box) => {
        const params = {};
        for (const row of box.querySelectorAll('.param-row')) {
          const k = row.children[0].value.trim();
          if (k !== '') {
            params[k] = row.children[1].value;
          }
        }
        return { name: box.dataset.module, params };
      });
    const runbooksOut = Array.from(runbooks.children).map((row) => ({
      slug: row.children[0].value.trim(),
      version: parseInt(row.children[1].value, 10) || 0,
    }));
    const vaultOut = Array.from(vault.children).map((row) => ({
      slot: row.children[0].value.trim(),
      vault_id: row.children[1].value.trim(),
    }));
    const body = {
      slug: $('dp-slug').value.trim(),
      title: $('dp-title').value.trim(),
      description: $('dp-description').value,
      image: $('dp-image').value.trim(),
      storage_class: $('dp-storage').value.trim(),
      size: sizeOut,
      network: {
        bridge: $('dp-bridge').value.trim(),
        vlan: parseInt($('dp-vlan').value, 10) || 0,
        dhcp: $('dp-dhcp').checked,
        ipam_pool: $('dp-ipam').value.trim(),
      },
      dns: {
        nameservers: $('dp-nameservers').value.split(',').map((c) => c.trim()).filter((c) => c !== ''),
        search_domain: $('dp-search').value.trim(),
      },
      bootstrap: bootstrapOut,
      runbooks: runbooksOut,
      vault_refs: vaultOut,
    };
    const button = $('dp-save');
    button.disabled = true;
    try {
      const r = await w.post('/deploy/save', body);
      window.location.href = '/deploy/' + encodeURIComponent(r.slug);
    } catch (err) {
      w.show(err.message || 'Could not save the profile.', true);
      button.disabled = false;
    }
  });
})();

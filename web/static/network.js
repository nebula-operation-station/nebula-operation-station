// SPDX-License-Identifier: AGPL-3.0-or-later
// Network pages (M9-1): save networks, assets and address entries through
// the JSON endpoints. Server text is shown with textContent only.
'use strict';

(() => {
  const w = nebulaWebAuthn;
  const $ = (id) => document.getElementById(id);
  const lines = (s) => s.split('\n').map((x) => x.trim()).filter((x) => x !== '');

  function draft(form) {
    if (!form.dataset.draft) return null;
    try { return JSON.parse(form.dataset.draft); } catch (_) { return null; }
  }

  function bind(form, read, url, done) {
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      let body;
      try {
        body = read();
      } catch (err) {
        w.show(err.message, true);
        return;
      }
      const button = form.querySelector('button[type="submit"]');
      button.disabled = true;
      try {
        const r = await w.post(url, body);
        done(r, body);
      } catch (err) {
        w.show(err.message || 'The change failed.', true);
        button.disabled = false;
      }
    });
  }

  const net = $('network-form');
  if (net) {
    const d = draft(net);
    if (d) {
      $('net-id').value = d.id;
      $('net-id').readOnly = true;
      $('net-name').value = d.name;
      $('net-prefix').value = d.prefix;
      $('net-vlan').value = String(d.vlan || 0);
      $('net-gateway').value = d.gateway || '';
      $('net-notes').value = d.notes || '';
      $('net-pools').value = (d.pools || []).map((p) => p.name + ' ' + p.first + '-' + p.last).join('\n');
    }
    bind(net, () => {
      const pools = lines($('net-pools').value).map((l) => {
        const m = /^(\S+)\s+(\S+)\s*-\s*(\S+)$/.exec(l);
        if (!m) throw new Error('Pools must be one "name first-last" per line.');
        return { name: m[1], first: m[2], last: m[3] };
      });
      const vlan = Number.parseInt($('net-vlan').value || '0', 10);
      return {
        id: $('net-id').value.trim(),
        name: $('net-name').value.trim(),
        prefix: $('net-prefix').value.trim(),
        vlan: Number.isNaN(vlan) ? -1 : vlan,
        gateway: $('net-gateway').value.trim(),
        notes: $('net-notes').value,
        pools,
      };
    }, '/network/save', (r) => window.location.assign('/network/n/' + encodeURIComponent(r.id)));
  }

  const asset = $('asset-form');
  if (asset) {
    const d = draft(asset);
    if (d) {
      $('asset-id').value = d.id;
      $('asset-id').readOnly = true;
      $('asset-name').value = d.name;
      $('asset-kind').value = d.kind;
      $('asset-hostname').value = d.hostname || '';
      $('asset-mac').value = d.mac || '';
      $('asset-notes').value = d.notes || '';
      $('asset-addresses').value = (d.addresses || []).join('\n');
    }
    bind(asset, () => ({
      id: $('asset-id').value.trim(),
      name: $('asset-name').value.trim(),
      kind: $('asset-kind').value,
      hostname: $('asset-hostname').value.trim(),
      mac: $('asset-mac').value.trim(),
      notes: $('asset-notes').value,
      addresses: lines($('asset-addresses').value),
    }), '/network/a/save', (r) => window.location.assign('/network/a/' + encodeURIComponent(r.id)));
  }

  const entry = $('entry-form');
  if (entry) {
    bind(entry, () => ({
      address: $('entry-address').value.trim(),
      kind: $('entry-kind').value,
      note: $('entry-note').value.trim(),
    }), '/network/entry', () => window.location.reload());
  }

  for (const [button, confirm, url, back] of [['net-delete', 'net-delete-confirm', '/network/delete', '/network'],
    ['asset-delete', 'asset-delete-confirm', '/network/a/delete', '/network']]) {
    const b = $(button);
    if (!b) continue;
    b.addEventListener('click', async () => {
      const id = b.dataset.id;
      if ($(confirm).value.trim() !== id) {
        w.show('Type the ID (' + id + ') to confirm the deletion.', true);
        return;
      }
      b.disabled = true;
      try {
        await w.post(url, { id });
        window.location.assign(back);
      } catch (err) {
        w.show(err.message || 'Could not delete.', true);
        b.disabled = false;
      }
    });
  }
})();

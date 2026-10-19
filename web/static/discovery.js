// SPDX-License-Identifier: AGPL-3.0-or-later
// Discovery pages (M9-2): queue or schedule scans, cancel, import staged
// hosts. Server text is shown with textContent only.
'use strict';

(() => {
  const w = nebulaWebAuthn;
  const $ = (id) => document.getElementById(id);

  const form = $('scan-form');
  if (form) {
    const radio = (name) => form.querySelector('input[name="' + name + '"]:checked').value;
    const sync = () => {
      const mode = radio('mode');
      const when = radio('when');
      for (const el of form.querySelectorAll('.mode-ports')) el.hidden = mode !== 'ports';
      for (const el of form.querySelectorAll('.mode-custom')) el.hidden = mode !== 'custom';
      for (const el of form.querySelectorAll('.when-sched')) el.hidden = when === 'now';
      for (const el of form.querySelectorAll('.when-interval')) el.hidden = when !== 'interval';
    };
    for (const el of form.querySelectorAll('input[type="radio"]')) el.addEventListener('change', sync);
    sync();
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const mode = radio('mode');
      const when = radio('when');
      const body = {
        mode,
        targets: $('scan-targets').value.split('\n').map((s) => s.trim()).filter((s) => s !== ''),
        ports: mode === 'ports' ? $('scan-ports').value.trim() : '',
        custom: null,
        schedule: { kind: when, name: '', at: 0, hours: 0 },
      };
      if (mode === 'custom') {
        const top = Number.parseInt($('c-top').value || '0', 10);
        body.custom = {
          no_ping: $('c-noping').checked,
          version: $('c-version').checked,
          os: $('c-os').checked,
          udp: $('c-udp').checked,
          open_only: $('c-open').checked,
          top_ports: Number.isNaN(top) ? -1 : top,
          ports: $('c-ports').value.trim(),
          timing: Number.parseInt($('c-timing').value, 10),
        };
      }
      if (when !== 'now') {
        body.schedule.name = $('sched-name').value.trim();
        const at = $('sched-at').value;
        body.schedule.at = at ? Math.floor(new Date(at).getTime() / 1000) : 0;
        if (when === 'interval') body.schedule.hours = Number.parseInt($('sched-hours').value || '0', 10);
      }
      const button = form.querySelector('button[type="submit"]');
      button.disabled = true;
      try {
        const r = await w.post('/network/discovery/submit', body);
        if (r.id) {
          window.location.assign('/network/discovery/' + encodeURIComponent(r.id));
        } else {
          window.location.reload();
        }
      } catch (err) {
        w.show(err.message || 'Could not queue the scan.', true);
        button.disabled = false;
      }
    });
  }

  for (const b of document.querySelectorAll('.sched-delete')) {
    b.addEventListener('click', async () => {
      b.disabled = true;
      try {
        await w.post('/network/discovery/schedule/delete', { id: b.dataset.id });
        window.location.reload();
      } catch (err) {
        w.show(err.message || 'Could not delete the schedule.', true);
        b.disabled = false;
      }
    });
  }

  const cancel = $('scan-cancel');
  if (cancel) {
    cancel.addEventListener('click', async () => {
      cancel.disabled = true;
      try {
        await w.post('/network/discovery/cancel', { id: cancel.dataset.id });
        window.location.reload();
      } catch (err) {
        w.show(err.message || 'Could not cancel the scan.', true);
        cancel.disabled = false;
      }
    });
  }

  const staging = $('staging');
  if (staging) {
    const run = async (button, all) => {
      const addresses = all ? [] : Array.from(staging.querySelectorAll('.stage-pick:checked')).map((c) => c.value);
      if (!all && addresses.length === 0) {
        w.show('Select the hosts to import.', true);
        return;
      }
      button.disabled = true;
      try {
        const r = await w.post('/network/discovery/import', { id: staging.dataset.id, addresses, all });
        const skipped = Object.entries(r.skipped || {}).map(([a, why]) => a + ': ' + why);
        if (skipped.length > 0) {
          w.show('Created ' + (r.created || []).length + ', updated ' + (r.updated || []).length + '. Skipped: ' + skipped.join('; '), true);
          button.disabled = false;
          return;
        }
        window.location.reload();
      } catch (err) {
        w.show(err.message || 'Could not import.', true);
        button.disabled = false;
      }
    };
    const sel = $('import-selected');
    const all = $('import-all');
    sel.addEventListener('click', () => run(sel, false));
    all.addEventListener('click', () => run(all, true));
  }
})();

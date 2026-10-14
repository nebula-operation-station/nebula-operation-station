// SPDX-License-Identifier: AGPL-3.0-or-later
// CSV import: read the file locally, ask the server for a preview with the
// chosen column mapping, import the selected rows. Every value from the
// file or the server is shown with textContent only.
'use strict';

(() => {
  const w = nebulaWebAuthn;
  const maxBytes = 768 * 1024;
  const fileInput = document.getElementById('csv-file');
  if (!fileInput) return;
  const selects = Array.from(document.querySelectorAll('#mapping select[data-field]'));
  const rowsBody = document.getElementById('preview-rows');
  const selectAll = document.getElementById('select-all');
  let csv = '';

  function request(extra) {
    return Object.assign({
      csv,
      mapping: mapping(),
      default_environment: document.getElementById('default-environment').value,
      default_criticality: document.getElementById('default-criticality').value,
    }, extra || {});
  }

  function mapping() {
    const m = {};
    for (const s of selects) if (s.value) m[s.dataset.field] = s.value;
    return m;
  }

  function cell(tr, text) {
    const td = document.createElement('td');
    td.textContent = text;
    tr.appendChild(td);
    return td;
  }

  function fillSelects(columns) {
    for (const s of selects) {
      s.replaceChildren();
      const none = document.createElement('option');
      none.value = '';
      none.textContent = '(not mapped)';
      s.appendChild(none);
      for (const c of columns) {
        const o = document.createElement('option');
        o.value = c;
        o.textContent = c;
        s.appendChild(o);
      }
      // Preselect a column with the field's name, if there is one.
      const guess = columns.find((c) => c.toLowerCase() === s.dataset.field);
      if (guess) s.value = guess;
    }
  }

  fileInput.addEventListener('change', async () => {
    const f = fileInput.files[0];
    if (!f) return;
    if (f.size > maxBytes) {
      w.show('The file is larger than 768 KiB.', true);
      return;
    }
    try {
      csv = await f.text();
      const r = await w.post('/inventory/import/preview', { csv, mapping: {} });
      fillSelects(r.columns);
      document.getElementById('mapping-panel').hidden = false;
      w.show('Map the columns, then preview.', false);
    } catch (err) {
      w.show(err.message || 'Could not read the file.', true);
    }
  });

  document.getElementById('import-preview').addEventListener('click', async () => {
    try {
      const r = await w.post('/inventory/import/preview', request());
      rowsBody.replaceChildren();
      for (const row of r.rows) {
        const tr = document.createElement('tr');
        const box = document.createElement('input');
        box.type = 'checkbox';
        box.value = String(row.number);
        const importable = row.errors.length === 0 && !row.exists;
        box.checked = importable;
        box.disabled = !importable;
        box.className = 'import-row';
        const td = document.createElement('td');
        td.appendChild(box);
        tr.appendChild(td);
        cell(tr, String(row.number));
        cell(tr, row.id);
        cell(tr, row.display_name);
        cell(tr, row.environment);
        cell(tr, row.criticality);
        cell(tr, (row.endpoints || []).join(', '));
        cell(tr, Object.entries(row.tags || {}).map(([k, v]) => k + '=' + v).join(', '));
        const problems = row.errors.slice();
        if (row.exists) problems.push('a host with this ID exists already');
        cell(tr, problems.join('; '));
        rowsBody.appendChild(tr);
      }
      document.getElementById('preview-panel').hidden = false;
      w.show(r.rows.length + ' rows read.', false);
    } catch (err) {
      w.show(err.message || 'Preview failed.', true);
    }
  });

  selectAll.addEventListener('change', () => {
    for (const b of document.querySelectorAll('.import-row')) if (!b.disabled) b.checked = selectAll.checked;
  });

  document.getElementById('import-commit').addEventListener('click', async () => {
    const rows = Array.from(document.querySelectorAll('.import-row'))
      .filter((b) => b.checked && !b.disabled)
      .map((b) => parseInt(b.value, 10));
    if (rows.length === 0) {
      w.show('Select at least one row.', true);
      return;
    }
    try {
      const r = await w.post('/inventory/import/commit', request({ rows }));
      const list = document.getElementById('results');
      list.replaceChildren();
      for (const x of r.results) {
        const li = document.createElement('li');
        li.textContent = 'Row ' + x.number + (x.id ? ' (' + x.id + ')' : '') + ': ' + x.status + (x.reason ? ' — ' + x.reason : '');
        list.appendChild(li);
      }
      document.getElementById('result-panel').hidden = false;
      w.show('Import finished.', false);
    } catch (err) {
      w.show(err.message || 'Import failed.', true);
    }
  });
})();

// SPDX-License-Identifier: AGPL-3.0-or-later
// Host page: the delete button stays disabled until the typed host ID
// matches. The server re-checks the value, this is only for clarity.
'use strict';

(() => {
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

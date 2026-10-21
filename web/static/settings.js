// SPDX-License-Identifier: AGPL-3.0-or-later
// Settings page: posts the chosen theme as JSON (through nebulaWebAuthn.post,
// so the security middleware's Origin check holds) and reloads so the new
// theme applies. The form is JS-only, like the other state-changing forms;
// without JS submitting it is a no-op GET to the current page.
(function () {
  'use strict';

  var form = document.getElementById('appearance-form');
  if (!form) return;

  form.addEventListener('submit', function (e) {
    e.preventDefault();
    var checked = form.querySelector('input[name="theme"]:checked');
    if (!checked || typeof nebulaWebAuthn === 'undefined') return;
    var btn = document.getElementById('appearance-submit');
    if (btn) btn.disabled = true;
    nebulaWebAuthn
      .post('/settings/appearance', { theme: checked.value })
      .then(function () {
        window.location.reload();
      })
      .catch(function () {
        if (btn) btn.disabled = false;
      });
  });
})();

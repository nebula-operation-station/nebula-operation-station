// SPDX-License-Identifier: AGPL-3.0-or-later
// Settings page: posts the chosen theme as JSON (through nebulaWebAuthn.post,
// so the security middleware's Origin check holds) and reloads so the new
// theme applies. The "Add a security key" panel runs the existing /setup
// registration flow while logged in: the one-time code comes from the
// executor host, and when keys are registered already the browser asks a
// confirming key. Removing a key and TOTP setup and removal stay CLI-only;
// the page only shows the exact commands.
(function () {
  'use strict';

  var form = document.getElementById('appearance-form');
  if (form) {
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
  }

  var keyForm = document.getElementById('key-form');
  if (!keyForm) return;

  var label = document.getElementById('key-label');
  var codeCmd = document.getElementById('key-code-cmd');
  var message = document.getElementById('key-message');

  // The label travels with the one-time code: the admin sets it on the
  // executor host, so the panel composes the exact command to run there.
  // The limits mirror the setup label: at most 200 printable characters,
  // and no characters that would break the shell command.
  function labelProblem(l) {
    if (l.length > 200) return 'Label longer than 200 characters.';
    for (var i = 0; i < l.length; i++) {
      var c = l.charCodeAt(i);
      if (c < 0x20 || c === 0x7f) return 'Label contains a non-printable character.';
    }
    if (/[\"$\\`]/.test(l)) return 'Label must not contain " $ \\ or `.';
    return null;
  }

  label.addEventListener('input', function () {
    var l = label.value.trim();
    var problem = labelProblem(l);
    if (problem) {
      codeCmd.textContent = problem;
      return;
    }
    codeCmd.textContent = l
      ? 'On the Nebula machine: nebula webauthn code --label "' + l + '"'
      : 'On the Nebula machine: nebula webauthn code';
  });

  keyForm.addEventListener('submit', function (e) {
    e.preventDefault();
    if (typeof nebulaWebAuthn === 'undefined') return;
    var btn = document.getElementById('key-submit');
    var code = document.getElementById('key-code').value.trim();
    btn.disabled = true;
    nebulaWebAuthn
      .register(code, message)
      .then(function (done) {
        if (done.recovery_confirmation_required) {
          message.textContent =
            'Security key registered. To end the recovery, confirm it on the executor host: nebula totp finish-recovery';
        } else {
          window.location.reload();
        }
      })
      .catch(function (err) {
        if (err.name === 'NotAllowedError') message.textContent = 'Cancelled or timed out.';
        else if (err.name === 'InvalidStateError') message.textContent = 'This security key is already registered.';
        else message.textContent = err.message || 'Registration failed.';
        message.classList.add('message--error');
        btn.disabled = false;
      });
  });
})();

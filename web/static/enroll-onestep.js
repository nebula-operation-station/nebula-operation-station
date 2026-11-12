// SPDX-License-Identifier: AGPL-3.0-or-later
// One-step enrollment (ADR 0013, EN-10): checks the pairing code before
// it is submitted (length, alphabet and the mod-37 check character, the
// same rules as internal/pairing.Parse; the server checks again) and
// approves a matched pin with the security key. Values are shown with
// textContent only.
'use strict';

(() => {
  // Crockford base32 data symbols (value = index) and the 37-symbol
  // check alphabet (ADR 0013 D3).
  const DATA = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
  const CHECK = '0123456789ABCDEFGHJKMNPQRSTVWXYZ*~$=U';
  const MAX_INPUT = 64;
  const DATA_CHARS = 24;

  // fold applies the Crockford folding: case-insensitive, O -> 0,
  // I and L -> 1; hyphens and spaces are ignored.
  function fold(raw) {
    let out = '';
    for (const ch of raw) {
      if (ch === '-' || ch === ' ') continue;
      let c = ch.toUpperCase();
      if (c === 'O') c = '0';
      else if (c === 'I' || c === 'L') c = '1';
      out += c;
    }
    return out;
  }

  // codeError returns '' for a well-formed code, otherwise the reason.
  function codeError(raw) {
    if (raw.length > MAX_INPUT) return 'The pairing code is too long.';
    const s = fold(raw);
    if (s.length !== DATA_CHARS + 1) return 'The pairing code must have 25 characters (five groups of five).';
    // v mod 37 over the 120-bit value, digit by digit (Horner).
    let c = 0;
    for (let i = 0; i < DATA_CHARS; i++) {
      const v = DATA.indexOf(s[i]);
      if (v < 0) return 'The pairing code has an invalid character at position ' + (i + 1) + '.';
      c = (c * 32 + v) % 37;
    }
    const check = CHECK.indexOf(s[DATA_CHARS]);
    if (check < 0) return 'The pairing code has an invalid character at position 25.';
    if (check !== c) return "The pairing code's check character does not match: there is a typing error in the code.";
    return '';
  }

  const codeForm = document.getElementById('onestep-code');
  if (codeForm) {
    const input = document.getElementById('onestep-code-input');
    const msg = document.getElementById('onestep-code-msg');
    const check = (final) => {
      const raw = input.value;
      const err = raw === '' && !final ? '' : codeError(raw);
      input.setCustomValidity(err);
      msg.textContent = err || (raw === '' ? '' : 'Code format and check character are correct.');
      msg.classList.toggle('message--error', err !== '');
      return err === '';
    };
    input.addEventListener('input', () => check(false));
    codeForm.addEventListener('submit', (e) => {
      if (!check(true)) {
        e.preventDefault();
        input.focus();
      }
    });
  }

  const approval = document.getElementById('onestep-approval');
  if (approval && typeof nebulaWebAuthn !== 'undefined') {
    const w = nebulaWebAuthn;
    const result = document.getElementById('onestep-result');
    const buttons = [document.getElementById('onestep-approve'), document.getElementById('onestep-approved-cli')];
    const commit = async (withKey) => {
      for (const b of buttons) b.disabled = true;
      try {
        const body = {};
        if (withKey) {
          const options = JSON.parse(approval.dataset.options || 'null');
          if (!options) throw new Error('No approval challenge; submit the code again.');
          w.show('Touch your security key…', false);
          const cred = await navigator.credentials.get(w.requestOptions(options));
          body.assertion = w.assertionJSON(cred);
        }
        w.show('Pinning…', false);
        const r = await w.post(approval.dataset.commit, body);
        let text = r.pinned ? 'Pinned ' + r.fingerprint : 'Not pinned: ' + (r.error || r.state || 'unknown reason');
        if (r.pinned) {
          text += r.login_ok ? '; login works.' : (r.login_detail ? '; ' + r.login_detail : '.');
          if (r.endpoint_added) text += ' Endpoint ' + r.endpoint_added + ' added to the inventory host.';
          if (r.endpoint_error) text += ' ' + r.endpoint_error;
        }
        result.textContent = text;
        w.show(r.pinned ? 'Host enrolled.' : 'Enrollment failed.', !r.pinned);
      } catch (err) {
        w.show(err.name === 'NotAllowedError' ? 'Cancelled or timed out.' : (err.message || 'Approval failed.'), true);
        for (const b of buttons) b.disabled = false;
      }
    };
    buttons[0].addEventListener('click', () => commit(true));
    buttons[1].addEventListener('click', () => commit(false));
  }
})();

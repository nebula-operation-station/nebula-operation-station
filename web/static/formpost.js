// SPDX-License-Identifier: AGPL-3.0-or-later
// Plain HTML forms that change state (host refresh, settings, delete).
// The security headers set Referrer-Policy: no-referrer, so a browser form
// navigation sends "Origin: null" and the middleware refuses it. These forms
// are therefore submitted with fetch (which sends the real Origin), and the
// page then follows the server's redirect. Errors are shown as text.
'use strict';

(() => {
  for (const form of document.querySelectorAll('form[method="post"][data-fetch]')) {
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const button = form.querySelector('button[type="submit"]');
      if (button) button.disabled = true;
      let msg = form.querySelector('.message');
      try {
        const res = await fetch(form.action, {
          method: 'POST',
          credentials: 'same-origin',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams(new FormData(form)),
        });
        if (res.ok) {
          window.location.assign(res.url);
          return;
        }
        const text = (await res.text()).trim();
        if (!msg) {
          msg = document.createElement('p');
          msg.className = 'message message--error';
          msg.setAttribute('role', 'status');
          form.appendChild(msg);
        }
        msg.textContent = text || ('Request failed (' + res.status + ')'); // text, never HTML
      } catch (err) {
        if (msg) msg.textContent = String(err);
      }
      if (button) button.disabled = false;
    });
  }
})();

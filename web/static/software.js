// SPDX-License-Identifier: AGPL-3.0-or-later
// Software catalog pages (ADR 0009 D5, D6; internal/web/ui/software).
//
// 1. Forms with data-confirm ask before they are submitted (merge,
//    ignore). The listener runs in the capture phase on the document, so
//    it runs before formpost.js submits the form with fetch.
// 2. Forms with data-sw-upload post the chosen image file as the raw
//    request body with fetch (so the browser sends the real Origin), then
//    follow the server's redirect to the icon page.
//
// Messages are set with textContent only; this script never parses or
// inserts HTML and never creates image elements or sets image sources.
'use strict';

(() => {
  const TYPES = ['image/png', 'image/jpeg', 'image/gif'];
  const MAX_BYTES = 256 * 1024;

  document.addEventListener('submit', (e) => {
    const form = e.target;
    if (!(form instanceof HTMLFormElement)) return;
    const question = form.dataset.confirm;
    if (question && !window.confirm(question)) {
      e.preventDefault();
      e.stopImmediatePropagation();
    }
  }, true);

  for (const form of document.querySelectorAll('form[method="post"][data-sw-upload]')) {
    const msg = form.querySelector('.message');
    const say = (text) => {
      if (!msg) return;
      msg.textContent = text; // text, never HTML
      msg.hidden = false;
    };
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const input = form.querySelector('input[type="file"]');
      const file = input && input.files && input.files[0];
      if (!file) {
        say('Choose an image first.');
        return;
      }
      if (!TYPES.includes(file.type)) {
        say('Only PNG, JPEG or GIF images are accepted (SVG and WebP are not supported).');
        return;
      }
      if (file.size > MAX_BYTES) {
        say('The image is larger than 256 KiB.');
        return;
      }
      const button = form.querySelector('button[type="submit"]');
      if (button) button.disabled = true;
      try {
        // The attribute, because a field named "action" would shadow the property.
        const target = new URL(form.getAttribute('action') || window.location.href, window.location.href);
        const res = await fetch(target, {
          method: 'POST',
          credentials: 'same-origin',
          headers: { 'Content-Type': file.type },
          body: file,
        });
        if (res.ok && res.redirected) {
          window.location.assign(res.url);
          return;
        }
        const text = (await res.text()).trim();
        say(text || ('Upload failed (' + res.status + ')'));
      } catch (err) {
        say(String(err));
      }
      if (button) button.disabled = false;
    });
  }
})();

// SPDX-License-Identifier: AGPL-3.0-or-later
// Navigation actions. POSTs go through fetch: a plain form would send
// "Origin: null" (Referrer-Policy no-referrer) and be rejected.
'use strict';

(() => {
  const logout = document.getElementById('logout');
  if (!logout) return;
  logout.addEventListener('click', async () => {
    logout.disabled = true;
    try {
      await fetch('/logout', { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' }, body: '{}' });
    } finally {
      window.location.assign('/login');
    }
  });
})();

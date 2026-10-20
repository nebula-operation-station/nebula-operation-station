// SPDX-License-Identifier: AGPL-3.0-or-later
// Navigation actions. POSTs go through fetch: a plain form would send
// "Origin: null" (Referrer-Policy no-referrer) and be rejected.
'use strict';

(() => {
  const logout = document.getElementById('logout');
  if (logout) {
    logout.addEventListener('click', async () => {
      logout.disabled = true;
      try {
        await fetch('/logout', { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' }, body: '{}' });
      } finally {
        window.location.assign('/login');
      }
    });
  }

  // Mobile: the sidebar becomes a top bar and the menu button toggles the nav.
  // The nav is visible by default (no-JS fallback); the class only ever hides it.
  const toggle = document.getElementById('nav-toggle');
  const app = document.querySelector('.app');
  if (toggle && app) {
    toggle.addEventListener('click', () => {
      const collapsed = app.classList.toggle('app--nav-collapsed');
      toggle.setAttribute('aria-expanded', collapsed ? 'false' : 'true');
    });
  }
})();

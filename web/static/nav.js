// SPDX-License-Identifier: AGPL-3.0-or-later
// Navigation actions. POSTs go through fetch: a plain form would send
// "Origin: null" (Referrer-Policy no-referrer) and be rejected.
'use strict';

(() => {
  // The drawer styles below only apply to html.js: without JavaScript the
  // sidebar stays a static top bar on phones, so the navigation remains
  // reachable.
  document.documentElement.classList.add('js');

  const app = document.querySelector('.app');

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

  // Desktop: the toggle collapses the sidebar to icons only. The state is
  // remembered in the nebula_nav cookie (POST /ui/nav) so the server
  // renders the right state on the next load; the DOM class is updated
  // here for the current one and rolled back if the request fails.
  const collapse = document.getElementById('nav-collapse');
  if (collapse && app) {
    const setIcon = (collapsed) => {
      const use = collapse.querySelector('use');
      if (use) {
        use.setAttribute('href', '/static/icons.svg#i-panel-left-' + (collapsed ? 'open' : 'close'));
      }
    };
    const apply = (collapsed) => {
      app.classList.toggle('app--nav-collapsed', collapsed);
      collapse.setAttribute('aria-expanded', collapsed ? 'false' : 'true');
      collapse.setAttribute('aria-label', collapsed ? 'Expand navigation' : 'Collapse navigation');
      setIcon(collapsed);
    };
    collapse.addEventListener('click', () => {
      const collapsed = !app.classList.contains('app--nav-collapsed');
      apply(collapsed);
      fetch('/ui/nav', { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ collapsed }) })
        .then((r) => {
          if (!r.ok) {
            throw new Error('status ' + r.status);
          }
        })
        .catch(() => apply(!collapsed));
    });
  }

  // Phones: the sidebar is an off-canvas drawer opened by the menu button
  // in the top bar. Escape closes it and focus returns to the button.
  const menu = document.getElementById('nav-menu');
  const close = document.getElementById('nav-close');
  const backdrop = document.getElementById('nav-backdrop');
  if (menu && app && backdrop) {
    const openDrawer = () => {
      app.classList.add('app--drawer-open');
      menu.setAttribute('aria-expanded', 'true');
      menu.setAttribute('aria-label', 'Close navigation');
      if (close) {
        close.focus();
      }
    };
    const closeDrawer = () => {
      app.classList.remove('app--drawer-open');
      menu.setAttribute('aria-expanded', 'false');
      menu.setAttribute('aria-label', 'Open navigation');
      menu.focus();
    };
    menu.addEventListener('click', () => {
      if (app.classList.contains('app--drawer-open')) {
        closeDrawer();
      } else {
        openDrawer();
      }
    });
    if (close) {
      close.addEventListener('click', closeDrawer);
    }
    backdrop.addEventListener('click', closeDrawer);
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' && app.classList.contains('app--drawer-open')) {
        closeDrawer();
      }
    });
  }

  // On narrow screens the full placeholder is clipped inside the search
  // field, so swap in a shorter one; the long text stays on wide screens.
  const search = document.querySelector('.topbar__search input');
  if (search) {
    const long = search.getAttribute('placeholder') || '';
    const short = 'Search hosts, IPs …';
    const narrow = window.matchMedia('(max-width: 600px)');
    const apply = () => {
      search.placeholder = narrow.matches ? short : long;
    };
    apply();
    narrow.addEventListener('change', apply);
  }
})();

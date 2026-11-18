// SPDX-License-Identifier: AGPL-3.0-or-later

// Polls the question list of the Assistant's Ops tab (ADR 0016 D11). The
// browser asks; the server never pushes. Only the list is refreshed, so text
// typed into the question form is kept. Loaded with the Ops tab; the guard
// keeps a second load from starting a second timer.
(function () {
  'use strict';

  // Interval of the question list refresh, in milliseconds.
  var ASSISTANT_OPS_POLL_MS = 15000;

  if (window.nosAssistantOpsPolling) {
    return;
  }
  window.nosAssistantOpsPolling = true;

  function poll() {
    // The tab is not shown (another tab, or the panel is closed): nothing to do.
    var list = document.getElementById('assistant-questions');
    if (!list || !window.htmx || document.hidden) {
      return;
    }
    window.htmx.ajax('GET', list.getAttribute('data-url'), {
      target: '#assistant-questions',
      swap: 'outerHTML'
    });
  }

  window.setInterval(poll, ASSISTANT_OPS_POLL_MS);
})();

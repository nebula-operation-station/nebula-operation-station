// Show <time datetime="RFC3339"> elements in the browser's local time, with a
// relative "5 min ago" / "in 2 h" title. The server renders the UTC text as
// the fallback, so without JavaScript the page still shows a correct time.
(function () {
  'use strict';

  var MIN = 60000, HOUR = 3600000, DAY = 86400000;

  function relative(ms) {
    var abs = Math.abs(ms);
    if (abs < MIN) return 'just now';
    if (abs < HOUR) return Math.round(abs / MIN) + ' min';
    if (abs < DAY) return Math.round(abs / HOUR) + ' h';
    return Math.round(abs / DAY) + ' d';
  }

  function render() {
    var now = Date.now();
    var els = document.querySelectorAll('time[datetime]');
    for (var i = 0; i < els.length; i++) {
      var el = els[i];
      var t = new Date(el.getAttribute('datetime'));
      if (isNaN(t.getTime())) continue;
      el.textContent = t.toLocaleString(undefined, { dateStyle: 'short', timeStyle: 'short' });
      var diff = t.getTime() - now;
      var rel = relative(diff);
      el.title = rel === 'just now' ? rel : diff >= 0 ? 'in ' + rel : rel + ' ago';
    }
  }

  render();
  setInterval(render, 60000);
})();

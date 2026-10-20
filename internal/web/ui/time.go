// SPDX-License-Identifier: AGPL-3.0-or-later

package ui

import (
	"html/template"
	"time"
)

// timeTag renders a <time> element for a timestamp shown on a page. The
// datetime attribute carries the RFC3339 UTC value so time.js can convert the
// visible text to the browser's local time (and a relative "5 min ago" title);
// without JS the UTC text stays. A zero time renders nothing.
//
// The element is built only from the time value — never from host data — so it
// is safe to emit as HTML.
func timeTag(t time.Time) template.HTML {
	if t.IsZero() {
		return ""
	}
	utc := t.UTC()
	const display = "2006-01-02 15:04:05 UTC"
	return template.HTML(`<time datetime="` + utc.Format(time.RFC3339) + `">` + utc.Format(display) + `</time>`)
}

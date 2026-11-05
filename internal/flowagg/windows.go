// SPDX-License-Identifier: AGPL-3.0-or-later

package flowagg

import (
	"fmt"
	"time"
)

// QueryWindow is one window a traffic view may query (ADR 0009 D3): the
// traffic map (internal/web/api/trafficmap) and the connections tab
// (internal/web/ui/connections) offer the same set.
type QueryWindow struct {
	// Name is the query parameter value: "1h", "24h", "7d" or "21d".
	Name string
	// Dur is the window's length.
	Dur time.Duration
}

// DefaultQueryWindow is the window shown when a request names none and
// the retention allows it.
const DefaultQueryWindow = "24h"

// queryWindows lists the windows, shortest first.
var queryWindows = []QueryWindow{
	{"1h", time.Hour},
	{"24h", 24 * time.Hour},
	{"7d", 7 * 24 * time.Hour},
	{"21d", 21 * 24 * time.Hour},
}

// RetentionReporter is implemented by a flow source that knows how long
// it keeps flow data (*trafficstore.Store, which an admin may configure
// lower than Retention).
type RetentionReporter interface {
	Retention() time.Duration
}

// EffectiveRetention returns the retention a traffic view must respect:
// configured (zero means Retention), lowered to src's own retention when
// src is a RetentionReporter. The result must lie in [1h, Retention], so
// at least the shortest window is always offered.
func EffectiveRetention(configured time.Duration, src any) (time.Duration, error) {
	r := configured
	if r == 0 {
		r = Retention
	}
	if rr, ok := src.(RetentionReporter); ok {
		r = min(r, rr.Retention())
	}
	if r < time.Hour || r > Retention {
		return 0, fmt.Errorf("flowagg: retention %s outside %s..%s", r, time.Hour, Retention)
	}
	return r, nil
}

// QueryWindows returns the windows no longer than retention, shortest
// first.
func QueryWindows(retention time.Duration) []QueryWindow {
	out := make([]QueryWindow, 0, len(queryWindows))
	for _, w := range queryWindows {
		if w.Dur <= retention {
			out = append(out, w)
		}
	}
	return out
}

// LookupQueryWindow returns the window called name when it exists and is
// no longer than retention.
func LookupQueryWindow(name string, retention time.Duration) (QueryWindow, bool) {
	for _, w := range queryWindows {
		if w.Name == name && w.Dur <= retention {
			return w, true
		}
	}
	return QueryWindow{}, false
}

// DefaultQueryWindowFor returns DefaultQueryWindow, or the longest window
// retention allows when it is shorter. retention must be at least an
// hour (EffectiveRetention).
func DefaultQueryWindowFor(retention time.Duration) QueryWindow {
	if w, ok := LookupQueryWindow(DefaultQueryWindow, retention); ok {
		return w
	}
	ws := QueryWindows(retention)
	if len(ws) == 0 {
		return queryWindows[0]
	}
	return ws[len(ws)-1]
}

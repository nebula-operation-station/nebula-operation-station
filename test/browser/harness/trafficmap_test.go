// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	tmapi "github.com/nebula-operation-station/nebula-operation-station/internal/web/api/trafficmap"
)

// TestHarnessTrafficMapNeedsASession: without preview the page, the
// renderer document and the model are behind the login, while the
// renderer modules load without cookies (the sandboxed iframe has none).
func TestHarnessTrafficMapNeedsASession(t *testing.T) {
	h := newHarness(false, "8080", t.TempDir())
	for _, p := range []string{"/traffic", "/traffic/frame", trafficMapAPIPath} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, p, nil))
		if rec.Code == http.StatusOK {
			t.Errorf("GET %s without a session = 200", p)
		}
	}
	if code, body := get(t, h, "/static/trafficmap/boot.js"); code != http.StatusOK || !strings.Contains(body, "startTrafficMap") {
		t.Errorf("renderer module without a session = %d", code)
	}
}

// TestHarnessTrafficMapServesHostileLabelsAsText: the preview harness
// serves the page with the sandboxed renderer iframe and a model whose
// hostile labels are JSON-escaped text (what trafficmap.spec.js draws).
func TestHarnessTrafficMapServesHostileLabelsAsText(t *testing.T) {
	h := newHarness(true, "8080", t.TempDir())
	code, body := get(t, h, "/traffic?window=24h&focus=e2e-host")
	if code != http.StatusOK {
		t.Fatalf("GET /traffic = %d", code)
	}
	if !strings.Contains(body, `sandbox="allow-scripts"`) {
		t.Fatal(`GET /traffic: no iframe with sandbox="allow-scripts"`)
	}
	if strings.Contains(body, "allow-same-origin") {
		t.Fatal("GET /traffic: the page grants allow-same-origin")
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/traffic/frame", nil))
	if csp := rec.Header().Get("Content-Security-Policy"); !strings.HasSuffix(csp, "sandbox allow-scripts") || !strings.Contains(csp, "connect-src 'none'") {
		t.Errorf("frame CSP = %q", csp)
	}

	code, body = get(t, h, trafficMapAPIPath+"?window=24h")
	if code != http.StatusOK {
		t.Fatalf("GET %s = %d: %s", trafficMapAPIPath, code, body)
	}
	if strings.ContainsAny(body, "<>") {
		t.Error("model contains raw markup characters")
	}
	var m tmapi.Model
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		t.Fatal(err)
	}
	labels := map[string]string{}
	for _, n := range m.Nodes {
		labels[n.ID] = n.Label
	}
	if labels["e2e-host"] != trafficHostLabel || labels["e2e-two"] != trafficTwoLabel {
		t.Errorf("labels = %q", labels)
	}
	if got := labels["asset:prn"]; strings.ContainsRune(got, '\u202e') || !strings.HasPrefix(got, "printer.local<svg") {
		t.Errorf("asset label = %q, want the bidi override removed", got)
	}
	if len(m.Zones) != 1 || m.Zones[0].Name != trafficZoneName {
		t.Errorf("zones = %+v", m.Zones)
	}
}

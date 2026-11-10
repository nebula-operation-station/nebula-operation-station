// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"html"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestHarnessAttackPathsNeedASession: without preview every attack-path
// route is behind the login.
func TestHarnessAttackPathsNeedASession(t *testing.T) {
	h := newHarness(false, "8080", t.TempDir())
	for _, p := range []string{"/vuln/paths", "/vuln/paths/map", "/vuln/paths/map/frame"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, p, nil))
		if rec.Code == http.StatusOK {
			t.Errorf("GET %s without a session = 200", p)
		}
	}
}

// TestHarnessAttackPathsServeHostileLabelsAsText: the preview harness
// serves the list with the hostile texts escaped (what attackpath.spec.js
// reads back) and an overlay frame with one beam between the two harness
// hosts on the traffic map and no label.
func TestHarnessAttackPathsServeHostileLabelsAsText(t *testing.T) {
	h := newHarness(true, "8080", t.TempDir())
	code, body := get(t, h, "/vuln/paths")
	if code != http.StatusOK {
		t.Fatalf("GET /vuln/paths = %d", code)
	}
	for _, l := range []string{pathsEntryLabel, pathsTargetLabel, pathsVulnID, pathsPackage} {
		if strings.Contains(body, l) || !strings.Contains(html.UnescapeString(body), l) {
			t.Errorf("list: %q not shown as escaped text", l)
		}
	}
	code, body = get(t, h, "/vuln/paths/map/frame?target=host:e2e-two")
	if code != http.StatusOK {
		t.Fatalf("GET frame = %d", code)
	}
	u := html.UnescapeString(body)
	if !strings.Contains(u, `"from":"e2e-host","to":"e2e-two"`) {
		t.Errorf("frame: no beam e2e-host -> e2e-two in %q", u)
	}
	if strings.Contains(u, "AP host") || strings.Contains(u, "AP jewel") || strings.Contains(u, "__pwned") {
		t.Error("frame carries a label")
	}
}

// TestHarnessPathsAdminHook: the hook clears and sets the admin flag and
// refuses anything else.
func TestHarnessPathsAdminHook(t *testing.T) {
	t.Cleanup(func() { pathsAdmin.Store(true) })
	for _, c := range []struct {
		q    string
		code int
		want bool
	}{{"on=0", http.StatusOK, false}, {"on=x", http.StatusBadRequest, false}, {"on=1", http.StatusOK, true}} {
		rec := httptest.NewRecorder()
		pathsAdminHook(rec, httptest.NewRequest(http.MethodGet, "/__paths/admin?"+c.q, nil))
		if rec.Code != c.code || pathsAdmin.Load() != c.want {
			t.Errorf("%s: status %d, admin %v; want %d, %v", c.q, rec.Code, pathsAdmin.Load(), c.code, c.want)
		}
	}
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package middleware

import (
	"bytes"
	"net/http"
	"testing"
)

// TestOriginExemptSkipsOnlyOriginCheck: a request the predicate exempts
// passes a state-changing request without an Origin, but keeps the security
// headers and the body limit. A request the predicate does not exempt is
// still refused.
func TestOriginExemptSkipsOnlyOriginCheck(t *testing.T) {
	exemptAPI := func(r *http.Request) bool { return r.URL.Path == "/api/v1/x" }
	h := Handler(Options{PublicOrigin: testOrigin, MaxBodyBytes: 16, OriginExempt: exemptAPI}, okHandler())

	cases := []struct {
		name, target, origin string
		body                 []byte
		want                 int
	}{
		{"exempt, no origin", "/api/v1/x", "", []byte("ok"), http.StatusOK},
		{"exempt, body over limit", "/api/v1/x", "", bytes.Repeat([]byte("a"), 17), http.StatusRequestEntityTooLarge},
		{"not exempt, no origin", "/ui", "", []byte("ok"), http.StatusForbidden},
		{"not exempt, wrong origin", "/ui", "https://evil.example", []byte("ok"), http.StatusForbidden},
		{"not exempt, matching origin", "/ui", testOrigin, []byte("ok"), http.StatusOK},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := do(h, http.MethodPost, c.target, c.origin, c.body)
			if rec.Code != c.want {
				t.Fatalf("status %d, want %d", rec.Code, c.want)
			}
			if got := rec.Header().Get("Content-Security-Policy"); got == "" {
				t.Fatal("Content-Security-Policy missing on a request the origin check exempted or refused")
			}
		})
	}
}

// TestOriginExemptNilKeepsCheck: without a predicate the chain is unchanged.
func TestOriginExemptNilKeepsCheck(t *testing.T) {
	h := Handler(Options{PublicOrigin: testOrigin}, okHandler())
	if rec := do(h, http.MethodPost, "/api/v1/x", "", []byte("ok")); rec.Code != http.StatusForbidden {
		t.Fatalf("status %d without predicate, want 403", rec.Code)
	}
}

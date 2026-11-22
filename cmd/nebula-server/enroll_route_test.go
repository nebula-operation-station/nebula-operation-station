// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/serverconfig"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
)

// enrollTestDeps returns deps with the listen address and a logger that
// writes into buf.
func enrollTestDeps(listen string, buf *bytes.Buffer) serverDeps {
	return serverDeps{
		cfg: serverconfig.Config{Listen: listen},
		log: slog.New(slog.NewTextHandler(buf, nil)),
	}
}

// TestEnrollOptionsResolverIgnoresForwardedFor: without trusted proxies the
// client address is the TCP peer, so a client-sent X-Forwarded-For cannot
// move the dialog's address or the download's rate-limit bucket.
func TestEnrollOptionsResolverIgnoresForwardedFor(t *testing.T) {
	var buf bytes.Buffer
	var o ui.Options
	if err := enrollFeature().options(enrollTestDeps("127.0.0.1:8080", &buf), &o); err != nil {
		t.Fatalf("options hook: %v", err)
	}
	if o.EnrollClientAddr == nil {
		t.Fatal("EnrollClientAddr not set")
	}
	req := httptest.NewRequest(http.MethodGet, "/enroll/x", nil)
	req.RemoteAddr = "192.0.2.10:4321"
	req.Header.Set("X-Forwarded-For", "203.0.113.5")
	res, err := o.EnrollClientAddr.Resolve(req)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res.Forwarded {
		t.Error("X-Forwarded-For used without a trusted proxy")
	}
	if got := res.Client.String(); got != "192.0.2.10" {
		t.Errorf("client = %s, want the TCP peer 192.0.2.10", got)
	}
}

// TestEnrollOptionsWarnsOnNonPublicListenerWithoutProxy: the startup warning
// of ADR 0013 fires when no trusted proxy is configured and the listener is
// loopback, private, link-local or wildcard (likely behind a reverse proxy
// that makes every client share one bucket). A public address stays quiet.
func TestEnrollOptionsWarnsOnNonPublicListenerWithoutProxy(t *testing.T) {
	cases := []struct {
		name   string
		listen string
		warn   bool
	}{
		{"loopback warns", "127.0.0.1:8080", true},
		{"private address warns", "192.168.1.10:8080", true},
		{"public address stays quiet", "203.0.113.7:8080", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			var o ui.Options
			if err := enrollFeature().options(enrollTestDeps(tc.listen, &buf), &o); err != nil {
				t.Fatalf("options hook: %v", err)
			}
			got := strings.Contains(buf.String(), "enrollment download enabled without trusted proxies")
			if got != tc.warn {
				t.Errorf("warning logged = %v, want %v; log:\n%s", got, tc.warn, buf.String())
			}
		})
	}
}

// TestEnrollRouteNeverLogsOfferID: the startup path of the route writes no
// path or offer ID; the log holds only the listener text.
func TestEnrollRouteNeverLogsOfferID(t *testing.T) {
	var buf bytes.Buffer
	var o ui.Options
	if err := enrollFeature().options(enrollTestDeps("203.0.113.7:8080", &buf), &o); err != nil {
		t.Fatalf("options hook: %v", err)
	}
	const id = "abcdefghijklmnopqrstuvwxyz234567"
	if strings.Contains(buf.String(), id) || strings.Contains(buf.String(), "/enroll/") {
		t.Errorf("log names the download route or an offer ID:\n%s", buf.String())
	}
}

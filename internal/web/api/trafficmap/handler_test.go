// SPDX-License-Identifier: AGPL-3.0-or-later

package trafficmap

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func newTestHandler(t *testing.T, allow bool, f *fakeFlows) *Handler {
	t.Helper()
	inv, sf := starInventory()
	if f == nil {
		f = sf
	}
	h, err := New(Options{
		Inventory: func(context.Context) (Inventory, error) { return inv, nil },
		Flows:     f,
		Authorize: func(*http.Request) bool { return allow },
		Now:       func() time.Time { return testNow },
		Log:       slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func serve(h http.Handler, method, target string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(method, target, nil))
	return rec
}

func TestHandlerRequiresAuthorization(t *testing.T) {
	inv := func(context.Context) (Inventory, error) { return Inventory{}, nil }
	if _, err := New(Options{Inventory: inv, Flows: &fakeFlows{}}); err == nil {
		t.Fatal("handler without authorization check accepted")
	}
	f := &fakeFlows{}
	rec := serve(newTestHandler(t, false, f), http.MethodGet, "/api/v1/trafficmap")
	if rec.Code != http.StatusForbidden || strings.Contains(rec.Body.String(), "nodes") {
		t.Fatalf("unauthorized: %d %s", rec.Code, rec.Body)
	}
	if len(f.windows) != 0 {
		t.Fatal("unauthorized request reached the store")
	}
}

func TestHandlerIsReadOnly(t *testing.T) {
	h := newTestHandler(t, true, nil)
	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		rec := serve(h, m, "/api/v1/trafficmap")
		if rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != "GET, HEAD" {
			t.Errorf("%s: %d", m, rec.Code)
		}
	}
}

func TestHandlerServesTheModel(t *testing.T) {
	h := newTestHandler(t, true, nil)
	rec := serve(h, http.MethodGet, "/api/v1/trafficmap?window=7d")
	if rec.Code != http.StatusOK {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	for k, v := range map[string]string{
		"Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff",
	} {
		if got := rec.Header().Get(k); got != v {
			t.Errorf("%s = %q", k, got)
		}
	}
	var m Model
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	if m.Window != "7d" || len(m.Edges) != 10 {
		t.Fatalf("window %q edges %d", m.Window, len(m.Edges))
	}
	rec = serve(h, http.MethodGet, "/api/v1/trafficmap?focus=p&window=1h")
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil || m.Focus != "p" || len(m.Edges) != 5 {
		t.Fatalf("focus: %v %+v", err, m)
	}
	rec = serve(h, http.MethodHead, "/api/v1/trafficmap")
	if rec.Code != http.StatusOK || rec.Body.Len() != 0 || rec.Header().Get("Content-Length") == "" {
		t.Fatalf("HEAD: %d body %d", rec.Code, rec.Body.Len())
	}
}

func TestHandlerRejectsBadQueries(t *testing.T) {
	h := newTestHandler(t, true, nil)
	tests := map[string]int{
		"?window=2h":                         http.StatusBadRequest,
		"?window=":                           http.StatusBadRequest,
		"?window=1h&window=7d":               http.StatusBadRequest,
		"?focus=%3Cscript%3E":                http.StatusBadRequest,
		"?focus=":                            http.StatusBadRequest,
		"?focus=nope":                        http.StatusNotFound,
		"?limit=100000":                      http.StatusBadRequest,
		"?window=%zz":                        http.StatusBadRequest,
		"?focus=" + strings.Repeat("a", 600): http.StatusBadRequest,
	}
	for q, want := range tests {
		rec := serve(h, http.MethodGet, "/api/v1/trafficmap"+q)
		if rec.Code != want {
			t.Errorf("%s: %d, want %d", q, rec.Code, want)
		}
		if strings.Contains(rec.Body.String(), "<script>") {
			t.Errorf("%s: input reflected unescaped: %s", q, rec.Body)
		}
	}
}

func TestHandlerHidesStoreErrors(t *testing.T) {
	f := &fakeFlows{err: errors.New("database /var/lib/nebula/traffic.db is locked")}
	rec := serve(newTestHandler(t, true, f), http.MethodGet, "/api/v1/trafficmap")
	if rec.Code != http.StatusServiceUnavailable || strings.Contains(rec.Body.String(), "traffic.db") {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
}

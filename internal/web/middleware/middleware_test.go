// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Table-driven tests for the HTTP security middleware: the response
// headers (acceptance criterion 1), the origin check (criterion 3), the
// body limit (criterion 2) and the server timeouts (criterion 2).

package middleware

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const testOrigin = "https://nebula.example.org"

var testCSP = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"

// newTestHandler builds the middleware chain around an ok handler.
func newTestHandler(opts Options, next http.Handler) http.Handler {
	if opts.PublicOrigin == "" {
		opts.PublicOrigin = testOrigin
	}
	return Handler(opts, next)
}

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Test", "reached")
		fmt.Fprint(w, "ok")
	})
}

func do(h http.Handler, method, target, origin string, body []byte) *httptest.ResponseRecorder {
	var r io.Reader
	if body != nil {
		r = bytes.NewReader(body)
	}
	req := httptest.NewRequest(method, target, r)
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// --- Acceptance criterion 1: headers on every response. ---

func TestSecurityHeaders(t *testing.T) {
	cases := []struct {
		header string
		want   string
	}{
		{"Content-Security-Policy", testCSP},
		{"X-Content-Type-Options", "nosniff"},
		{"Referrer-Policy", "no-referrer"},
		{"Cross-Origin-Opener-Policy", "same-origin"},
	}
	h := newTestHandler(Options{}, okHandler())
	rec := do(h, http.MethodGet, "/", "", nil)
	for _, tc := range cases {
		t.Run(tc.header, func(t *testing.T) {
			if got := rec.Header().Get(tc.header); got != tc.want {
				t.Errorf("%s = %q, want %q", tc.header, got, tc.want)
			}
		})
	}
}

func TestHeadersOnRejections(t *testing.T) {
	h := newTestHandler(Options{}, okHandler())
	rec := do(h, http.MethodPost, "/", "https://evil.example", nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	for _, header := range []string{"Content-Security-Policy", "X-Content-Type-Options", "Referrer-Policy", "Cross-Origin-Opener-Policy"} {
		if rec.Header().Get(header) == "" {
			t.Errorf("%s missing on 403 response", header)
		}
	}
	if got := rec.Header().Get("Content-Security-Policy"); got != testCSP {
		t.Errorf("CSP on 403 = %q", got)
	}
}

func TestHeadersOnBodyLimitRejection(t *testing.T) {
	h := newTestHandler(Options{MaxBodyBytes: 16}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.Copy(io.Discard, r.Body); err != nil {
			http.Error(w, "read", http.StatusInternalServerError)
			return
		}
		fmt.Fprint(w, "ok")
	}))
	rec := do(h, http.MethodPost, "/", testOrigin, bytes.Repeat([]byte("a"), 17))
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", rec.Code)
	}
	if rec.Header().Get("Content-Security-Policy") != testCSP {
		t.Error("CSP missing on 413 response")
	}
}

// --- Acceptance criterion 3: origin check for state-changing methods. ---

func TestOriginCheck(t *testing.T) {
	h := newTestHandler(Options{}, okHandler())
	cases := []struct {
		name   string
		method string
		origin string
		want   int
	}{
		{"get without origin", http.MethodGet, "", http.StatusOK},
		{"head without origin", http.MethodHead, "", http.StatusOK},
		{"options without origin", http.MethodOptions, "", http.StatusOK},
		{"get with foreign origin", http.MethodGet, "https://evil.example", http.StatusOK},
		{"post with matching origin", http.MethodPost, testOrigin, http.StatusOK},
		{"put with matching origin", http.MethodPut, testOrigin, http.StatusOK},
		{"patch with matching origin", http.MethodPatch, testOrigin, http.StatusOK},
		{"delete with matching origin", http.MethodDelete, testOrigin, http.StatusOK},
		{"post with foreign origin", http.MethodPost, "https://evil.example", http.StatusForbidden},
		{"put with foreign origin", http.MethodPut, "http://evil.example", http.StatusForbidden},
		{"patch with foreign origin", http.MethodPatch, "https://evil.example.evil", http.StatusForbidden},
		{"delete with foreign origin", http.MethodDelete, "https://evil.example", http.StatusForbidden},
		{"post without origin", http.MethodPost, "", http.StatusForbidden},
		{"post with origin missing scheme", http.MethodPost, "//nebula.example.org", http.StatusForbidden},
		{"post with origin trailing slash", http.MethodPost, testOrigin + "/", http.StatusForbidden},
		{"post with origin different case", http.MethodPost, "HTTPS://nebula.example.org", http.StatusForbidden},
		{"post with origin different port", http.MethodPost, "https://nebula.example.org:8443", http.StatusForbidden},
		{"trace requires origin", http.MethodTrace, "", http.StatusForbidden},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := do(h, tc.method, "/", tc.origin, nil)
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d", rec.Code, tc.want)
			}
			if tc.want == http.StatusOK && rec.Header().Get("X-Test") != "reached" {
				t.Error("handler was not reached")
			}
			if tc.want == http.StatusForbidden && rec.Header().Get("X-Test") != "" {
				t.Error("handler was reached for a rejected origin")
			}
		})
	}
}

// --- Acceptance criterion 2: body limit. ---

func TestBodyLimitDefault(t *testing.T) {
	h := newTestHandler(Options{}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.Copy(io.Discard, r.Body); err != nil {
			http.Error(w, "read", http.StatusInternalServerError)
			return
		}
		fmt.Fprint(w, "ok")
	}))
	// One byte over the 1 MiB default.
	rec := do(h, http.MethodPost, "/", testOrigin, bytes.Repeat([]byte("a"), DefaultMaxBodyBytes+1))
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", rec.Code)
	}
	// Exactly at the limit passes.
	rec = do(h, http.MethodPost, "/", testOrigin, bytes.Repeat([]byte("a"), DefaultMaxBodyBytes))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func TestBodyLimitConfigurable(t *testing.T) {
	h := newTestHandler(Options{MaxBodyBytes: 16}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.Copy(io.Discard, r.Body); err != nil {
			http.Error(w, "read", http.StatusInternalServerError)
			return
		}
		fmt.Fprint(w, "ok")
	}))
	rec := do(h, http.MethodPost, "/", testOrigin, bytes.Repeat([]byte("a"), 17))
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", rec.Code)
	}
	rec = do(h, http.MethodPost, "/", testOrigin, bytes.Repeat([]byte("a"), 16))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func TestBodyLimitBackstopChunked(t *testing.T) {
	// A chunked request has ContentLength == -1, so the Content-Length
	// pre-check cannot see the size. The MaxBytesReader backstop must still
	// stop the read once the limit is exceeded, and the handler answers 413.
	h := newTestHandler(Options{MaxBodyBytes: 16}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var mbe *http.MaxBytesError
		if _, err := io.Copy(io.Discard, r.Body); err != nil {
			if errors.As(err, &mbe) {
				http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
				return
			}
			http.Error(w, "read", http.StatusInternalServerError)
			return
		}
		fmt.Fprint(w, "ok")
	}))
	// Build a request whose declared length is unknown (chunked).
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(bytes.Repeat([]byte("a"), 17)))
	req.ContentLength = -1
	req.Header.Set("Origin", testOrigin)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", rec.Code)
	}
}

func TestDefaultMaxBodyBytesValue(t *testing.T) {
	if DefaultMaxBodyBytes != 1<<20 {
		t.Errorf("DefaultMaxBodyBytes = %d, want 1 MiB", DefaultMaxBodyBytes)
	}
}

// --- Acceptance criterion 2: server timeouts. ---

func TestNewServerTimeouts(t *testing.T) {
	s, err := NewServer(Options{PublicOrigin: testOrigin}, okHandler())
	if err != nil {
		t.Fatal(err)
	}
	if s.ReadTimeout != DefaultReadTimeout {
		t.Errorf("ReadTimeout = %v, want %v", s.ReadTimeout, DefaultReadTimeout)
	}
	if s.WriteTimeout != DefaultWriteTimeout {
		t.Errorf("WriteTimeout = %v, want %v", s.WriteTimeout, DefaultWriteTimeout)
	}
	if s.IdleTimeout != DefaultIdleTimeout {
		t.Errorf("IdleTimeout = %v, want %v", s.IdleTimeout, DefaultIdleTimeout)
	}
	if s.Handler == nil {
		t.Error("server handler is nil")
	}
}

func TestNewServerTimeoutsConfigurable(t *testing.T) {
	s, err := NewServer(Options{
		PublicOrigin: testOrigin,
		ReadTimeout:  time.Second,
		WriteTimeout: 2 * time.Second,
		IdleTimeout:  3 * time.Second,
	}, okHandler())
	if err != nil {
		t.Fatal(err)
	}
	if s.ReadTimeout != time.Second || s.WriteTimeout != 2*time.Second || s.IdleTimeout != 3*time.Second {
		t.Errorf("timeouts = %v/%v/%v", s.ReadTimeout, s.WriteTimeout, s.IdleTimeout)
	}
}

func TestNewServerRequiresPublicOrigin(t *testing.T) {
	if _, err := NewServer(Options{}, okHandler()); err == nil {
		t.Fatal("NewServer accepted an empty PublicOrigin")
	}
}

// TestServerEndToEnd serves the chain on a real listener and checks that a
// foreign-origin POST is rejected with 403 and the security headers.
func TestServerEndToEnd(t *testing.T) {
	s, err := NewServer(Options{PublicOrigin: testOrigin}, okHandler())
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(s.Handler)
	defer ts.Close()

	req, err := http.NewRequest(http.MethodPost, ts.URL, strings.NewReader("x"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Origin", "https://evil.example")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Security-Policy"); got != testCSP {
		t.Errorf("CSP = %q", got)
	}
}

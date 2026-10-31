// SPDX-License-Identifier: AGPL-3.0-or-later
// Package pveapi fuzz targets. These files exercise every PVE reader parser
// end-to-end (HTTP + decode + validate) with hostile bodies. They add no
// production code.
package pveapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"unicode/utf8"
)

// fuzzT is the subset of *testing.T / *testing.F the helpers need, so a helper
// can be called from both the seed section (f) and the fuzz closure (t).
type fuzzT interface {
	Helper()
	Fatalf(format string, args ...any)
	Cleanup(func())
}

// readFuzzFixture reads a test fixture from testdata, failing the test on
// error. Fuzz targets use these as seed corpus entries.
func readFuzzFixture(t fuzzT, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return b
}

// wrapData wraps a raw PVE payload in the {"data": ...} envelope returned by
// the HTTP endpoints. Fixtures under testdata/pve8/ are raw data values and
// need this; top-level fixtures are already wrapped.
func wrapData(payload []byte) []byte {
	out := make([]byte, 0, len(payload)+9)
	out = append(out, `{"data":`...)
	out = append(out, payload...)
	out = append(out, '}')
	return out
}

// fuzzServer is a persistent httptest server whose handler returns, for every
// request, the body chosen by route. A fuzz target feeds hostile bytes through
// the real HTTP + decode pipeline by swapping the served body each iteration
// instead of rebuilding a server on every call.
type fuzzServer struct {
	srv   *httptest.Server
	route func(path string) []byte
}

// newFuzzServer starts a catch-all JSON server driven by route. The server is
// closed via t.Cleanup when the test (or fuzz run) finishes.
func newFuzzServer(t fuzzT, route func(path string) []byte) *fuzzServer {
	t.Helper()
	fs := &fuzzServer{route: route}
	fs.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(fs.route(r.URL.Path))
	}))
	t.Cleanup(fs.srv.Close)
	return fs
}

// url returns the server base URL for client construction.
func (fs *fuzzServer) url() string { return fs.srv.URL }

// newFuzzClient builds a standard pveapi Client against base (the fuzz server
// URL) with the fixed test token. It is used by every reader that goes through
// New (inventory, config, agent, storage, snapshots, cluster, tasks).
func newFuzzClient(t fuzzT, base string) *Client {
	t.Helper()
	c, err := New(base, http.DefaultClient, func(context.Context) (string, error) {
		return testToken, nil
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

// assertFuzzInvariants checks the invariants every reader must uphold on a
// hostile body:
//
//   - an oversize body (longer than sizeLimit) is rejected with an error;
//   - for readers that validate UTF-8 at the body level (rejectUTF8), an
//     invalid-UTF-8 body is rejected with an error;
//   - on success, checkLimits (if non-nil) must hold.
//
// A panic inside the reader is caught by the fuzzer itself, so these
// assertions only need to cover the non-panic rejection/limit invariants.
func assertFuzzInvariants(t *testing.T, data []byte, sizeLimit int, rejectUTF8 bool, err error, checkLimits func()) {
	t.Helper()
	if len(data) > sizeLimit && err == nil {
		t.Fatalf("oversize body (%d bytes > %d) accepted without error", len(data), sizeLimit)
	}
	if rejectUTF8 && !utf8.Valid(data) && err == nil {
		t.Fatalf("invalid utf-8 body accepted without error")
	}
	if err == nil && checkLimits != nil {
		checkLimits()
	}
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package nosclient

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/serverconfig"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnstore"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/api"
)

// The tests run the client against the real api.VulnHandler on a real
// vulnstore in a temporary directory, behind an httptest TLS server on
// loopback. Synthetic data only.

var t0 = time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)

const digestA = "sha256:abababababababababababababababababababababababababababababababab"

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) Add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

type fakeInventory struct {
	mu      sync.Mutex
	snaps   map[string]api.VulnSnapshot
	current string
}

func (f *fakeInventory) VulnSnapshot(_ context.Context, id string) (api.VulnSnapshot, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if id == "" {
		id = f.current
	}
	s, ok := f.snaps[id]
	if !ok {
		return api.VulnSnapshot{}, api.ErrVulnSnapshotGone
	}
	return s, nil
}

func (f *fakeInventory) set(s api.VulnSnapshot) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.snaps = map[string]api.VulnSnapshot{s.ID: s}
	f.current = s.ID
}

type unconfirmed struct{}

func (unconfirmed) Classify(context.Context, vulnstore.Finding) (vulnstore.Class, error) {
	return vulnstore.ClassUnconfirmed, nil
}

func tierOf(vulnstore.Subject, vulnfinding.Record) vulnstore.Tier { return vulnstore.TierMedium }

var testSources = []vulnstore.Source{
	{ID: "debian-tracker", MaxAge: 72 * time.Hour},
	{ID: "kev", MaxAge: 72 * time.Hour},
}

func comp(src, ver string) api.VulnComponent {
	return api.VulnComponent{Source: src, SourceVersion: ver, Binaries: []api.VulnBinary{{Name: src, Version: ver, Arch: "amd64"}}}
}

func bigComponent(i int) api.VulnComponent {
	c := api.VulnComponent{Source: fmt.Sprintf("pkg%05d", i), SourceVersion: "1.0-1"}
	for j := 0; j < 256; j++ {
		c.Binaries = append(c.Binaries, api.VulnBinary{Name: fmt.Sprintf("pkg%05d-binary-package-%03d", i, j), Version: "1.0-1+b1", Arch: "amd64"})
	}
	return c
}

func baseSnapshot(id string, gen int64, at time.Time) api.VulnSnapshot {
	return api.VulnSnapshot{ID: id, Generation: gen, TakenAt: at, Subjects: []api.VulnSubject{
		{Kind: vulnfinding.SubjectHost, Ref: vulnfinding.SubjectRef{ID: "web01"}, Ecosystem: "debian:bookworm", Complete: true,
			Kernel:     &api.VulnKernel{Release: "6.1.0-28-amd64", Source: "linux", SourceVersion: "6.1.119-1"},
			Components: []api.VulnComponent{comp("openssl", "3.0.15-1~deb12u1"), comp("bash", "5.2.15-2+b7")}},
		{Kind: vulnfinding.SubjectImage, Ref: vulnfinding.SubjectRef{ID: "web01", ImageDigest: digestA}, Ecosystem: "alpine:3.20", Complete: true,
			Components: []api.VulnComponent{comp("musl", "1.2.5-r0")}},
	}}
}

// bigComps components of bigComponent size (about 15 KiB each) do not fit
// on one 4 MiB page.
const bigComps = 350

// bigSnapshot has a host split over several pages between two small ones.
func bigSnapshot(id string) api.VulnSnapshot {
	s := api.VulnSnapshot{ID: id, Generation: 9, TakenAt: t0.Add(-time.Hour)}
	big := api.VulnSubject{Kind: vulnfinding.SubjectHost, Ref: vulnfinding.SubjectRef{ID: "big01"}, Ecosystem: "debian:bookworm", Complete: true}
	for i := 0; i < bigComps; i++ {
		big.Components = append(big.Components, bigComponent(i))
	}
	s.Subjects = append(s.Subjects,
		api.VulnSubject{Kind: vulnfinding.SubjectHost, Ref: vulnfinding.SubjectRef{ID: "first"}, Ecosystem: "debian:bookworm", Complete: true,
			Components: []api.VulnComponent{comp("bash", "5.2.15-2")}},
		big,
		api.VulnSubject{Kind: vulnfinding.SubjectHost, Ref: vulnfinding.SubjectRef{ID: "last"}, Complete: false,
			Components: []api.VulnComponent{comp("bash", "5.2.15-2")}})
	return s
}

// env is a real vuln API on an httptest TLS server.
type env struct {
	srv *httptest.Server
	inv *fakeInventory
	clk *clock
	log *bytes.Buffer
	// wrap, when set, sees every request before the handler.
	mu   sync.Mutex
	wrap func(w http.ResponseWriter, r *http.Request, next http.Handler) bool
	// requests counts requests per path.
	requests map[string]int
	caFile   string
	tokFile  string
	sleeps   []time.Duration
}

func newEnv(t *testing.T) *env {
	t.Helper()
	db, err := serverdb.Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	clk := &clock{t: t0}
	st, err := vulnstore.New(db, vulnstore.Config{Sources: testSources, Tier: tierOf, Classifier: unconfirmed{}, Now: clk.Now})
	if err != nil {
		t.Fatal(err)
	}
	inv := &fakeInventory{}
	inv.set(baseSnapshot("inv-1", 7, t0.Add(-time.Hour)))
	var buf bytes.Buffer
	tok := serverconfig.APIToken{Name: serverconfig.DefaultVulnTokenName, SHA256: api.HashToken(testToken),
		Scopes: []string{serverconfig.ScopeVulnInventoryRead, serverconfig.ScopeVulnFindingsWrite}, SourceAddresses: []string{"127.0.0.1"}}
	h, err := api.NewVuln(api.VulnOptions{Tokens: []serverconfig.APIToken{tok}, Inventory: inv, Store: st, Sources: testSources,
		Log: slog.New(slog.NewJSONHandler(&buf, nil)), Now: clk.Now})
	if err != nil {
		t.Fatal(err)
	}
	e := &env{inv: inv, clk: clk, log: &buf, requests: map[string]int{}}
	e.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e.mu.Lock()
		e.requests[r.URL.Path]++
		wrap := e.wrap
		e.mu.Unlock()
		if wrap != nil && wrap(w, r, h) {
			return
		}
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(e.srv.Close)
	e.caFile = writeCA(t, e.srv)
	e.tokFile = writeToken(t, testToken+"\n", 0o600)
	return e
}

func writeCA(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "ca.pem")
	b := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func (e *env) setWrap(f func(w http.ResponseWriter, r *http.Request, next http.Handler) bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.wrap = f
}

func (e *env) count(path string) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.requests[path]
}

func (e *env) config() Config {
	return Config{BaseURL: e.srv.URL, TokenFile: e.tokFile, CAFile: e.caFile, Now: e.clk.Now,
		Sleep: func(ctx context.Context, d time.Duration) error {
			e.mu.Lock()
			e.sleeps = append(e.sleeps, d)
			e.mu.Unlock()
			return ctx.Err()
		}}
}

func (e *env) client(t *testing.T) *Client {
	t.Helper()
	c, err := New(e.config())
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func (e *env) export(t *testing.T, c *Client) *Snapshot {
	t.Helper()
	snap, err := c.Export(context.Background(), func(Page) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	return snap
}

func startReq() StartRequest {
	at := t0.Add(-time.Hour)
	return StartRequest{MatcherVersion: "1.4.0", Sources: []SourceSnapshot{
		{SourceID: "debian-tracker", SnapshotID: "snap-debian-tracker", Integrity: vulnfinding.IntegrityNone, DateKind: DateKindData, ContentDate: at},
		{SourceID: "kev", SnapshotID: "snap-kev", Integrity: vulnfinding.IntegrityNone, DateKind: DateKindData, ContentDate: at},
	}}
}

// record is a valid Debian record for host web01's openssl.
func record(t *testing.T, cve string) json.RawMessage {
	t.Helper()
	r := map[string]any{
		"subject_kind":  "host",
		"subject_ref":   map[string]any{"id": "web01"},
		"ecosystem":     "debian:bookworm",
		"component":     map[string]any{"source_package": "openssl", "source_version": "3.0.15-1~deb12u1"},
		"vuln":          map[string]any{"id": cve},
		"fix":           map[string]any{"state": "fixed", "version": "3.0.16-1~deb12u1"},
		"tracker_state": "fixed",
		"match_basis":   "distro_tracker",
		"evidence": map[string]any{"matcher_version": "1.4.0",
			"basis_sources": []any{map[string]any{"source_id": "debian-tracker", "snapshot_id": "snap-debian-tracker", "integrity": "none"}}},
	}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func web01Host() BatchSubject {
	return BatchSubject{Kind: vulnfinding.SubjectHost, Ref: vulnfinding.SubjectRef{ID: "web01"}, Part: 1, LastPart: true}
}

// dropOnce lets the first request to path reach the handler and then
// drops the connection before the client gets the answer.
func dropOnce(path string) func(http.ResponseWriter, *http.Request, http.Handler) bool {
	var once sync.Once
	return func(w http.ResponseWriter, r *http.Request, next http.Handler) bool {
		if r.URL.Path != path {
			return false
		}
		dropped := false
		once.Do(func() {
			rec := httptest.NewRecorder()
			next.ServeHTTP(rec, r)
			hijackClose(w)
			dropped = true
		})
		return dropped
	}
}

func hijackClose(w http.ResponseWriter) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		return
	}
	conn, _, err := hj.Hijack()
	if err == nil {
		_ = conn.Close()
	}
}

// fixed answers every request with status and body.
func fixed(status int, body string, hdr ...string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		for i := 0; i+1 < len(hdr); i += 2 {
			w.Header().Set(hdr[i], hdr[i+1])
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}
}

// fakeServer is an httptest TLS server with a handler under test control;
// for answers the real handler never gives.
func fakeServer(t *testing.T, h http.Handler) Config {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	return Config{BaseURL: srv.URL, TokenFile: writeToken(t, testToken, 0o600), CAFile: writeCA(t, srv),
		Sleep: func(ctx context.Context, _ time.Duration) error { return ctx.Err() }}
}

func mustContain(t *testing.T, s, sub string) {
	t.Helper()
	if !strings.Contains(s, sub) {
		t.Fatalf("%q does not contain %q", s, sub)
	}
}

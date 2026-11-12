// SPDX-License-Identifier: AGPL-3.0-or-later

package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
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

// Synthetic test data only: documentation addresses, invented IDs.
const (
	vulnTok    = "nos_hermes-vuln-token"
	hermesAddr = "192.0.2.10:40000"
	digestA    = "sha256:abababababababababababababababababababababababababababababababab"
)

var vt0 = time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)

type vclock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *vclock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *vclock) Add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// fakeVulnInventory holds snapshots by ID; current is the newest.
type fakeVulnInventory struct {
	mu      sync.Mutex
	snaps   map[string]api.VulnSnapshot
	current string
}

func (f *fakeVulnInventory) VulnSnapshot(_ context.Context, id string) (api.VulnSnapshot, error) {
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

func (f *fakeVulnInventory) set(s api.VulnSnapshot) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.snaps = map[string]api.VulnSnapshot{s.ID: s}
	f.current = s.ID
}

type unconfirmed struct{}

func (unconfirmed) Classify(context.Context, vulnstore.Finding) (vulnstore.Class, error) {
	return vulnstore.ClassUnconfirmed, nil
}

func tierOf(_ vulnstore.Subject, r vulnfinding.Record) vulnstore.Tier {
	if r.Scores.KEV != nil {
		return vulnstore.TierCritical
	}
	return vulnstore.TierMedium
}

var vulnSources = []vulnstore.Source{
	{ID: "debian-tracker", MaxAge: 72 * time.Hour},
	{ID: "dsa", MaxAge: 72 * time.Hour},
	{ID: "kev", MaxAge: 72 * time.Hour},
	{ID: "osv", MaxAge: 72 * time.Hour},
}

type venv struct {
	h   *api.VulnHandler
	st  *vulnstore.Store
	inv *fakeVulnInventory
	clk *vclock
	log *bytes.Buffer
}

func comp(src, ver string) api.VulnComponent {
	return api.VulnComponent{Source: src, SourceVersion: ver, Binaries: []api.VulnBinary{{Name: src, Version: ver, Arch: "amd64"}}}
}

// baseSnapshot: host web01 (Debian 12, running kernel mapped), host db01
// (partial read), image on web01 (Alpine).
func baseSnapshot(id string, gen int64, at time.Time) api.VulnSnapshot {
	return api.VulnSnapshot{ID: id, Generation: gen, TakenAt: at, Subjects: []api.VulnSubject{
		{Kind: vulnfinding.SubjectHost, Ref: vulnfinding.SubjectRef{ID: "web01"}, Ecosystem: "debian:bookworm", Complete: true,
			Kernel:     &api.VulnKernel{Release: "6.1.0-28-amd64", Source: "linux", SourceVersion: "6.1.119-1"},
			Components: []api.VulnComponent{comp("openssl", "3.0.15-1~deb12u1"), comp("bash", "5.2.15-2+b7"), comp("curl", "7.88.1-10+deb12u8")}},
		{Kind: vulnfinding.SubjectHost, Ref: vulnfinding.SubjectRef{ID: "db01"}, Ecosystem: "debian:bookworm", Complete: false,
			Kernel:     &api.VulnKernel{Release: "6.1.0-28-amd64"},
			Components: []api.VulnComponent{comp("openssl", "3.0.15-1~deb12u1")}},
		{Kind: vulnfinding.SubjectImage, Ref: vulnfinding.SubjectRef{ID: "web01", ImageDigest: digestA}, Ecosystem: "alpine:3.20", Complete: true,
			Components: []api.VulnComponent{comp("musl", "1.2.5-r0")}},
	}}
}

func vulnToken(scopes ...string) serverconfig.APIToken {
	if len(scopes) == 0 {
		scopes = []string{serverconfig.ScopeVulnInventoryRead, serverconfig.ScopeVulnFindingsWrite}
	}
	return serverconfig.APIToken{Name: serverconfig.DefaultVulnTokenName, SHA256: api.HashToken(vulnTok), Scopes: scopes,
		SourceAddresses: []string{"192.0.2.10"}}
}

func newVulnEnv(t *testing.T, tokens ...serverconfig.APIToken) *venv {
	t.Helper()
	db, err := serverdb.Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	clk := &vclock{t: vt0}
	st, err := vulnstore.New(db, vulnstore.Config{Sources: vulnSources, Tier: tierOf, Classifier: unconfirmed{}, Now: clk.Now})
	if err != nil {
		t.Fatal(err)
	}
	inv := &fakeVulnInventory{}
	inv.set(baseSnapshot("inv-1", 7, vt0.Add(-time.Hour)))
	if len(tokens) == 0 {
		tokens = []serverconfig.APIToken{vulnToken(), {Name: "ha", SHA256: api.HashToken(invTok), Scopes: []string{serverconfig.ScopeInventoryRead}}}
	}
	var buf bytes.Buffer
	h, err := api.NewVuln(api.VulnOptions{Tokens: tokens, Inventory: inv, Store: st, Sources: vulnSources,
		Log: slog.New(slog.NewJSONHandler(&buf, nil)), Now: clk.Now})
	if err != nil {
		t.Fatal(err)
	}
	return &venv{h: h, st: st, inv: inv, clk: clk, log: &buf}
}

type resp struct {
	code int
	body string
	hdr  http.Header
}

func (r resp) json(t *testing.T) map[string]any {
	t.Helper()
	var v map[string]any
	if err := json.Unmarshal([]byte(r.body), &v); err != nil {
		t.Fatalf("%d %s: %v", r.code, r.body, err)
	}
	return v
}

func (e *venv) do(t *testing.T, method, path, tok string, body []byte) resp {
	t.Helper()
	return e.doFrom(t, method, path, tok, body, hermesAddr)
}

func (e *venv) doFrom(t *testing.T, method, path, tok string, body []byte, remote string) resp {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	req.RemoteAddr = remote
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	return resp{code: rec.Code, body: rec.Body.String(), hdr: rec.Header()}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func source(id string, at time.Time) map[string]any {
	return map[string]any{"source_id": id, "snapshot_id": "snap-" + id, "integrity": "none", "date_kind": "data",
		"content_date": at.UTC().Format(time.RFC3339)}
}

func (e *venv) startBody(t *testing.T, snapshot string, sources ...map[string]any) []byte {
	t.Helper()
	if len(sources) == 0 {
		at := e.clk.Now().Add(-time.Hour)
		sources = []map[string]any{source("debian-tracker", at), source("dsa", at), source("kev", at), source("osv", at)}
	}
	return mustJSON(t, map[string]any{"inventory_snapshot_id": snapshot, "matcher_version": "1.4.0", "sources": sources})
}

// start starts a run on the current snapshot and returns its ID.
func (e *venv) start(t *testing.T) string {
	t.Helper()
	r := e.do(t, "POST", "/api/v1/vuln/runs", vulnTok, e.startBody(t, e.inv.current))
	if r.code != http.StatusCreated {
		t.Fatalf("start: %d %s", r.code, r.body)
	}
	return r.json(t)["run_id"].(string)
}

type recOpt func(map[string]any)

// record is a valid Debian record for host web01's openssl.
func record(cve string, opts ...recOpt) map[string]any {
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
		"assessment": map[string]any{"text": "HERMES-ASSESSMENT-TEXT"},
	}
	for _, o := range opts {
		o(r)
	}
	return r
}

func onSubject(kind, id, digest string) recOpt {
	return func(r map[string]any) {
		r["subject_kind"] = kind
		ref := map[string]any{"id": id}
		if digest != "" {
			ref["image_digest"] = digest
		}
		r["subject_ref"] = ref
	}
}

func withComponent(src, ver string) recOpt {
	return func(r map[string]any) {
		r["component"] = map[string]any{"source_package": src, "source_version": ver}
	}
}

// osvRecord makes the record an OSV-range match in ecosystem eco (no
// Debian tracker state).
func osvRecord(eco string) recOpt {
	return func(r map[string]any) {
		r["ecosystem"], r["match_basis"] = eco, "osv_range"
		delete(r, "tracker_state")
	}
}

func withFixed(ver string) recOpt {
	return func(r map[string]any) { r["fix"] = map[string]any{"state": "fixed", "version": ver} }
}

type subj struct {
	kind, id, digest string
	part             int
	last             bool
}

func batchBody(t *testing.T, seq int64, subjects []subj, records ...map[string]any) []byte {
	t.Helper()
	subs := []any{}
	for _, s := range subjects {
		ref := map[string]any{"id": s.id}
		if s.digest != "" {
			ref["image_digest"] = s.digest
		}
		subs = append(subs, map[string]any{"subject_kind": s.kind, "subject_ref": ref, "part": s.part, "last_part": s.last})
	}
	recs := []any{}
	for _, r := range records {
		recs = append(recs, r)
	}
	return mustJSON(t, map[string]any{"batch_seq": seq, "subjects": subs, "findings": recs})
}

func web01(part int, last bool) subj { return subj{kind: "host", id: "web01", part: part, last: last} }

func (e *venv) batch(t *testing.T, run string, body []byte) resp {
	t.Helper()
	return e.do(t, "POST", "/api/v1/vuln/runs/"+run+"/findings", vulnTok, body)
}

func (e *venv) complete(t *testing.T, run string) resp {
	t.Helper()
	return e.do(t, "POST", "/api/v1/vuln/runs/"+run+"/complete", vulnTok, nil)
}

func completion(t *testing.T, r resp) map[string]any {
	t.Helper()
	if r.code != http.StatusOK {
		t.Fatalf("complete: %d %s", r.code, r.body)
	}
	return r.json(t)["completion"].(map[string]any)
}

// --- scopes and token ---

func TestVulnScopesAreExclusiveToTheAgentToken(t *testing.T) {
	e := newVulnEnv(t)
	run := e.start(t)
	for name, tc := range map[string]struct {
		method, path, tok string
		code              int
	}{
		"no token":                 {"GET", "/api/v1/vuln/inventory", "", http.StatusUnauthorized},
		"read-only api token":      {"GET", "/api/v1/vuln/inventory", invTok, http.StatusUnauthorized},
		"read-only token writes":   {"POST", "/api/v1/vuln/runs", invTok, http.StatusUnauthorized},
		"agent token export":       {"GET", "/api/v1/vuln/inventory", vulnTok, http.StatusOK},
		"agent token wrong method": {"DELETE", "/api/v1/vuln/runs/" + run + "/findings", vulnTok, http.StatusMethodNotAllowed},
		"unknown endpoint":         {"GET", "/api/v1/vuln/findings", vulnTok, http.StatusNotFound},
		"bad run id":               {"POST", "/api/v1/vuln/runs/../complete", vulnTok, http.StatusNotFound},
	} {
		t.Run(name, func(t *testing.T) {
			if r := e.do(t, tc.method, tc.path, tc.tok, nil); r.code != tc.code {
				t.Fatalf("%d %s", r.code, r.body)
			}
		})
	}

	// The agent token reads nothing of the read-only API.
	ro := handler(t)
	all := api.Mount(ro, e.h)
	for _, path := range []string{"/api/v1/hosts", "/api/v1/operations", "/api/v1/operations/" + opID} {
		req := httptest.NewRequest("GET", path, nil)
		req.Header.Set("Authorization", "Bearer "+vulnTok)
		rec := httptest.NewRecorder()
		all.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized && rec.Code != http.StatusForbidden {
			t.Fatalf("%s with the agent token: %d %s", path, rec.Code, rec.Body.String())
		}
	}
	// Mount sends the vuln prefix to the vuln handler.
	req := httptest.NewRequest("GET", "/api/v1/vuln/inventory", nil)
	req.RemoteAddr = hermesAddr
	req.Header.Set("Authorization", "Bearer "+vulnTok)
	rec := httptest.NewRecorder()
	all.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("mounted export: %d", rec.Code)
	}
}

func TestVulnTokenScopesAreSeparate(t *testing.T) {
	ro := newVulnEnv(t, vulnToken(serverconfig.ScopeVulnInventoryRead))
	if r := ro.do(t, "POST", "/api/v1/vuln/runs", vulnTok, ro.startBody(t, "inv-1")); r.code != http.StatusForbidden {
		t.Fatalf("read-only agent token started a run: %d %s", r.code, r.body)
	}
	wo := newVulnEnv(t, vulnToken(serverconfig.ScopeVulnFindingsWrite))
	if r := wo.do(t, "GET", "/api/v1/vuln/inventory", vulnTok, nil); r.code != http.StatusForbidden {
		t.Fatalf("write-only agent token read the export: %d %s", r.code, r.body)
	}
}

func TestNewVulnRefusesAVulnTokenWithOtherScopes(t *testing.T) {
	inv := &fakeVulnInventory{}
	for name, toks := range map[string][]serverconfig.APIToken{
		"with operations.read":     {{Name: "hermes-vuln", SHA256: api.HashToken(vulnTok), Scopes: []string{serverconfig.ScopeVulnFindingsWrite, serverconfig.ScopeOperationsRead}}},
		"with execution_logs.read": {{Name: "hermes-vuln", SHA256: api.HashToken(vulnTok), Scopes: []string{serverconfig.ScopeVulnInventoryRead, serverconfig.ScopeExecutionLogsRead}}},
		"two vuln tokens": {vulnToken(), {Name: "second", SHA256: api.HashToken("nos_second"),
			Scopes: []string{serverconfig.ScopeVulnInventoryRead}}},
		"no vuln token": {{Name: "ha", SHA256: api.HashToken(invTok), Scopes: []string{serverconfig.ScopeInventoryRead}}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := api.NewVuln(api.VulnOptions{Tokens: toks, Inventory: inv, Store: &vulnstore.Store{}, Sources: vulnSources}); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestVulnTokenOnlyFromItsSourceAddress(t *testing.T) {
	e := newVulnEnv(t)
	for remote, code := range map[string]int{
		hermesAddr:                 http.StatusOK,
		"[::ffff:192.0.2.10]:4000": http.StatusOK,
		"198.51.100.7:4000":        http.StatusForbidden,
		"[2001:db8::1]:4000":       http.StatusForbidden,
		"garbage":                  http.StatusForbidden,
	} {
		if r := e.doFrom(t, "GET", "/api/v1/vuln/inventory", vulnTok, nil, remote); r.code != code {
			t.Errorf("%s: %d %s", remote, r.code, r.body)
		}
	}
	// Forwarding headers do not count.
	req := httptest.NewRequest("GET", "/api/v1/vuln/inventory", nil)
	req.RemoteAddr = "198.51.100.7:4000"
	req.Header.Set("X-Forwarded-For", "192.0.2.10")
	req.Header.Set("X-Real-IP", "192.0.2.10")
	req.Header.Set("Authorization", "Bearer "+vulnTok)
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("forwarded: %d", rec.Code)
	}
}

// --- rate limits ---

func TestVulnExportRateLimit(t *testing.T) {
	e := newVulnEnv(t)
	for i := 0; i < api.MaxExportRequests; i++ {
		if r := e.do(t, "GET", "/api/v1/vuln/inventory", vulnTok, nil); r.code != http.StatusOK {
			t.Fatalf("request %d: %d", i, r.code)
		}
	}
	r := e.do(t, "GET", "/api/v1/vuln/inventory", vulnTok, nil)
	if r.code != http.StatusTooManyRequests || r.hdr.Get("Retry-After") == "" {
		t.Fatalf("61st export request: %d", r.code)
	}
	// Writes have their own budget.
	e.start(t)
	e.clk.Add(api.ExportWindow)
	if r := e.do(t, "GET", "/api/v1/vuln/inventory", vulnTok, nil); r.code != http.StatusOK {
		t.Fatalf("after the window: %d", r.code)
	}
}

func TestVulnWriteRateLimit(t *testing.T) {
	e := newVulnEnv(t)
	run := e.start(t)
	for i := 1; i < api.MaxWriteRequests; i++ {
		if r := e.batch(t, run, batchBody(t, int64(i), nil)); r.code != http.StatusOK {
			t.Fatalf("batch %d: %d %s", i, r.code, r.body)
		}
	}
	if r := e.batch(t, run, batchBody(t, 999, nil)); r.code != http.StatusTooManyRequests {
		t.Fatalf("61st write: %d", r.code)
	}
	e.clk.Add(api.WriteWindow)
	if r := e.batch(t, run, batchBody(t, 999, nil)); r.code != http.StatusOK {
		t.Fatalf("after the window: %d %s", r.code, r.body)
	}
}

// --- export ---

// allowedExportKeys is every key the export may contain.
var allowedExportKeys = map[string]bool{
	"format": true, "snapshot_id": true, "generation": true, "taken_at": true, "page": true, "pages": true, "subjects": true, "next_cursor": true,
	"subject_kind": true, "subject_ref": true, "id": true, "image_digest": true, "ecosystem": true, "running_kernel": true, "release": true,
	"mapped": true, "source_package": true, "source_version": true, "complete": true, "part": true, "last_part": true, "components": true,
	"binaries": true, "name": true, "version": true, "arch": true,
	"device": true, "vendor": true, "model": true, "firmware_version": true,
}

func walkKeys(t *testing.T, v any) {
	t.Helper()
	switch x := v.(type) {
	case map[string]any:
		for k, c := range x {
			if !allowedExportKeys[k] {
				t.Errorf("export carries key %q", k)
			}
			walkKeys(t, c)
		}
	case []any:
		for _, c := range x {
			walkKeys(t, c)
		}
	}
}

func TestVulnExportCarriesNoAddressesNamesOrSecrets(t *testing.T) {
	e := newVulnEnv(t)
	s := baseSnapshot("inv-2", 8, vt0.Add(-time.Hour))
	s.Subjects = append(s.Subjects,
		// An ID that is an address is left out.
		api.VulnSubject{Kind: vulnfinding.SubjectHost, Ref: vulnfinding.SubjectRef{ID: "10.0.0.5"}, Complete: true},
		// A device is exported with its model and firmware only (ADR 0011 D3).
		api.VulnSubject{Kind: vulnfinding.SubjectDevice, Ref: vulnfinding.SubjectRef{ID: "fw01"}, Complete: true,
			Device: &api.VulnDevice{Vendor: "paloalto", Model: "PA-220", FirmwareVersion: "10.2.3-h1", Current: true}},
		// Free text in a package field is left out and the subject is not
		// complete any more.
		api.VulnSubject{Kind: vulnfinding.SubjectHost, Ref: vulnfinding.SubjectRef{ID: "app01"}, Ecosystem: "debian:bookworm", Complete: true,
			Components: []api.VulnComponent{comp("openssl", "3.0.15-1"), {Source: "pkg", SourceVersion: "1.0 PASSWORD=hunter2"},
				{Source: "x y", SourceVersion: "1"}}},
	)
	e.inv.set(s)
	r := e.do(t, "GET", "/api/v1/vuln/inventory", vulnTok, nil)
	if r.code != http.StatusOK {
		t.Fatalf("%d %s", r.code, r.body)
	}
	for _, bad := range []string{"10.0.0.5", "hunter2", "PASSWORD", "x y"} {
		if strings.Contains(r.body, bad) {
			t.Errorf("export contains %q", bad)
		}
	}
	v := r.json(t)
	walkKeys(t, v)
	if v["format"] != api.VulnInventoryFormat || v["snapshot_id"] != "inv-2" || v["generation"] != 8.0 {
		t.Fatalf("envelope %v", v)
	}
	subs := v["subjects"].([]any)
	if len(subs) != 5 {
		t.Fatalf("%d subjects: %s", len(subs), r.body)
	}
	byID := map[string]map[string]any{}
	for _, x := range subs {
		m := x.(map[string]any)
		ref := m["subject_ref"].(map[string]any)
		byID[m["subject_kind"].(string)+"/"+ref["id"].(string)] = m
	}
	if fw := byID["device/fw01"]; fw["complete"] != true || fw["device"].(map[string]any)["model"] != "PA-220" {
		t.Fatalf("fw01 %v", fw)
	}
	if app := byID["host/app01"]; app["complete"] != false || len(app["components"].([]any)) != 1 {
		t.Fatalf("app01 %v", app)
	}
	if db := byID["host/db01"]; db["complete"] != false || db["running_kernel"].(map[string]any)["mapped"] != false {
		t.Fatalf("db01 %v", db)
	}
	if web := byID["host/web01"]; web["complete"] != true || web["running_kernel"].(map[string]any)["source_version"] != "6.1.119-1" {
		t.Fatalf("web01 %v", web)
	}
	if strings.Contains(e.log.String(), "hunter2") {
		t.Fatal("audit log carries inventory text")
	}
}

func bigComponent(i int) api.VulnComponent {
	c := api.VulnComponent{Source: fmt.Sprintf("pkg%05d", i), SourceVersion: "1.0-1"}
	for j := 0; j < 256; j++ {
		c.Binaries = append(c.Binaries, api.VulnBinary{Name: fmt.Sprintf("pkg%05d-binary-package-%03d", i, j), Version: "1.0-1+b1", Arch: "amd64"})
	}
	return c
}

func TestVulnExportSplitsASubjectAcrossPages(t *testing.T) {
	e := newVulnEnv(t)
	s := api.VulnSnapshot{ID: "inv-big", Generation: 9, TakenAt: vt0.Add(-time.Hour)}
	big := api.VulnSubject{Kind: vulnfinding.SubjectHost, Ref: vulnfinding.SubjectRef{ID: "big01"}, Ecosystem: "debian:bookworm", Complete: true}
	for i := 0; i < 600; i++ {
		big.Components = append(big.Components, bigComponent(i))
	}
	s.Subjects = append(s.Subjects, api.VulnSubject{Kind: vulnfinding.SubjectHost, Ref: vulnfinding.SubjectRef{ID: "first"}, Complete: true,
		Components: []api.VulnComponent{comp("bash", "5.2.15-2")}}, big)
	e.inv.set(s)

	seen := map[string]bool{}
	parts := []float64{}
	cursor, pages := "", 0
	for {
		path := "/api/v1/vuln/inventory"
		if cursor != "" {
			path += "?cursor=" + cursor
		}
		r := e.do(t, "GET", path, vulnTok, nil)
		if r.code != http.StatusOK {
			t.Fatalf("%d %s", r.code, r.body[:min(len(r.body), 200)])
		}
		if len(r.body) > api.MaxExportBytes {
			t.Fatalf("page of %d bytes", len(r.body))
		}
		pages++
		v := r.json(t)
		for _, x := range v["subjects"].([]any) {
			m := x.(map[string]any)
			if m["subject_ref"].(map[string]any)["id"] != "big01" {
				continue
			}
			parts = append(parts, m["part"].(float64))
			last := m["last_part"].(bool)
			for _, c := range m["components"].([]any) {
				name := c.(map[string]any)["source_package"].(string)
				if seen[name] {
					t.Fatalf("component %s twice", name)
				}
				seen[name] = true
			}
			if last != (len(seen) == 600) {
				t.Fatalf("last_part %v after %d components", last, len(seen))
			}
		}
		next, _ := v["next_cursor"].(string)
		if next == "" {
			break
		}
		cursor = next
	}
	if len(seen) != 600 || len(parts) < 3 || pages != len(parts) {
		t.Fatalf("%d components in parts %v over %d pages", len(seen), parts, pages)
	}
	for i, p := range parts {
		if p != float64(i+1) {
			t.Fatalf("parts out of order: %v", parts)
		}
	}
}

func TestVulnExportPageHoldsAtMost1000Subjects(t *testing.T) {
	e := newVulnEnv(t)
	s := api.VulnSnapshot{ID: "inv-many", Generation: 9, TakenAt: vt0.Add(-time.Hour)}
	for i := 0; i < api.MaxSubjectsPerPage+5; i++ {
		s.Subjects = append(s.Subjects, api.VulnSubject{Kind: vulnfinding.SubjectHost, Ref: vulnfinding.SubjectRef{ID: fmt.Sprintf("h%04d", i)}, Complete: true})
	}
	e.inv.set(s)
	r := e.do(t, "GET", "/api/v1/vuln/inventory", vulnTok, nil)
	v := r.json(t)
	if n := len(v["subjects"].([]any)); n != api.MaxSubjectsPerPage || v["next_cursor"] == nil {
		t.Fatalf("first page %d subjects", n)
	}
	r = e.do(t, "GET", "/api/v1/vuln/inventory?cursor="+v["next_cursor"].(string), vulnTok, nil)
	if n := len(r.json(t)["subjects"].([]any)); n != 5 {
		t.Fatalf("second page %d subjects", n)
	}
}

func TestVulnExportCursorIsBoundToItsSnapshot(t *testing.T) {
	e := newVulnEnv(t)
	s := api.VulnSnapshot{ID: "inv-a", Generation: 9, TakenAt: vt0.Add(-time.Hour)}
	for i := 0; i < api.MaxSubjectsPerPage+1; i++ {
		s.Subjects = append(s.Subjects, api.VulnSubject{Kind: vulnfinding.SubjectHost, Ref: vulnfinding.SubjectRef{ID: fmt.Sprintf("h%04d", i)}, Complete: true})
	}
	e.inv.set(s)
	cursor := e.do(t, "GET", "/api/v1/vuln/inventory", vulnTok, nil).json(t)["next_cursor"].(string)
	s.ID = "inv-b"
	e.inv.set(s)
	if r := e.do(t, "GET", "/api/v1/vuln/inventory?cursor="+cursor, vulnTok, nil); r.code != http.StatusGone {
		t.Fatalf("stale cursor: %d %s", r.code, r.body)
	}
	for _, q := range []string{"?cursor=", "?cursor=bm9wZQ", "?cursor=%ff", "?page=2", "?cursor=" + strings.Repeat("A", 600)} {
		if r := e.do(t, "GET", "/api/v1/vuln/inventory"+q, vulnTok, nil); r.code != http.StatusBadRequest {
			t.Errorf("%s: %d", q, r.code)
		}
	}
}

// --- run start ---

func TestVulnRunStartReportsSourcesOneByOne(t *testing.T) {
	e := newVulnEnv(t)
	now := e.clk.Now()
	r := e.do(t, "POST", "/api/v1/vuln/runs", vulnTok, e.startBody(t, "inv-1", source("debian-tracker", now.Add(-time.Hour)), source("kev", now.Add(-time.Hour))))
	if r.code != http.StatusCreated {
		t.Fatalf("%d %s", r.code, r.body)
	}
	if run := r.json(t)["run_id"].(string); completion(t, e.complete(t, run)) == nil {
		t.Fatal("no completion")
	}
	e.clk.Add(time.Minute)
	none := map[string]any{"source_id": "dsa", "snapshot_id": "snap-dsa", "integrity": "signed", "date_kind": "none"}
	r = e.do(t, "POST", "/api/v1/vuln/runs", vulnTok, e.startBody(t, "inv-1",
		source("debian-tracker", now.Add(-2*time.Hour)), // behind its mark: regressed
		source("kev", now.Add(time.Hour)),               // in the future: invalid
		none,                                            // undated
		source("ghsa", now.Add(-time.Hour)),             // not on the list: unknown
	))
	if r.code != http.StatusCreated {
		t.Fatalf("start with a regressed source must not be rejected: %d %s", r.code, r.body)
	}
	v := r.json(t)
	got := map[string]string{}
	for _, x := range v["sources"].([]any) {
		m := x.(map[string]any)
		got[m["source_id"].(string)] = m["status"].(string)
	}
	want := map[string]string{"debian-tracker": "regressed", "kev": "invalid", "dsa": "undated"}
	for k, w := range want {
		if got[k] != w {
			t.Errorf("%s: %q, want %q (%v)", k, got[k], w, got)
		}
	}
	if fmt.Sprint(v["unknown_sources"]) != "[ghsa]" || v["unknown_count"] != 1.0 || fmt.Sprint(v["omitted_sources"]) != "[osv]" {
		t.Fatalf("unknown/omitted: %v %v %v", v["unknown_sources"], v["unknown_count"], v["omitted_sources"])
	}
	if !strings.Contains(e.log.String(), `"debian-tracker:regressed"`) || !strings.Contains(e.log.String(), "vuln_run_unknown_sources") {
		t.Fatalf("audit: %s", e.log.String())
	}
}

func TestVulnRunStartRejectsMalformedSourceLists(t *testing.T) {
	e := newVulnEnv(t)
	at := e.clk.Now().Add(-time.Hour)
	long := strings.Repeat("a", 65)
	five := []map[string]any{source("debian-tracker", at), source("dsa", at), source("kev", at), source("osv", at), source("ghsa", at)}
	for name, body := range map[string][]byte{
		"id over 64 bytes":  e.startBody(t, "inv-1", source(long, at)),
		"id upper case":     e.startBody(t, "inv-1", source("KEV", at)),
		"id with slash":     e.startBody(t, "inv-1", source("kev/../x", at)),
		"id twice":          e.startBody(t, "inv-1", source("kev", at), source("kev", at)),
		"more than listed":  e.startBody(t, "inv-1", five...),
		"no sources":        mustJSON(t, map[string]any{"inventory_snapshot_id": "inv-1", "matcher_version": "1", "sources": []any{}}),
		"bad date kind":     e.startBody(t, "inv-1", map[string]any{"source_id": "kev", "snapshot_id": "s", "integrity": "none", "date_kind": "fetched"}),
		"bad content date":  e.startBody(t, "inv-1", map[string]any{"source_id": "kev", "snapshot_id": "s", "integrity": "none", "date_kind": "data", "content_date": "yesterday"}),
		"bad integrity":     e.startBody(t, "inv-1", map[string]any{"source_id": "kev", "snapshot_id": "s", "integrity": "trusted", "date_kind": "none"}),
		"unknown field":     []byte(`{"inventory_snapshot_id":"inv-1","matcher_version":"1","sources":[],"generation":99}`),
		"case variant key":  []byte(`{"Inventory_Snapshot_ID":"inv-1","matcher_version":"1","sources":[]}`),
		"duplicate key":     []byte(`{"inventory_snapshot_id":"inv-1","inventory_snapshot_id":"inv-1","matcher_version":"1","sources":[]}`),
		"invalid utf-8":     []byte("{\"inventory_snapshot_id\":\"inv-1\",\"matcher_version\":\"1\",\"sources\":[{\"source_id\":\"k\xffv\"}]}"),
		"escaped surrogate": []byte(`{"inventory_snapshot_id":"inv-1","matcher_version":"1","sources":[{"source_id":"k\udc00"}]}`),
		"trailing data":     append(e.startBody(t, "inv-1"), []byte(`{}`)...),
	} {
		t.Run(name, func(t *testing.T) {
			if r := e.do(t, "POST", "/api/v1/vuln/runs", vulnTok, body); r.code != http.StatusBadRequest {
				t.Fatalf("%d %s", r.code, r.body)
			}
		})
	}
	// A rejected ID is audited by length and hash only.
	if strings.Contains(e.log.String(), long) || !strings.Contains(e.log.String(), `"id_sha256"`) {
		t.Fatalf("audit: %s", e.log.String())
	}
	if r := e.do(t, "POST", "/api/v1/vuln/runs", vulnTok, bytes.Repeat([]byte(" "), 70<<10)); r.code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversize start: %d", r.code)
	}
}

func TestVulnRunStartUsesNOSSnapshotAndLimits(t *testing.T) {
	e := newVulnEnv(t)
	if r := e.do(t, "POST", "/api/v1/vuln/runs", vulnTok, e.startBody(t, "inv-gone")); r.code != http.StatusConflict {
		t.Fatalf("unknown snapshot: %d %s", r.code, r.body)
	}
	e.start(t)
	e.start(t)
	if r := e.do(t, "POST", "/api/v1/vuln/runs", vulnTok, e.startBody(t, "inv-1")); r.code != http.StatusTooManyRequests {
		t.Fatalf("third concurrent run: %d %s", r.code, r.body)
	}
	e.clk.Add(25 * time.Hour)
	if r := e.do(t, "POST", "/api/v1/vuln/runs", vulnTok, e.startBody(t, "inv-1")); r.code != http.StatusConflict {
		t.Fatalf("inventory older than 24 h: %d %s", r.code, r.body)
	}
	req := httptest.NewRequest("POST", "/api/v1/vuln/runs", bytes.NewReader(e.startBody(t, "inv-1")))
	req.RemoteAddr = hermesAddr
	req.Header.Set("Authorization", "Bearer "+vulnTok)
	req.Header.Set("Content-Type", "text/plain")
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("text/plain: %d", rec.Code)
	}
}

// --- batches ---

func TestVulnBatchesAreIdempotent(t *testing.T) {
	e := newVulnEnv(t)
	run := e.start(t)
	body := batchBody(t, 1, []subj{web01(1, true)}, record("CVE-2024-0001"))
	r := e.batch(t, run, body)
	if r.code != http.StatusOK || r.json(t)["opened"] != 1.0 {
		t.Fatalf("%d %s", r.code, r.body)
	}
	r = e.batch(t, run, body)
	if r.code != http.StatusOK || r.json(t)["duplicate"] != true || r.json(t)["opened"] != 0.0 {
		t.Fatalf("retry: %d %s", r.code, r.body)
	}
	other := batchBody(t, 1, []subj{web01(1, true)}, record("CVE-2024-0002"))
	if r := e.batch(t, run, other); r.code != http.StatusConflict {
		t.Fatalf("same seq, other body: %d %s", r.code, r.body)
	}
	if !strings.Contains(e.log.String(), "vuln_batch_refused") {
		t.Fatal("conflict not audited")
	}
	c := completion(t, e.complete(t, run))
	if c["batch_rejected"] != false {
		t.Fatalf("%v", c)
	}
	// complete is idempotent too.
	r = e.complete(t, run)
	if r.code != http.StatusOK || r.json(t)["repeat"] != true {
		t.Fatalf("repeat complete: %d %s", r.code, r.body)
	}
	if r := e.batch(t, run, batchBody(t, 2, nil)); r.code != http.StatusConflict {
		t.Fatalf("batch after complete: %d", r.code)
	}
	if strings.Contains(e.log.String(), "HERMES-ASSESSMENT-TEXT") {
		t.Fatal("assessment text in the audit log")
	}
}

// Every whole-batch rejection makes the run close nothing (D5 5e).
func TestVulnHostileBatchesAreRejectedWhole(t *testing.T) {
	withKey := record("CVE-2024-0003")
	withKey["finding_key"] = strings.Repeat("ab", 32)
	withState := record("CVE-2024-0003")
	withState["state"] = "fixed"
	signed := record("CVE-2024-0004", withComponent("linux-signed-amd64", "6.1.119+1"))
	meta := record("CVE-2024-0004", withComponent("linux-meta", "6.1.119+1"))
	tooMany := make([]map[string]any, vulnstore.MaxFindingsPerBatch+1)
	for i := range tooMany {
		tooMany[i] = record(fmt.Sprintf("CVE-2024-%04d", i+1000))
	}
	longText := record("CVE-2024-0005")
	longText["assessment"] = map[string]any{"text": strings.Repeat("x", vulnfinding.MaxAssessmentBytes+1)}
	withURL := record("CVE-2024-0006")
	withURL["advisory_url"] = "https://evil.example/"
	for name, tc := range map[string]struct {
		body func(t *testing.T) []byte
		code int
	}{
		"oversize body": {func(t *testing.T) []byte {
			return append([]byte(`{"batch_seq":1,"findings":[`), bytes.Repeat([]byte(" "), api.MaxBatchBytes)...)
		}, http.StatusRequestEntityTooLarge},
		"over 1000 findings":     {func(t *testing.T) []byte { return batchBody(t, 1, nil, tooMany...) }, http.StatusRequestEntityTooLarge},
		"unknown envelope field": {func(t *testing.T) []byte { return []byte(`{"batch_seq":1,"findings":[],"close_all":true}`) }, http.StatusBadRequest},
		"case variant field":     {func(t *testing.T) []byte { return []byte(`{"Batch_Seq":1,"findings":[]}`) }, http.StatusBadRequest},
		"missing batch_seq":      {func(t *testing.T) []byte { return []byte(`{"findings":[]}`) }, http.StatusBadRequest},
		"negative batch_seq":     {func(t *testing.T) []byte { return []byte(`{"batch_seq":-4,"findings":[]}`) }, http.StatusBadRequest},
		"reserved batch_seq":     {func(t *testing.T) []byte { return []byte(`{"batch_seq":4611686018427387904,"findings":[]}`) }, http.StatusBadRequest},
		"not json":               {func(t *testing.T) []byte { return []byte(`batch`) }, http.StatusBadRequest},
		"hermes-supplied key":    {func(t *testing.T) []byte { return batchBody(t, 1, nil, withKey) }, http.StatusUnprocessableEntity},
		"hermes-supplied state":  {func(t *testing.T) []byte { return batchBody(t, 1, nil, withState) }, http.StatusUnprocessableEntity},
		"signed kernel source":   {func(t *testing.T) []byte { return batchBody(t, 1, nil, signed) }, http.StatusUnprocessableEntity},
		"meta kernel source":     {func(t *testing.T) []byte { return batchBody(t, 1, nil, meta) }, http.StatusUnprocessableEntity},
		"assessment over 4 KiB":  {func(t *testing.T) []byte { return batchBody(t, 1, nil, longText) }, http.StatusUnprocessableEntity},
		"url field":              {func(t *testing.T) []byte { return batchBody(t, 1, nil, withURL) }, http.StatusUnprocessableEntity},
		"subject not in snapshot": {func(t *testing.T) []byte {
			return batchBody(t, 1, []subj{{kind: "host", id: "ghost", part: 1, last: true}})
		}, http.StatusUnprocessableEntity},
		"last_part on a wrong part": {func(t *testing.T) []byte {
			return batchBody(t, 1, []subj{web01(1, false)})
		}, http.StatusUnprocessableEntity},
		"part beyond the export": {func(t *testing.T) []byte { return batchBody(t, 1, []subj{web01(2, true)}) }, http.StatusUnprocessableEntity},
	} {
		t.Run(name, func(t *testing.T) {
			e := newVulnEnv(t)
			// Run 1 opens a finding on web01 and covers it.
			r1 := e.start(t)
			if r := e.batch(t, r1, batchBody(t, 0, []subj{web01(1, true)}, record("CVE-2024-0001"))); r.code != http.StatusOK {
				t.Fatalf("%d %s", r.code, r.body)
			}
			completion(t, e.complete(t, r1))
			// Run 2 covers web01 again without the finding, plus one
			// hostile batch: the omission must close nothing.
			r2 := e.start(t)
			if r := e.batch(t, r2, batchBody(t, 0, []subj{web01(1, true)})); r.code != http.StatusOK {
				t.Fatalf("%d %s", r.code, r.body)
			}
			if r := e.batch(t, r2, tc.body(t)); r.code != tc.code {
				t.Fatalf("hostile batch: %d %s", r.code, r.body)
			}
			c := completion(t, e.complete(t, r2))
			if c["batch_rejected"] != true || c["closed_unconfirmed"] != 0.0 {
				t.Fatalf("hostile batch did not block closures: %v", c)
			}
			if !strings.Contains(e.log.String(), "vuln_batch_rejected") || strings.Contains(e.log.String(), "evil.example") {
				t.Fatalf("audit: %s", e.log.String())
			}
		})
	}
}

// V5: NOS re-checks each record against the run's snapshot; a rejected
// record blocks only its own key.
func TestVulnRecordsAreRecheckedAgainstNOSInventory(t *testing.T) {
	kernel := func(src, ver, fixed string) map[string]any {
		return record("CVE-2025-0100", withComponent(src, ver), withFixed(fixed))
	}
	for name, tc := range map[string]struct {
		rec     map[string]any
		reason  string
		checked bool
	}{
		"matching version":      {rec: record("CVE-2025-0001"), checked: true},
		"binNMU-only host":      {rec: record("CVE-2025-0002", withComponent("bash", "5.2.15-2+b7"), withFixed("5.2.15-3")), checked: true},
		"other source version":  {rec: record("CVE-2025-0003", withComponent("openssl", "3.0.14-1~deb12u1")), reason: "source version is not NOS's"},
		"already fixed":         {rec: record("CVE-2025-0004", withFixed("3.0.15-1~deb12u1")), reason: "installed version is not below the fixed version"},
		"not installed":         {rec: record("CVE-2025-0005", withComponent("nginx", "1.22.1-9")), reason: "source package not installed"},
		"other subject":         {rec: record("CVE-2025-0006", onSubject("host", "ghost01", "")), reason: "subject not in the run's inventory snapshot"},
		"other release":         {rec: func() map[string]any { r := record("CVE-2025-0007"); r["ecosystem"] = "debian:trixie"; return r }(), reason: "ecosystem is not the subject's"},
		"running kernel":        {rec: kernel("linux", "6.1.119-1", "6.1.123-1"), checked: true},
		"kernel not running":    {rec: kernel("linux-5.10", "5.10.226-1", "5.10.230-1"), reason: "kernel source is not the running kernel's"},
		"kernel other version":  {rec: kernel("linux", "6.1.115-1", "6.1.123-1"), reason: "source version is not NOS's"},
		"kernel unmapped":       {rec: record("CVE-2025-0101", onSubject("host", "db01", ""), withComponent("linux", "6.1.119-1"), withFixed("6.1.123-1"))},
		"partial read, missing": {rec: record("CVE-2025-0008", onSubject("host", "db01", ""), withComponent("nginx", "1.22.1-9"))},
		"language ecosystem":    {rec: record("CVE-2025-0009", osvRecord("Go"), withComponent("golang.org/x/net", "0.20.0"), withFixed("0.23.0"))},
		"image record": {rec: record("CVE-2025-0010", onSubject("image", "web01", digestA), osvRecord("alpine:3.20"),
			withComponent("musl", "1.2.5-r0"), withFixed("1.2.5-r1")), checked: true},
		"no fix yet, unchanged": {rec: record("CVE-2025-0011", func(r map[string]any) {
			r["fix"], r["tracker_state"] = map[string]any{"state": "no_fix_yet"}, "unfixed"
		}), checked: true},
		"basis source not named": {rec: record("CVE-2025-0012", func(r map[string]any) {
			r["evidence"].(map[string]any)["basis_sources"] = []any{map[string]any{"source_id": "nvd", "snapshot_id": "s", "integrity": "none"}}
		})},
	} {
		t.Run(name, func(t *testing.T) {
			e := newVulnEnv(t)
			run := e.start(t)
			r := e.batch(t, run, batchBody(t, 0, nil, tc.rec))
			if r.code != http.StatusOK {
				t.Fatalf("%d %s", r.code, r.body)
			}
			v := r.json(t)
			rej := v["rejections"].([]any)
			switch {
			case tc.reason != "":
				if len(rej) != 1 || rej[0].(map[string]any)["reason"] != tc.reason || v["opened"] != 0.0 || v["rejected"] != 1.0 {
					t.Fatalf("want rejection %q: %s", tc.reason, r.body)
				}
			case name == "basis source not named":
				// Rejected by the store: the run did not name nvd.
				if v["rejected"] != 1.0 || v["opened"] != 0.0 {
					t.Fatalf("%s", r.body)
				}
			default:
				if len(rej) != 0 || v["opened"] != 1.0 {
					t.Fatalf("want accepted: %s", r.body)
				}
				if checked := v["not_checked_by_nos"] == 0.0; checked != tc.checked {
					t.Fatalf("nos_checked %v, want %v: %s", checked, tc.checked, r.body)
				}
			}
		})
	}
}

// D3: a subject the export split into parts counts as covered only after
// all its parts, in order; a run naming it without all parts is rejected
// at complete.
func TestVulnSubjectSplitAcrossPagesMustBeCompleteAtComplete(t *testing.T) {
	e := newVulnEnv(t)
	s := api.VulnSnapshot{ID: "inv-split", Generation: 9, TakenAt: vt0.Add(-time.Hour)}
	big := api.VulnSubject{Kind: vulnfinding.SubjectHost, Ref: vulnfinding.SubjectRef{ID: "big01"}, Ecosystem: "debian:bookworm", Complete: true}
	for i := 0; i < 400; i++ {
		big.Components = append(big.Components, bigComponent(i))
	}
	s.Subjects = []api.VulnSubject{big}
	e.inv.set(s)
	first := e.do(t, "GET", "/api/v1/vuln/inventory", vulnTok, nil).json(t)
	sub := first["subjects"].([]any)[0].(map[string]any)
	if sub["part"] != 1.0 || sub["last_part"] != false {
		t.Fatalf("subject not split: %v %v", sub["part"], sub["last_part"])
	}
	bigSubj := func(part int, last bool) subj { return subj{kind: "host", id: "big01", part: part, last: last} }

	run := e.start(t)
	if r := e.batch(t, run, batchBody(t, 0, []subj{bigSubj(1, false)})); r.code != http.StatusOK {
		t.Fatalf("%d %s", r.code, r.body)
	}
	r := e.complete(t, run)
	if r.code != http.StatusUnprocessableEntity || r.json(t)["incomplete_count"] != 1.0 || !strings.Contains(r.body, "big01") {
		t.Fatalf("complete with a missing part: %d %s", r.code, r.body)
	}
	r = e.batch(t, run, batchBody(t, 1, []subj{bigSubj(2, true)}))
	if r.code != http.StatusOK || r.json(t)["subjects_covered"] != 1.0 {
		t.Fatalf("last part: %d %s", r.code, r.body)
	}
	completion(t, e.complete(t, run))

	// Parts out of order are a hostile batch.
	run = e.start(t)
	if r := e.batch(t, run, batchBody(t, 0, []subj{bigSubj(2, true)})); r.code != http.StatusUnprocessableEntity {
		t.Fatalf("part 2 first: %d %s", r.code, r.body)
	}
}

// A run cannot cover a subject NOS read only partially, so omissions there
// close nothing; and the store's run guard holds bulk omissions.
func TestVulnRunGuardHoldsBulkClosure(t *testing.T) {
	e := newVulnEnv(t)
	recs := []map[string]any{}
	for i := 0; i < 30; i++ {
		recs = append(recs, record(fmt.Sprintf("CVE-2025-%04d", 2000+i)))
	}
	partial := record("CVE-2025-3000", onSubject("host", "db01", ""))
	r1 := e.start(t)
	r := e.batch(t, r1, batchBody(t, 0, []subj{web01(1, true), {kind: "host", id: "db01", part: 1, last: true}}, append(recs, partial)...))
	if r.code != http.StatusOK || r.json(t)["opened"] != 31.0 || r.json(t)["subjects_not_coverable"] != 1.0 {
		t.Fatalf("%d %s", r.code, r.body)
	}
	completion(t, e.complete(t, r1))

	r2 := e.start(t)
	if r := e.batch(t, r2, batchBody(t, 0, []subj{web01(1, true), {kind: "host", id: "db01", part: 1, last: true}})); r.code != http.StatusOK {
		t.Fatalf("%d %s", r.code, r.body)
	}
	c := completion(t, e.complete(t, r2))
	if c["run_guard"] != true || c["closed_unconfirmed"] != 0.0 {
		t.Fatalf("bulk omission not held: %v", c)
	}
	if held := c["held"].(map[string]any); held["run_guard"] != 30.0 {
		t.Fatalf("held %v", held)
	}
}

// After a restart the handler no longer knows the run's snapshot: the run
// can neither take batches nor complete, and closes nothing.
func TestVulnRunUnknownToTheHandlerClosesNothing(t *testing.T) {
	e := newVulnEnv(t)
	r1 := e.start(t)
	e.batch(t, r1, batchBody(t, 0, []subj{web01(1, true)}, record("CVE-2025-0001")))
	completion(t, e.complete(t, r1))

	h2, err := api.NewVuln(api.VulnOptions{Tokens: []serverconfig.APIToken{vulnToken()}, Inventory: e.inv, Store: e.st, Sources: vulnSources,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Now: e.clk.Now})
	if err != nil {
		t.Fatal(err)
	}
	r2 := e.start(t)
	e.h = h2
	if r := e.batch(t, r2, batchBody(t, 0, []subj{web01(1, true)})); r.code != http.StatusConflict {
		t.Fatalf("batch after restart: %d %s", r.code, r.body)
	}
	if r := e.complete(t, r2); r.code != http.StatusConflict {
		t.Fatalf("complete after restart: %d %s", r.code, r.body)
	}
	if r := e.do(t, "POST", "/api/v1/vuln/runs/"+strings.Repeat("0", 32)+"/complete", vulnTok, nil); r.code != http.StatusConflict {
		t.Fatalf("unknown run: %d", r.code)
	}
	if r := e.do(t, "POST", "/api/v1/vuln/runs/"+r1+"/complete", vulnTok, []byte(`{"close":"all"}`)); r.code != http.StatusBadRequest {
		t.Fatalf("complete with a body: %d", r.code)
	}
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"

	"github.com/nebula-operation-station/nebula-operation-station/internal/auditlog"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executorclient"
	"github.com/nebula-operation-station/nebula-operation-station/internal/notify"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverconfig"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnnotify"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnstore"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/api"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/auth"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
)

const (
	vtToken     = "nos_hermes-vuln-test-token"
	vtHermes    = "192.0.2.10:40000"
	vtAssessTxt = "HERMES-ASSESSMENT-TEXT"
	vtWait      = 10 * time.Second
)

// vtSink records events; while failing it accepts none.
type vtSink struct {
	mu      sync.Mutex
	failing bool
	events  []notify.Event
	ch      chan notify.Event
}

func newVTSink() *vtSink { return &vtSink{ch: make(chan notify.Event, 64)} }

func (s *vtSink) Notify(_ context.Context, e notify.Event) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failing {
		return 0
	}
	s.events = append(s.events, e)
	select {
	case s.ch <- e:
	default:
	}
	return 1
}

func (s *vtSink) setFailing(f bool) { s.mu.Lock(); s.failing = f; s.mu.Unlock() }

// waitKind waits for an event of kind and returns it.
func (s *vtSink) waitKind(t *testing.T, kind string) notify.Event {
	t.Helper()
	deadline := time.After(vtWait)
	for {
		select {
		case e := <-s.ch:
			if e.Kind == kind {
				return e
			}
		case <-deadline:
			t.Fatalf("no %s event reached the sink", kind)
		}
	}
}

type vtClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *vtClock) Now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *vtClock) Add(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

// vtInventory serves one snapshot with host web01.
type vtInventory struct{ at time.Time }

func (i vtInventory) VulnSnapshot(_ context.Context, id string) (api.VulnSnapshot, error) {
	if id != "" && id != "snap-1" {
		return api.VulnSnapshot{}, api.ErrVulnSnapshotGone
	}
	return api.VulnSnapshot{ID: "snap-1", Generation: 1, TakenAt: i.at, Subjects: []api.VulnSubject{
		{Kind: vulnfinding.SubjectHost, Ref: vulnfinding.SubjectRef{ID: "web01"}, Ecosystem: "debian:bookworm", Complete: true,
			Kernel: &api.VulnKernel{Release: "6.1.0-28-amd64", Source: "linux", SourceVersion: "6.1.119-1"},
			Components: []api.VulnComponent{{Source: "openssl", SourceVersion: "3.0.15-1~deb12u1",
				Binaries: []api.VulnBinary{{Name: "openssl", Version: "3.0.15-1~deb12u1", Arch: "amd64"}}}}},
	}}, nil
}

type vtEnv struct {
	db    *sql.DB
	svc   *vulnService
	sink  *vtSink
	clk   *vtClock
	api   http.Handler
	audit *auditlog.Store
}

func newVTEnv(t *testing.T) *vtEnv {
	t.Helper()
	db, err := serverdb.Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	clk := &vtClock{t: time.Now().UTC().Truncate(time.Second)}
	sink := newVTSink()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc, err := newVulnService(db, sink, log, clk.Now)
	if err != nil {
		t.Fatal(err)
	}
	tok := serverconfig.APIToken{Name: serverconfig.DefaultVulnTokenName, SHA256: api.HashToken(vtToken),
		Scopes:          []string{serverconfig.ScopeVulnInventoryRead, serverconfig.ScopeVulnFindingsWrite},
		SourceAddresses: []string{"192.0.2.10"}}
	vh, err := newVulnAPI(serverconfig.APIConfig{Enabled: true, Tokens: []serverconfig.APIToken{tok}}, svc, vtInventory{at: clk.Now().Add(-time.Minute)}, log)
	if err != nil || vh == nil {
		t.Fatalf("newVulnAPI = %v, %v", vh, err)
	}
	// Mounted like run does: the vuln prefix goes to the agent API.
	readOnly := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "read-only api", http.StatusTeapot) })
	return &vtEnv{db: db, svc: svc, sink: sink, clk: clk, api: api.Mount(readOnly, vh), audit: auditlog.New(db, false)}
}

func (e *vtEnv) do(t *testing.T, method, path, tok, remote string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var rd io.Reader = http.NoBody
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		rd = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, rd)
	req.RemoteAddr = remote
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	e.api.ServeHTTP(rec, req)
	return rec
}

func vtRecord(cve string, kev bool) map[string]any {
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
		"assessment": map[string]any{"text": vtAssessTxt},
	}
	if kev {
		r["scores"] = map[string]any{"kev": map[string]any{"date_added": "2026-11-01"}}
	}
	return r
}

// startAndSubmit starts a run over the HTTP agent API and submits one
// batch with the records; it returns the run ID.
func (e *vtEnv) startAndSubmit(t *testing.T, records ...map[string]any) string {
	t.Helper()
	at := e.clk.Now().Add(-time.Hour).Format(time.RFC3339)
	var sources []any
	for _, id := range []string{"debian-tracker", "kev", "osv"} {
		sources = append(sources, map[string]any{"source_id": id, "snapshot_id": "snap-" + id, "integrity": "none", "date_kind": "data", "content_date": at})
	}
	rec := e.do(t, http.MethodPost, "/api/v1/vuln/runs", vtToken, vtHermes,
		map[string]any{"inventory_snapshot_id": "snap-1", "matcher_version": "1.4.0", "sources": sources})
	if rec.Code != http.StatusCreated {
		t.Fatalf("start run: %d %s", rec.Code, rec.Body)
	}
	var started struct {
		RunID string `json:"run_id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &started); err != nil {
		t.Fatal(err)
	}
	recs := make([]any, len(records))
	for i, r := range records {
		recs[i] = r
	}
	rec = e.do(t, http.MethodPost, "/api/v1/vuln/runs/"+started.RunID+"/findings", vtToken, vtHermes,
		map[string]any{"batch_seq": 0, "subjects": []any{}, "findings": recs})
	if rec.Code != http.StatusOK {
		t.Fatalf("submit batch: %d %s", rec.Code, rec.Body)
	}
	return started.RunID
}

func TestVulnAgentAPIKEVFindingReachesNotifySink(t *testing.T) {
	e := newVTEnv(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { e.svc.runEvents(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })

	e.startAndSubmit(t, vtRecord("CVE-2026-0001", true), vtRecord("CVE-2026-0002", false))
	ev := e.sink.waitKind(t, vulnnotify.KindKEVNew)
	if !strings.Contains(ev.Reason, "CVE-2026-0001") || strings.Contains(ev.Reason, vtAssessTxt) {
		t.Fatalf("kev_new reason = %q, want the CVE and no assessment text", ev.Reason)
	}
	e.sink.mu.Lock()
	defer e.sink.mu.Unlock()
	for _, got := range e.sink.events {
		if strings.Contains(got.Reason, "CVE-2026-0002") {
			t.Fatalf("a finding that is neither KEV nor critical notified: %+v", got)
		}
	}
}

func TestVulnAgentAPIMountedBehindTokenScopesAndAllowlist(t *testing.T) {
	e := newVTEnv(t)
	cases := map[string]struct {
		tok, remote string
		want        int
	}{
		"vuln token from hermes":        {vtToken, vtHermes, http.StatusOK},
		"vuln token from other address": {vtToken, "198.51.100.7:40000", http.StatusForbidden},
		"wrong token":                   {"nos_other", vtHermes, http.StatusUnauthorized},
		"no token":                      {"", vtHermes, http.StatusUnauthorized},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if rec := e.do(t, http.MethodGet, "/api/v1/vuln/inventory", c.tok, c.remote, nil); rec.Code != c.want {
				t.Fatalf("GET inventory = %d %s, want %d", rec.Code, rec.Body, c.want)
			}
		})
	}
	// Other API paths still reach the read-only API.
	if rec := e.do(t, http.MethodGet, "/api/v1/hosts", vtToken, vtHermes, nil); rec.Code != http.StatusTeapot {
		t.Fatalf("GET /api/v1/hosts went to %d, want the read-only API", rec.Code)
	}
	// A token holding only the read scope cannot write.
	readOnly := serverconfig.APIToken{Name: serverconfig.DefaultVulnTokenName, SHA256: api.HashToken(vtToken),
		Scopes: []string{serverconfig.ScopeVulnInventoryRead}}
	vh, err := newVulnAPI(serverconfig.APIConfig{Enabled: true, Tokens: []serverconfig.APIToken{readOnly}}, e.svc, vtInventory{at: e.clk.Now()}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/vuln/runs", strings.NewReader("{}"))
	req.RemoteAddr, req.Header = vtHermes, http.Header{"Authorization": {"Bearer " + vtToken}, "Content-Type": {"application/json"}}
	rec := httptest.NewRecorder()
	vh.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("run start with read scope only = %d, want 403", rec.Code)
	}
}

func TestVulnAgentAPINotMountedWithoutVulnToken(t *testing.T) {
	e := newVTEnv(t)
	other := serverconfig.APIToken{Name: "dash", SHA256: api.HashToken("nos_dash"), Scopes: []string{"hosts.read"}}
	vh, err := newVulnAPI(serverconfig.APIConfig{Enabled: true, Tokens: []serverconfig.APIToken{other}}, e.svc, vtInventory{}, slog.Default())
	if err != nil || vh != nil {
		t.Fatalf("newVulnAPI without vuln token = %v, %v; want nil, nil", vh, err)
	}
}

func TestVulnInventorySnapshotIsStableAndExpires(t *testing.T) {
	clk := &vtClock{t: time.Date(2026, 11, 9, 12, 30, 0, 0, time.UTC)}
	inv := vulnInventory{now: clk.Now}
	cur, err := inv.VulnSnapshot(context.Background(), "")
	if err != nil || len(cur.Subjects) != 0 || !cur.TakenAt.Equal(time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)) {
		t.Fatalf("current snapshot = %+v, %v; want empty, taken at the hour", cur, err)
	}
	clk.Add(3 * time.Hour)
	again, err := inv.VulnSnapshot(context.Background(), cur.ID)
	if err != nil || again.ID != cur.ID || again.Generation != cur.Generation || !again.TakenAt.Equal(cur.TakenAt) {
		t.Fatalf("snapshot by ID = %+v, %v; want the same snapshot", again, err)
	}
	now, _ := inv.VulnSnapshot(context.Background(), "")
	if now.Generation <= cur.Generation {
		t.Fatalf("generation %d after %d, want it to rise", now.Generation, cur.Generation)
	}
	clk.Add(vulnstore.MaxInventoryAge)
	for _, id := range []string{cur.ID, "nos-empty-x", "other", vulnSnapshotPrefix + "1"} {
		if _, err := inv.VulnSnapshot(context.Background(), id); !errors.Is(err, api.ErrVulnSnapshotGone) {
			t.Fatalf("snapshot %q: err = %v, want ErrVulnSnapshotGone", id, err)
		}
	}
}

// vtStatus reports an open privileged session.
type vtStatus struct{}

func (vtStatus) GetStatus(context.Context, *pb.GetStatusRequest, ...grpc.CallOption) (*pb.GetStatusResponse, error) {
	return &pb.GetStatusResponse{PrivilegedSessionActive: true, PrivilegedSessionExpiryUnix: time.Now().Add(time.Hour).Unix()}, nil
}

func (e *vtEnv) export(t *testing.T, admin bool, format string) *httptest.ResponseRecorder {
	t.Helper()
	h := vulnExport{v: e.svc, admin: func(context.Context) bool { return admin }, audit: e.audit, log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, vulnExportPath+"?format="+format, nil))
	return rec
}

func (e *vtEnv) exportAudits(t *testing.T) []auditlog.Entry {
	t.Helper()
	es, err := e.audit.List(context.Background(), 0, 10, vulnnotify.AuditKindExport)
	if err != nil {
		t.Fatal(err)
	}
	return es
}

func TestVulnExportRefusedForNonAdmin(t *testing.T) {
	e := newVTEnv(t)
	e.startAndSubmit(t, vtRecord("CVE-2026-0001", true))
	rec := e.export(t, false, "csv")
	if rec.Code != http.StatusForbidden || strings.Contains(rec.Body.String(), "CVE-2026-0001") {
		t.Fatalf("non-admin export = %d %q, want 403 without findings", rec.Code, rec.Body)
	}
	if es := e.exportAudits(t); len(es) != 0 {
		t.Fatalf("refused export wrote %d export audit entries", len(es))
	}
	// The real admin rule: an executor-reported privileged session is
	// not enough outside the session that holds it.
	if vulnAdmin(vtStatus{})(context.Background()) {
		t.Fatal("vulnAdmin granted admin outside the login chain")
	}
	if vulnAdmin(nil)(context.Background()) {
		t.Fatal("vulnAdmin granted admin without an executor")
	}
}

func TestVulnExportIsAuditedAndCarriesNoAssessment(t *testing.T) {
	e := newVTEnv(t)
	e.startAndSubmit(t, vtRecord("CVE-2026-0001", true))
	rec := e.export(t, true, "csv")
	if rec.Code != http.StatusOK {
		t.Fatalf("admin export = %d %s", rec.Code, rec.Body)
	}
	body := rec.Body.String()
	if !strings.HasPrefix(body, "finding_key,") || !strings.Contains(body, "CVE-2026-0001") || strings.Contains(body, vtAssessTxt) {
		t.Fatalf("csv export = %q, want header and finding, no assessment text", body)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/csv") || rec.Header().Get("Content-Disposition") == "" {
		t.Fatalf("csv headers = %v", rec.Header())
	}
	es := e.exportAudits(t)
	if len(es) != 1 || es[0].Attrs["format"] != "csv" || es[0].Attrs["findings"] != "1" {
		t.Fatalf("export audit = %+v, want one csv entry for 1 finding", es)
	}
	rec = e.export(t, true, "json")
	if rec.Code != http.StatusOK || !json.Valid(rec.Body.Bytes()) || strings.Contains(rec.Body.String(), vtAssessTxt) {
		t.Fatalf("json export = %d %q", rec.Code, rec.Body)
	}
	if es := e.exportAudits(t); len(es) != 2 {
		t.Fatalf("after json export %d audit entries, want 2", len(es))
	}
	if rec := e.export(t, true, "xlsx"); rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown format = %d, want 400", rec.Code)
	}
}

func TestVulnSweepAbortsExpiredRun(t *testing.T) {
	e := newVTEnv(t)
	runID := e.startAndSubmit(t, vtRecord("CVE-2026-0001", false))
	e.clk.Add(vulnstore.MaxRunDuration + time.Minute)
	swept := make(chan vulnstore.PruneResult, 1)
	e.svc.swept = func(r vulnstore.PruneResult, err error) {
		if err == nil {
			select {
			case swept <- r:
			default:
			}
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { e.svc.runSweeps(ctx, 10*time.Millisecond); close(done) }()
	defer func() { cancel(); <-done }()
	select {
	case r := <-swept:
		if r.AbortedRuns != 1 {
			t.Fatalf("sweep = %+v, want the expired run aborted", r)
		}
	case <-time.After(vtWait):
		t.Fatal("no sweep ran")
	}
	if _, err := e.svc.store.Complete(context.Background(), runID); !errors.Is(err, vulnstore.ErrRunNotRunning) {
		t.Fatalf("complete after sweep: %v, want ErrRunNotRunning", err)
	}
}

// reasons returns the reasons of the delivered events of kind.
func (s *vtSink) reasons(kind string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for _, e := range s.events {
		if e.Kind == kind {
			out = append(out, e.Reason)
		}
	}
	return out
}

// TestVulnNotifyNeverSeenSourcesRaiseNothing: an install where no run ever
// named a source (vulnerability management unused) gets no feed_stale,
// however often the tick runs.
func TestVulnNotifyNeverSeenSourcesRaiseNothing(t *testing.T) {
	e := newVTEnv(t)
	for range 3 {
		e.svc.notifyTick(context.Background())
		e.clk.Add(30 * 24 * time.Hour)
	}
	if got := e.sink.reasons(vulnnotify.KindFeedStale); len(got) != 0 || e.svc.notifier.Pending() != 0 {
		t.Fatalf("never-seen sources raised %v (pending %d)", got, e.svc.notifier.Pending())
	}
}

func TestVulnNotifyTickRaisesFeedStaleAndShutdownFlushRetries(t *testing.T) {
	e := newVTEnv(t)
	// The run names debian-tracker, kev and osv (dated one hour ago); past
	// their 72 h maximum age those three are stale, the six sources no run
	// named are not yet seen.
	e.startAndSubmit(t, vtRecord("CVE-2026-0001", false))
	e.clk.Add(72 * time.Hour)
	e.sink.setFailing(true)
	e.svc.notifyTick(context.Background())
	if n := e.svc.notifier.Pending(); n != 3 {
		t.Fatalf("%d undelivered feed_stale alerts queued, want 3", n)
	}
	e.sink.setFailing(false)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { e.svc.runNotify(ctx, time.Hour); close(done) }()
	cancel()
	<-done
	got := e.sink.reasons(vulnnotify.KindFeedStale)
	if len(got) != 3 {
		t.Fatalf("feed_stale after the shutdown flush = %v, want debian-tracker, kev and osv", got)
	}
	for _, r := range got {
		if !strings.Contains(r, "since ") || strings.Contains(r, "nvd") {
			t.Fatalf("feed_stale reason = %q", r)
		}
	}
	if n := e.svc.notifier.Pending(); n != 0 {
		t.Fatalf("after the shutdown flush %d alerts still pending", n)
	}
}

// TestVulnNotifyStateSurvivesRestart: a restarted service (same database,
// same state file) does not repeat the feed_stale alerts of episodes still
// running, but alerts a source that turned stale while it was down.
func TestVulnNotifyStateSurvivesRestart(t *testing.T) {
	e := newVTEnv(t)
	e.svc.statePath = filepath.Join(t.TempDir(), vulnNotifyStateFile)
	e.startAndSubmit(t, vtRecord("CVE-2026-0001", false))
	e.clk.Add(72 * time.Hour)
	e.svc.notifyTick(context.Background())
	if got := e.sink.reasons(vulnnotify.KindFeedStale); len(got) != 3 {
		t.Fatalf("first process sent %v, want 3 feed_stale", got)
	}
	if fi, err := os.Stat(e.svc.statePath); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("state file: %v, %v; want mode 0600", fi, err)
	}

	restart := func() (*vulnService, *vtSink) {
		t.Helper()
		sink := newVTSink()
		svc, err := newVulnService(e.db, sink, slog.New(slog.NewTextHandler(io.Discard, nil)), e.clk.Now)
		if err != nil {
			t.Fatal(err)
		}
		svc.statePath = e.svc.statePath
		svc.loadNotifyState(context.Background())
		return svc, sink
	}
	svc, sink := restart()
	svc.notifyTick(context.Background())
	if got := sink.reasons(vulnnotify.KindFeedStale); len(got) != 0 {
		t.Fatalf("restart repeated %v", got)
	}

	// A malformed or oversized state file is ignored: alerts may repeat,
	// nothing fails.
	for _, bad := range [][]byte{[]byte("{not json"), bytes.Repeat([]byte(" "), maxVulnNotifyState+1)} {
		if err := os.WriteFile(e.svc.statePath, bad, 0o600); err != nil {
			t.Fatal(err)
		}
		svc, sink = restart()
		svc.notifyTick(context.Background())
		if got := sink.reasons(vulnnotify.KindFeedStale); len(got) != 3 {
			t.Fatalf("with a bad state file sent %v, want the 3 alerts again", got)
		}
	}
}

func TestVulnExportRefusalIsAudited(t *testing.T) {
	e := newVTEnv(t)
	if rec := e.export(t, false, "json"); rec.Code != http.StatusForbidden {
		t.Fatalf("non-admin export = %d, want 403", rec.Code)
	}
	es, err := e.audit.List(context.Background(), 0, 10, vulnAuditExportRefused)
	if err != nil {
		t.Fatal(err)
	}
	if len(es) != 1 || es[0].Attrs["reason"] != "not_admin" || es[0].Attrs["format"] != "json" {
		t.Fatalf("refused export audit = %+v, want one not_admin entry", es)
	}
}

// vtExecutor is a fake executor served over gRPC: unlocked, and the
// privileged session it opens (and reports) ends at expiry.
type vtExecutor struct {
	pb.UnimplementedExecutorServiceServer
	expiry int64
}

func (x vtExecutor) GetStatus(context.Context, *pb.GetStatusRequest) (*pb.GetStatusResponse, error) {
	return &pb.GetStatusResponse{Unlocked: true, PrivilegedSessionActive: true, PrivilegedSessionExpiryUnix: x.expiry}, nil
}

func (x vtExecutor) CheckCredential(context.Context, *pb.CheckCredentialRequest) (*pb.CheckCredentialResponse, error) {
	return &pb.CheckCredentialResponse{Registered: true}, nil
}

func (x vtExecutor) CompletePrivilegedSession(context.Context, *pb.CompletePrivilegedSessionRequest) (*pb.CompletePrivilegedSessionResponse, error) {
	return &pb.CompletePrivilegedSessionResponse{SessionExpiryUnix: x.expiry}, nil
}

// serveVTExecutor serves a vtExecutor on a Unix socket in a temporary
// directory and returns the socket path.
func serveVTExecutor(t *testing.T) string {
	t.Helper()
	// Short path: Unix socket paths are limited to about 100 bytes.
	dir, err := os.MkdirTemp("", "nos-vx-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "e.sock")
	lis, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer()
	pb.RegisterExecutorServiceServer(srv, vtExecutor{expiry: time.Now().Add(time.Hour).Unix()})
	go srv.Serve(lis) //nolint:errcheck
	t.Cleanup(srv.Stop)
	return sock
}

// TestVulnAdminGrantsTheHolderOfThePrivilegedSession: through the real
// login chain and executor client, vulnAdmin grants the web session that
// opened the executor's privileged session, and refuses another signed-in
// user and the holder before it opened the session.
func TestVulnAdminGrantsTheHolderOfThePrivilegedSession(t *testing.T) {
	u, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	c, err := executorclient.New(context.Background(), executorclient.Options{SocketPath: serveVTExecutor(t), ExecutorUser: u.Username})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	db, err := serverdb.Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	sessions := auth.NewStore(db, nil)
	login, err := auth.New(auth.Options{Executor: c, Sessions: sessions, Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	isAdmin := vulnAdmin(c)
	probe := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isAdmin(r.Context()) {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusForbidden)
	})
	h := login.Wrap(probe)
	alice, _, err := sessions.Create(context.Background(), "cred-alice", "alice")
	if err != nil {
		t.Fatal(err)
	}
	bob, _, err := sessions.Create(context.Background(), "cred-bob", "bob")
	if err != nil {
		t.Fatal(err)
	}
	do := func(method, path, token, body string) int {
		t.Helper()
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: token})
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	if got := do(http.MethodGet, "/probe", alice, ""); got != http.StatusForbidden {
		t.Fatalf("before the privileged session: %d, want 403", got)
	}
	if got := do(http.MethodPost, "/privileged/finish", alice, `{"assertion":{"id":"k"}}`); got != http.StatusOK {
		t.Fatalf("privileged finish: %d", got)
	}
	if got := do(http.MethodGet, "/probe", alice, ""); got != http.StatusNoContent {
		t.Fatalf("holder of the privileged session: %d, want granted (204)", got)
	}
	if got := do(http.MethodGet, "/probe", bob, ""); got != http.StatusForbidden {
		t.Fatalf("other signed-in user: %d, want 403", got)
	}
}

func TestVulnPagesReadTheRealStoreAndRefuseDecisions(t *testing.T) {
	e := newVTEnv(t)
	e.startAndSubmit(t, vtRecord("CVE-2026-0001", true), vtRecord("CVE-2026-0002", false))
	p := vulnPages{v: e.svc, admin: func(context.Context) bool { return false }}
	ctx := context.Background()
	page, err := p.VulnFindings(ctx, ui.VulnQuery{Limit: ui.MaxVulnRows})
	if err != nil || len(page.Rows) != 2 || page.Truncated {
		t.Fatalf("VulnFindings = %d rows (truncated %v), %v; want 2", len(page.Rows), page.Truncated, err)
	}
	if len(page.Subjects) != 1 || page.Subjects[0].Subject.ID != "web01" || !page.Subjects[0].LastComplete.IsZero() {
		t.Fatalf("subjects = %+v, want web01 not assessed", page.Subjects)
	}
	if len(page.Feeds) != len(vulnSources) {
		t.Fatalf("feeds = %d, want the %d listed sources", len(page.Feeds), len(vulnSources))
	}
	one, err := p.VulnFindings(ctx, ui.VulnQuery{VulnID: "CVE-2026-0001", Limit: 1})
	if err != nil || len(one.Rows) != 1 || one.Rows[0].Tier != vulnstore.TierCritical {
		t.Fatalf("by CVE = %+v, %v; want the KEV finding in the critical tier", one.Rows, err)
	}
	d, err := p.VulnFinding(ctx, one.Rows[0].Finding.Key)
	if err != nil || d.Row.Finding.Key != one.Rows[0].Finding.Key {
		t.Fatalf("VulnFinding = %+v, %v", d, err)
	}
	if ok, _ := p.VulnMaintainer(ctx, "alice"); ok {
		t.Fatal("maintainer without the admin rule")
	}
	if _, err := p.BeginVulnDecision(ctx, "alice", ui.VulnDecision{}); !errors.Is(err, errVulnDecisionsUnavailable) {
		t.Fatalf("begin decision err = %v", err)
	}
	if err := p.CommitVulnDecision(ctx, "alice", "c", ui.VulnDecision{}, nil); !errors.Is(err, errVulnDecisionsUnavailable) {
		t.Fatalf("commit decision err = %v", err)
	}
}

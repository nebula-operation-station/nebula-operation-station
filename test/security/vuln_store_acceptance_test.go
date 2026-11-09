// SPDX-License-Identifier: AGPL-3.0-or-later

package security

// Vulnerability store acceptance tests (ADR 0011, VU-16 part 1; rules V5,
// V7, V11 and V12 of docs/implementation/vulnerability-management.md).
//
// Every test drives the real agent API (internal/web/api VulnHandler, served
// over a loopback HTTP server with the hermes-vuln token and its source
// address allowlist) on the real findings store (internal/vulnstore on a
// fresh server.db) and reads the result back from the store. The source
// list and the tier function mirror cmd/nebula-server's wiring. Two parts
// are test doubles because NOS does not store the parsed package inventory
// yet: the inventory snapshot the export and the V5 re-check use, and the
// closure classifier. The production classifier fails closed (every run
// closure is held as classify_failed), which would make every closure
// guard below pass vacuously; the double classifies against an explicit
// NOS package view instead (no view: unconfirmed; installed below the
// episode fixed version: contradicted; at or above: evidenced), so each
// test can see a closure happen and fails if its guard is removed.

import (
	"context"
	"database/sql"
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

	"github.com/nebula-operation-station/nebula-operation-station/internal/notify"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverconfig"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnnotify"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnprio"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnstore"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnver"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/api"
)

// Synthetic test data only: invented token, IDs and digests.
const (
	vulnAgentToken  = "nos_vu16a-acceptance-agent-token"
	vulnDigestHex   = "2222222222222222222222222222222222222222222222222222222222222222"
	vulnImageDigest = "sha256:" + vulnDigestHex
	vulnImageRef    = "registry.example.org/app@" + vulnImageDigest

	opensslInstalled = "3.0.15-1~deb12u1"
	opensslFixed     = "3.0.16-1~deb12u1"
	opensslFixedHigh = "3.0.17-1~deb12u1"
	kevDate          = "2026-10-01"
)

var vulnT0 = time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)

// vulnListedSources mirrors cmd/nebula-server's fixed source list.
var vulnListedSources = []vulnstore.Source{
	{ID: "debian-tracker", MaxAge: 72 * time.Hour},
	{ID: "dsa", MaxAge: 72 * time.Hour},
	{ID: "dla", MaxAge: 72 * time.Hour},
	{ID: "osv", MaxAge: 72 * time.Hour},
	{ID: "nvd", MaxAge: 72 * time.Hour},
	{ID: "kev", MaxAge: 72 * time.Hour},
	{ID: "epss", MaxAge: 72 * time.Hour},
	{ID: "cisco-csaf", MaxAge: 30 * 24 * time.Hour},
	{ID: "paloalto-csaf", MaxAge: 30 * 24 * time.Hour},
}

// vulnTierOf mirrors cmd/nebula-server's vulnTier (vu-prio-v1 with the
// formula's defaults for exposure and criticality).
func vulnTierOf(_ vulnstore.Subject, r vulnfinding.Record) vulnstore.Tier {
	res, err := vulnprio.Compute(vulnprio.Input{Scores: r.Scores})
	if err != nil {
		return vulnstore.TierUnknown
	}
	switch res.Tier {
	case vulnprio.TierLow:
		return vulnstore.TierLow
	case vulnprio.TierMedium:
		return vulnstore.TierMedium
	case vulnprio.TierHigh:
		return vulnstore.TierHigh
	case vulnprio.TierCritical:
		return vulnstore.TierCritical
	}
	return vulnstore.TierUnknown
}

type vulnClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *vulnClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }

func (c *vulnClock) Add(d time.Duration) { c.mu.Lock(); defer c.mu.Unlock(); c.t = c.t.Add(d) }

// viewClassifier classifies a requested closure against an explicit NOS
// package view per subject (see the file comment).
type viewClassifier struct {
	mu   sync.Mutex
	view map[vulnstore.Subject]map[string]string
}

func (c *viewClassifier) set(s vulnstore.Subject, pkgs map[string]string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.view[s] = pkgs
}

func (c *viewClassifier) Classify(_ context.Context, f vulnstore.Finding) (vulnstore.Class, error) {
	c.mu.Lock()
	v, ok := c.view[f.Subject]
	c.mu.Unlock()
	if !ok {
		return vulnstore.ClassUnconfirmed, nil
	}
	installed, present := v[f.Record.Component.SourcePackage]
	if !present || f.EpisodeFixedVersion == "" {
		return vulnstore.ClassUnconfirmed, nil
	}
	sch, err := vulnver.SchemeForEcosystem(f.Record.Ecosystem)
	if err != nil {
		return 0, fmt.Errorf("classify: %w", err)
	}
	affected, err := vulnver.Affected(sch, installed, f.EpisodeFixedVersion)
	if err != nil {
		return 0, fmt.Errorf("classify: %w", err)
	}
	if affected {
		return vulnstore.ClassContradicted, nil
	}
	return vulnstore.ClassEvidenced, nil
}

// vulnInventory serves immutable snapshots of the current subjects; take
// records a new one with a higher generation.
type vulnInventory struct {
	mu       sync.Mutex
	subjects []api.VulnSubject
	snaps    map[string]api.VulnSnapshot
	current  string
	gen      int64
}

func (i *vulnInventory) VulnSnapshot(_ context.Context, id string) (api.VulnSnapshot, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if id == "" {
		id = i.current
	}
	s, ok := i.snaps[id]
	if !ok {
		return api.VulnSnapshot{}, api.ErrVulnSnapshotGone
	}
	return s, nil
}

func (i *vulnInventory) setSubjects(s ...api.VulnSubject) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.subjects = s
}

func (i *vulnInventory) take(now time.Time) string {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.gen++
	id := fmt.Sprintf("inv-%d", i.gen)
	i.snaps[id] = api.VulnSnapshot{ID: id, Generation: i.gen, TakenAt: now, Subjects: append([]api.VulnSubject(nil), i.subjects...)}
	i.current = id
	return id
}

func vulnComp(src, ver string) api.VulnComponent {
	return api.VulnComponent{Source: src, SourceVersion: ver, Binaries: []api.VulnBinary{{Name: src, Version: ver, Arch: "amd64"}}}
}

// hostWeb01 is a Debian 12 host with a complete package read and a mapped
// running kernel.
func hostWeb01() api.VulnSubject {
	return api.VulnSubject{Kind: vulnfinding.SubjectHost, Ref: vulnfinding.SubjectRef{ID: "web01"}, Ecosystem: "debian:bookworm", Complete: true,
		Kernel:     &api.VulnKernel{Release: "6.1.0-28-amd64", Source: "linux", SourceVersion: "6.1.119-1"},
		Components: []api.VulnComponent{vulnComp("openssl", opensslInstalled), vulnComp("bash", "5.2.15-2"), vulnComp("curl", "7.88.1-10+deb12u8")}}
}

// imageOnWeb01 is a Debian 12 image on web01 with the given components and
// read completeness.
func imageOnWeb01(complete bool, comps ...api.VulnComponent) api.VulnSubject {
	return api.VulnSubject{Kind: vulnfinding.SubjectImage, Ref: vulnfinding.SubjectRef{ID: "web01", ImageDigest: vulnImageDigest},
		Ecosystem: "debian:bookworm", Complete: complete, Components: comps}
}

var (
	subjWeb01 = vulnstore.Subject{Kind: vulnfinding.SubjectHost, ID: "web01"}
	subjImage = vulnstore.Subject{Kind: vulnfinding.SubjectImage, ID: "web01", ImageDigest: vulnImageDigest}
)

// vulnSink records every notification the notifier sends.
type vulnSink struct {
	mu     sync.Mutex
	events []notify.Event
}

func (s *vulnSink) Notify(_ context.Context, e notify.Event) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, e)
	return 1
}

func (s *vulnSink) all() []notify.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]notify.Event(nil), s.events...)
}

// notifyingStore is the store behind the agent API with the run-start
// feed events wired as in cmd/nebula-server (vulnAPIStore), delivered
// synchronously.
type notifyingStore struct {
	*vulnstore.Store
	n *vulnnotify.Notifier
}

func (s notifyingStore) StartRun(ctx context.Context, req vulnstore.StartRequest) (vulnstore.Run, error) {
	r, err := s.Store.StartRun(ctx, req)
	if err == nil {
		s.n.Run(ctx, r)
	}
	return r, err
}

type vulnEnv struct {
	t        *testing.T
	srv      *httptest.Server
	db       *sql.DB
	st       *vulnstore.Store
	clk      *vulnClock
	inv      *vulnInventory
	cls      *viewClassifier
	log      *syncBuffer
	sink     *vulnSink
	notifier *vulnnotify.Notifier
	sources  []vulnstore.Source
	batchSeq int64
}

// newVulnEnv starts the agent API on a fresh server.db. sources nil means
// the production source list.
func newVulnEnv(t *testing.T, sources []vulnstore.Source) *vulnEnv {
	t.Helper()
	if sources == nil {
		sources = vulnListedSources
	}
	db, err := serverdb.Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	e := &vulnEnv{t: t, db: db, clk: &vulnClock{t: vulnT0}, cls: &viewClassifier{view: map[vulnstore.Subject]map[string]string{}},
		inv: &vulnInventory{snaps: map[string]api.VulnSnapshot{}}, log: &syncBuffer{}, sink: &vulnSink{}, sources: sources}
	e.inv.setSubjects(hostWeb01(), imageOnWeb01(true, vulnComp("openssl", opensslInstalled)))
	e.st, err = vulnstore.New(db, vulnstore.Config{Sources: sources, Tier: vulnTierOf, Classifier: e.cls, Now: e.clk.Now})
	if err != nil {
		t.Fatal(err)
	}
	ids := make([]string, len(sources))
	for i, s := range sources {
		ids[i] = s.ID
	}
	e.notifier, err = vulnnotify.New(vulnnotify.Config{Sink: e.sink, Sources: ids, Now: e.clk.Now})
	if err != nil {
		t.Fatal(err)
	}
	tokens := []serverconfig.APIToken{{Name: serverconfig.DefaultVulnTokenName, SHA256: api.HashToken(vulnAgentToken),
		Scopes:          []string{serverconfig.ScopeVulnInventoryRead, serverconfig.ScopeVulnFindingsWrite},
		SourceAddresses: []string{"127.0.0.1"}}}
	h, err := api.NewVuln(api.VulnOptions{Tokens: tokens, Inventory: e.inv, Store: notifyingStore{Store: e.st, n: e.notifier},
		Sources: sources, Log: slog.New(slog.NewJSONHandler(e.log, nil)), Now: e.clk.Now})
	if err != nil {
		t.Fatal(err)
	}
	e.srv = httptest.NewServer(api.Mount(http.NotFoundHandler(), h))
	t.Cleanup(e.srv.Close)
	return e
}

func (e *vulnEnv) do(method, path string, body []byte) (int, []byte) {
	e.t.Helper()
	req, err := http.NewRequestWithContext(e.t.Context(), method, e.srv.URL+path, strings.NewReader(string(body)))
	if err != nil {
		e.t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+vulnAgentToken)
	if method != http.MethodGet {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := e.srv.Client().Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		e.t.Fatal(err)
	}
	return resp.StatusCode, b
}

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// srcSpec is one source as a run names it at start.
type srcSpec struct {
	id      string
	at      time.Time
	undated bool
}

func (s srcSpec) json() map[string]any {
	m := map[string]any{"source_id": s.id, "snapshot_id": "snap-" + s.id, "integrity": "none", "date_kind": "data"}
	if s.undated {
		m["date_kind"] = "none"
	} else {
		m["content_date"] = s.at.UTC().Format(time.RFC3339)
	}
	return m
}

// fresh names every listed source an hour before now, except the IDs in
// skip; extra specs are appended.
func (e *vulnEnv) fresh(skip []string, extra ...srcSpec) []srcSpec {
	var out []srcSpec
	at := e.clk.Now().Add(-time.Hour)
outer:
	for _, s := range e.sources {
		for _, k := range skip {
			if k == s.ID {
				continue outer
			}
		}
		out = append(out, srcSpec{id: s.ID, at: at})
	}
	return append(out, extra...)
}

type verdict struct {
	SourceID  string `json:"source_id"`
	Status    string `json:"status"`
	Stale     bool   `json:"stale"`
	Probation bool   `json:"probation"`
}

type startResult struct {
	RunID          string    `json:"run_id"`
	RunSeq         int64     `json:"run_seq"`
	Sources        []verdict `json:"sources"`
	UnknownSources []string  `json:"unknown_sources"`
	UnknownCount   int       `json:"unknown_count"`
}

func (r startResult) verdict(id string) verdict {
	for _, v := range r.Sources {
		if v.SourceID == id {
			return v
		}
	}
	return verdict{}
}

// start takes a new inventory snapshot and starts a run naming specs.
func (e *vulnEnv) start(specs []srcSpec) startResult {
	e.t.Helper()
	var srcs []map[string]any
	for _, s := range specs {
		srcs = append(srcs, s.json())
	}
	snap := e.inv.take(e.clk.Now())
	code, body := e.do(http.MethodPost, "/api/v1/vuln/runs", mustMarshal(e.t, map[string]any{
		"inventory_snapshot_id": snap, "matcher_version": "1.4.0", "sources": srcs}))
	if code != http.StatusCreated {
		e.t.Fatalf("run start: %d %s", code, body)
	}
	var r startResult
	if err := json.Unmarshal(body, &r); err != nil {
		e.t.Fatal(err)
	}
	return r
}

type batchResult struct {
	Opened          int `json:"opened"`
	Updated         int `json:"updated"`
	Rejected        int `json:"rejected"`
	ClosureRequests int `json:"closure_requests"`
	Ignored         int `json:"ignored_changes"`
	Covered         int `json:"subjects_covered"`
	NotCoverable    int `json:"subjects_not_coverable"`
}

// batch posts one batch that names every subject in cover as complete
// (part 1 of 1) and carries recs.
func (e *vulnEnv) batch(runID string, cover []vulnstore.Subject, recs ...map[string]any) batchResult {
	e.t.Helper()
	subs := []any{}
	for _, s := range cover {
		ref := map[string]any{"id": s.ID}
		if s.ImageDigest != "" {
			ref["image_digest"] = s.ImageDigest
		}
		subs = append(subs, map[string]any{"subject_kind": s.Kind, "subject_ref": ref, "part": 1, "last_part": true})
	}
	if recs == nil {
		recs = []map[string]any{}
	}
	e.batchSeq++
	code, body := e.do(http.MethodPost, "/api/v1/vuln/runs/"+runID+"/findings", mustMarshal(e.t, map[string]any{
		"batch_seq": e.batchSeq, "subjects": subs, "findings": recs}))
	if code != http.StatusOK {
		e.t.Fatalf("batch: %d %s", code, body)
	}
	var r batchResult
	if err := json.Unmarshal(body, &r); err != nil {
		e.t.Fatal(err)
	}
	if r.Rejected != 0 {
		e.t.Fatalf("batch rejected %d records: %s", r.Rejected, body)
	}
	return r
}

func (e *vulnEnv) complete(runID string) vulnstore.Completion {
	e.t.Helper()
	code, body := e.do(http.MethodPost, "/api/v1/vuln/runs/"+runID+"/complete", nil)
	if code != http.StatusOK {
		e.t.Fatalf("complete: %d %s", code, body)
	}
	var r struct {
		Completion *vulnstore.Completion `json:"completion"`
	}
	if err := json.Unmarshal(body, &r); err != nil || r.Completion == nil {
		e.t.Fatalf("complete: %s: %v", body, err)
	}
	return *r.Completion
}

// run is one whole run: start, one batch, complete. The clock moves on
// ten minutes afterwards.
func (e *vulnEnv) run(specs []srcSpec, cover []vulnstore.Subject, recs ...map[string]any) (startResult, batchResult, vulnstore.Completion) {
	e.t.Helper()
	s := e.start(specs)
	b := e.batch(s.RunID, cover, recs...)
	c := e.complete(s.RunID)
	e.clk.Add(10 * time.Minute)
	return s, b, c
}

// finding reads the finding of cve on subject from the store.
func (e *vulnEnv) finding(cve string, subj vulnstore.Subject) vulnstore.Finding {
	e.t.Helper()
	fs, _, err := e.st.List(e.t.Context(), vulnstore.ListQuery{VulnID: cve, Subject: &subj, Limit: 10})
	if err != nil {
		e.t.Fatal(err)
	}
	if len(fs) != 1 {
		e.t.Fatalf("%s on %s: %d findings", cve, subj, len(fs))
	}
	return fs[0]
}

func (e *vulnEnv) wantOpen(subj vulnstore.Subject, cves ...string) {
	e.t.Helper()
	for _, c := range cves {
		if f := e.finding(c, subj); f.State != vulnstore.StateOpen {
			e.t.Errorf("%s: state %s (closed by %s), want open", c, f.State, f.ClosedBy)
		}
	}
}

func (e *vulnEnv) wantClosedUnconfirmed(subj vulnstore.Subject, cves ...string) {
	e.t.Helper()
	for _, c := range cves {
		if f := e.finding(c, subj); f.State != vulnstore.StateFixed || f.ClosedBy != vulnstore.ClosedByHermesUnconfirmed {
			e.t.Errorf("%s: state %s closed by %q, want fixed by hermes_unconfirmed", c, f.State, f.ClosedBy)
		}
	}
}

// markDate returns the high-water mark content date of a listed source.
func (e *vulnEnv) markDate(id string) time.Time {
	e.t.Helper()
	st, err := e.st.FeedStatuses(e.t.Context())
	if err != nil {
		e.t.Fatal(err)
	}
	for _, s := range st {
		if s.SourceID == id {
			return s.ContentDate
		}
	}
	e.t.Fatalf("source %s not listed", id)
	return time.Time{}
}

// --- records ---

type recOpt func(map[string]any)

// vulnRecord is a valid Debian record for web01's openssl (installed
// opensslInstalled, fixed in opensslFixed) resting on debian-tracker.
func vulnRecord(cve string, opts ...recOpt) map[string]any {
	r := map[string]any{
		"subject_kind":  "host",
		"subject_ref":   map[string]any{"id": "web01"},
		"ecosystem":     "debian:bookworm",
		"component":     map[string]any{"source_package": "openssl", "source_version": opensslInstalled},
		"vuln":          map[string]any{"id": cve},
		"fix":           map[string]any{"state": "fixed", "version": opensslFixed},
		"tracker_state": "fixed",
		"match_basis":   "distro_tracker",
		"scores":        map[string]any{},
		"evidence": map[string]any{"matcher_version": "1.4.0",
			"basis_sources": []any{map[string]any{"source_id": "debian-tracker", "snapshot_id": "snap-debian-tracker", "integrity": "none"}}},
		"assessment": map[string]any{"text": "assessment of " + cve},
	}
	for _, o := range opts {
		o(r)
	}
	return r
}

func basis(ids ...string) recOpt {
	return func(r map[string]any) {
		var bs []any
		for _, id := range ids {
			bs = append(bs, map[string]any{"source_id": id, "snapshot_id": "snap-" + id, "integrity": "none"})
		}
		r["evidence"].(map[string]any)["basis_sources"] = bs
	}
}

func withKEV() recOpt {
	return func(r map[string]any) { r["scores"].(map[string]any)["kev"] = map[string]any{"date_added": kevDate} }
}

func withCVSS(score float64) recOpt {
	return func(r map[string]any) {
		r["scores"].(map[string]any)["cvss"] = map[string]any{"version": "3.1", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			"base_score": score, "source": "nvd"}
	}
}

func fixedIn(v string) recOpt {
	return func(r map[string]any) { r["fix"] = map[string]any{"state": "fixed", "version": v} }
}

func notAffected() recOpt {
	return func(r map[string]any) {
		r["fix"] = map[string]any{"state": "not_affected"}
		r["tracker_state"] = "<not-affected>"
	}
}

func withText(s string) recOpt {
	return func(r map[string]any) { r["assessment"] = map[string]any{"text": s} }
}

func onImage() recOpt {
	return func(r map[string]any) {
		r["subject_kind"] = "image"
		r["subject_ref"] = map[string]any{"id": "web01", "image_digest": vulnImageDigest}
	}
}

func cveN(n int) string { return fmt.Sprintf("CVE-2026-%d", 10000+n) }

// vulnRecords returns plain records for cveN(from) .. cveN(to-1).
func vulnRecords(from, to int, opts ...recOpt) ([]map[string]any, []string) {
	var recs []map[string]any
	var cves []string
	for i := from; i < to; i++ {
		recs = append(recs, vulnRecord(cveN(i), opts...))
		cves = append(cves, cveN(i))
	}
	return recs, cves
}

func host() []vulnstore.Subject { return []vulnstore.Subject{subjWeb01} }

// --- closure guards (V11) ---

// The run guard: a run that would close more than half of a subject's
// findings open at its start (at least 10 per subject, 20 in total) has
// every unevidenced closure held, so none of them is applied.
func TestVulnBulkClosureRunGuardHoldsTheRun(t *testing.T) {
	e := newVulnEnv(t, nil)
	recs, cves := vulnRecords(0, 40)
	if _, b, _ := e.run(e.fresh(nil), host(), recs...); b.Opened != 40 {
		t.Fatalf("run 1 opened %d", b.Opened)
	}
	_, _, c := e.run(e.fresh(nil), host(), recs[21:]...)
	if !c.RunGuard || c.Held[vulnstore.HoldRunGuard] != 21 || c.ClosedUnconfirmed != 0 {
		t.Fatalf("run omitting 21 of 40: %+v", c)
	}
	e.wantOpen(subjWeb01, cves...)

	// Control: below the guard the same omission closes.
	_, _, c = e.run(e.fresh(nil), host(), recs[5:]...)
	if c.RunGuard || c.WindowGuard || c.ClosedUnconfirmed != 5 {
		t.Fatalf("run omitting 5 of 40: %+v", c)
	}
	e.wantClosedUnconfirmed(subjWeb01, cves[:5]...)
	e.wantOpen(subjWeb01, cves[5:]...)
}

// The 24 h window guard: two runs that close 40 % each of the findings
// open at the window start trip it on the second run, although neither
// trips the run guard (the first run opened 40 new findings, which count
// for the run guard's scope but not for the window baseline).
func TestVulnBulkClosureWindowGuardHoldsTheSecondRun(t *testing.T) {
	e := newVulnEnv(t, nil)
	a, aCVEs := vulnRecords(0, 100)
	b, bCVEs := vulnRecords(100, 140)
	e.run(e.fresh(nil), host(), a...)
	e.clk.Add(25 * time.Hour) // the opening run lies before the window

	_, _, c := e.run(e.fresh(nil), host(), append(append([]map[string]any{}, a[40:]...), b...)...)
	if c.RunGuard || c.WindowGuard || c.ClosedUnconfirmed != 40 {
		t.Fatalf("first run closing 40 of 100: %+v", c)
	}
	e.wantClosedUnconfirmed(subjWeb01, aCVEs[:40]...)
	e.clk.Add(time.Hour)

	_, _, c = e.run(e.fresh(nil), host(), append(append([]map[string]any{}, a[80:]...), b...)...)
	if c.RunGuard {
		t.Fatalf("second run tripped the run guard, the test needs the window guard alone: %+v", c)
	}
	if !c.WindowGuard || c.Held[vulnstore.HoldWindowGuard] != 40 || c.ClosedUnconfirmed != 0 {
		t.Fatalf("second run closing 40 more: %+v", c)
	}
	e.wantOpen(subjWeb01, aCVEs[40:]...)
	e.wantOpen(subjWeb01, bCVEs...)
}

// A run that started before a newer one but completes after it closes
// nothing the newer run wrote (run_seq ordering, subject watermark).
func TestVulnStaleRunCompletingLateClosesNothing(t *testing.T) {
	e := newVulnEnv(t, nil)
	recs, cves := vulnRecords(0, 5)
	e.run(e.fresh(nil), host(), recs...)

	old := e.start(e.fresh(nil))
	e.batch(old.RunID, host()) // covers web01 and omits all five
	newer := e.start(e.fresh(nil))
	if newer.RunSeq <= old.RunSeq {
		t.Fatalf("run_seq %d after %d", newer.RunSeq, old.RunSeq)
	}
	e.batch(newer.RunID, host(), recs...)
	if c := e.complete(newer.RunID); c.ClosedUnconfirmed != 0 {
		t.Fatalf("newer run: %+v", c)
	}
	c := e.complete(old.RunID)
	if c.ClosedUnconfirmed != 0 || c.SubjectsBelowWatermark != 1 || len(c.Held) != 0 {
		t.Fatalf("stale run completing late: %+v", c)
	}
	e.wantOpen(subjWeb01, cves...)
}

// not_affected is a closure: reported for every finding of a subject it
// trips the run guard like an omission and closes nothing.
func TestVulnNotAffectedMassClosureIsHeld(t *testing.T) {
	e := newVulnEnv(t, nil)
	recs, cves := vulnRecords(0, 30)
	e.run(e.fresh(nil), host(), recs...)
	na, _ := vulnRecords(0, 30, notAffected())
	_, b, c := e.run(e.fresh(nil), host(), na...)
	if b.ClosureRequests != 30 {
		t.Fatalf("not_affected closure requests %d", b.ClosureRequests)
	}
	if !c.RunGuard || c.Held[vulnstore.HoldRunGuard] != 30 || c.ClosedUnconfirmed != 0 {
		t.Fatalf("mass not_affected: %+v", c)
	}
	e.wantOpen(subjWeb01, cves...)

	// Control: a single not_affected below the guard closes.
	_, _, c = e.run(e.fresh(nil), host(), append(append([]map[string]any{}, recs[1:]...), na[0])...)
	if c.RunGuard || c.ClosedUnconfirmed != 1 {
		t.Fatalf("single not_affected: %+v", c)
	}
	e.wantClosedUnconfirmed(subjWeb01, cves[0])
}

// A single omitted KEV finding, or one NOS's inventory contradicts, is
// held whatever the guards say; an ordinary unconfirmed one closes.
func TestVulnSingleKEVOrContradictedClosureIsHeld(t *testing.T) {
	for name, tc := range map[string]struct {
		open     []recOpt
		report   bool // reported not_affected instead of omitted
		nosView  bool // NOS still sees openssl below the fixed version
		wantHold vulnstore.HoldReason
	}{
		"omitted KEV finding":            {open: []recOpt{withKEV()}, wantHold: vulnstore.HoldKEVOrCritical},
		"not_affected KEV finding":       {open: []recOpt{withKEV()}, report: true, wantHold: vulnstore.HoldKEVOrCritical},
		"omitted contradicted finding":   {nosView: true, wantHold: vulnstore.HoldContradicted},
		"not_affected contradicted":      {report: true, nosView: true, wantHold: vulnstore.HoldContradicted},
		"control: omitted, unconfirmed":  {},
		"control: not_affected, unconf.": {report: true},
	} {
		t.Run(name, func(t *testing.T) {
			e := newVulnEnv(t, nil)
			cve := cveN(1)
			e.run(e.fresh(nil), host(), vulnRecord(cve, tc.open...))
			if tc.nosView {
				e.cls.set(subjWeb01, map[string]string{"openssl": opensslInstalled})
			}
			var recs []map[string]any
			if tc.report {
				recs = append(recs, vulnRecord(cve, append(append([]recOpt{}, tc.open...), notAffected())...))
			}
			_, _, c := e.run(e.fresh(nil), host(), recs...)
			if c.RunGuard || c.WindowGuard {
				t.Fatalf("a single closure tripped a guard: %+v", c)
			}
			if tc.wantHold == "" {
				if c.ClosedUnconfirmed != 1 {
					t.Fatalf("control: %+v", c)
				}
				e.wantClosedUnconfirmed(subjWeb01, cve)
				return
			}
			if c.Held[tc.wantHold] != 1 || c.ClosedUnconfirmed != 0 || c.ClosedEvidenced != 0 {
				t.Fatalf("want held %s: %+v", tc.wantHold, c)
			}
			e.wantOpen(subjWeb01, cve)
		})
	}
}

// The KEV high-water mark: a run that drops the KEV flag and a later run
// that omits the finding still hold the closure.
func TestVulnKEVFlagDroppedThenOmittedIsStillHeld(t *testing.T) {
	e := newVulnEnv(t, nil)
	cve := cveN(1)
	e.run(e.fresh(nil), host(), vulnRecord(cve, withKEV()))
	e.run(e.fresh(nil), host(), vulnRecord(cve))
	f := e.finding(cve, subjWeb01)
	if f.Record.Scores.KEV != nil || !f.EpisodeKEV() {
		t.Fatalf("after the drop: current KEV %v, episode KEV %v; the test needs the drop applied and the mark kept",
			f.Record.Scores.KEV, f.EpisodeKEV())
	}
	_, _, c := e.run(e.fresh(nil), host())
	if c.Held[vulnstore.HoldKEVOrCritical] != 1 || c.ClosedUnconfirmed != 0 {
		t.Fatalf("omitted after KEV drop: %+v", c)
	}
	e.wantOpen(subjWeb01, cve)
}

// --- feed trust (V7, V12) ---

// A finding whose basis source is stale, or which the run does not name,
// is not closed by that run's omission (path 5d); a finding on a fresh
// source in the same run closes, so only the stale or omitted source is
// frozen.
func TestVulnStaleOrOmittedSourceClosesNothing(t *testing.T) {
	for name, stale := range map[string]bool{"stale source": true, "omitted source": false} {
		t.Run(name, func(t *testing.T) {
			e := newVulnEnv(t, nil)
			d := e.clk.Now().Add(-time.Hour)
			onTracker, onOSV := cveN(1), cveN(4)
			e.run(e.fresh(nil), host(), vulnRecord(onTracker), vulnRecord(onOSV, basis("osv")))

			specs := e.fresh([]string{"debian-tracker"})
			if stale {
				// The same snapshot (at its mark, not regressed), past
				// its maximum age of 72 h.
				e.clk.Add(80 * time.Hour)
				specs = e.fresh([]string{"debian-tracker"}, srcSpec{id: "debian-tracker", at: d})
			}
			s, _, c := e.run(specs, host())
			if stale {
				if v := s.verdict("debian-tracker"); v.Status != "accepted" || !v.Stale {
					t.Fatalf("verdict %+v, want accepted and stale", v)
				}
			}
			if c.NotRequested != 1 || len(c.Held) != 0 || c.ClosedUnconfirmed != 1 {
				t.Fatalf("completion %+v", c)
			}
			e.wantOpen(subjWeb01, onTracker)
			e.wantClosedUnconfirmed(subjWeb01, onOSV)
		})
	}
}

// raiseOnlyCase is one way a source is raise-only for a run.
type raiseOnlyCase struct {
	source string
	// prep runs between the opening run and the run under test.
	prep func(e *vulnEnv, d time.Time)
	// spec is how the run under test names the source.
	spec          func(d time.Time) srcSpec
	wantStatus    string // verdict; "unknown" means reported as unknown
	wantProbation bool
	markKept      bool
}

func regressedDSA(d time.Time) srcSpec { return srcSpec{id: "dsa", at: d.Add(-48 * time.Hour)} }

// A source that is not accepted for a run (a replayed older content date,
// also when it comes back after a run that omitted it; an ID not on NOS's
// list; an undated snapshot) or that is on probation after a mark reset is
// raise-only for that run: nothing resting on it closes, a new KEV finding
// on it still opens, and no existing finding's current fixed version, KEV
// flag, CVSS score, tier or text is lowered, also for a record resting on
// it and on a fresh source. A finding on a fresh source in the same run
// closes, so only that source is frozen; a regressed or undated source
// keeps its high-water mark.
func TestVulnRaiseOnlySourceClosesNothingAndLowersNothing(t *testing.T) {
	for name, tc := range map[string]raiseOnlyCase{
		"replayed older content date": {source: "dsa", spec: regressedDSA, wantStatus: "regressed", markKept: true},
		"replayed after an omitting run": {source: "dsa", spec: regressedDSA, wantStatus: "regressed", markKept: true,
			prep: func(e *vulnEnv, _ time.Time) {
				_, _, c := e.run(e.fresh([]string{"dsa"}), host(), vulnRecord(cveN(4), basis("osv")))
				if c.ClosedUnconfirmed != 0 || c.NotRequested != 3 {
					e.t.Fatalf("omitting run: %+v", c)
				}
			}},
		"unknown source ID": {source: "dsa-mirror", spec: func(d time.Time) srcSpec { return srcSpec{id: "dsa-mirror", at: d} },
			wantStatus: "unknown"},
		"undated source": {source: "dsa", spec: func(time.Time) srcSpec { return srcSpec{id: "dsa", undated: true} },
			wantStatus: "undated", markKept: true},
		"on probation after a mark reset": {source: "dsa", wantStatus: "accepted", wantProbation: true,
			prep: func(e *vulnEnv, d time.Time) {
				s, _, _ := e.run(e.fresh([]string{"dsa"}, regressedDSA(d)), nil)
				if _, err := e.st.ResetMark(e.t.Context(), vulnstore.MarkResetRequest{SourceID: "dsa", RunID: s.RunID,
					ContentDate: d.Add(-48 * time.Hour), Admin: "admin", Reason: "feed rebuilt from an older mirror"}); err != nil {
					e.t.Fatalf("admin reset: %v", err)
				}
			},
			// Past the reset value, not past the pre-reset mark d.
			spec: func(d time.Time) srcSpec { return srcSpec{id: "dsa", at: d.Add(-24 * time.Hour)} }},
	} {
		t.Run(name, func(t *testing.T) { testRaiseOnly(t, tc) })
	}
}

func testRaiseOnly(t *testing.T, tc raiseOnlyCase) {
	e := newVulnEnv(t, nil)
	d := e.clk.Now().Add(-time.Hour)
	S := tc.source
	var extra []srcSpec
	skip := []string{S}
	if tc.wantStatus == "unknown" {
		// A run names at most as many sources as the list holds, so the
		// unknown ID takes the place of a listed source no record uses.
		extra = append(extra, srcSpec{id: S, at: d})
		skip = append(skip, "paloalto-csaf")
	}
	omitted, lowered, newKEV, onFresh, mixed := cveN(1), cveN(2), cveN(3), cveN(4), cveN(5)
	high := []recOpt{fixedIn(opensslFixedHigh), withKEV(), withCVSS(9.8), withText("original assessment")}
	low := []recOpt{fixedIn(opensslFixed), withCVSS(2.0), withText("replayed assessment")}
	hi := vulnTierOf(subjWeb01, recordOf(t, vulnRecord(lowered, high...)))
	if lo := vulnTierOf(subjWeb01, recordOf(t, vulnRecord(lowered, low...))); hi <= lo {
		t.Fatalf("fixture: tier %d does not fall to %d", hi, lo)
	}
	e.run(e.fresh(skip[1:], extra...), host(),
		vulnRecord(omitted, basis(S)),
		vulnRecord(lowered, append([]recOpt{basis(S)}, high...)...),
		vulnRecord(onFresh, basis("osv")),
		vulnRecord(mixed, append([]recOpt{basis(S, "nvd")}, high...)...))
	before := map[string]vulnstore.Finding{lowered: e.finding(lowered, subjWeb01), mixed: e.finding(mixed, subjWeb01)}
	if tc.prep != nil {
		tc.prep(e, d)
		e.wantOpen(subjWeb01, omitted, lowered, onFresh, mixed)
	}

	s := e.start(e.fresh(skip, tc.spec(d)))
	if tc.wantStatus == "unknown" {
		if s.UnknownCount != 1 || len(s.UnknownSources) != 1 || s.UnknownSources[0] != S {
			t.Fatalf("unknown sources %v (%d)", s.UnknownSources, s.UnknownCount)
		}
	} else if v := s.verdict(S); v.Status != tc.wantStatus || v.Probation != tc.wantProbation {
		t.Fatalf("verdict %+v, want %s probation %v", v, tc.wantStatus, tc.wantProbation)
	}
	b := e.batch(s.RunID, host(),
		vulnRecord(lowered, append([]recOpt{basis(S)}, low...)...),
		vulnRecord(mixed, append([]recOpt{basis(S, "nvd")}, low...)...),
		vulnRecord(newKEV, basis(S), withKEV()))
	if b.Opened != 1 || b.Ignored < 2 {
		t.Fatalf("batch %+v: want the KEV finding opened and the lowering changes ignored", b)
	}
	c := e.complete(s.RunID)
	if c.ClosedUnconfirmed != 1 {
		t.Fatalf("completion %+v: want only the finding on the fresh source closed", c)
	}
	if tc.wantProbation {
		if c.Held[vulnstore.HoldProbation] != 1 {
			t.Fatalf("completion %+v: want the closure on the probation source held", c)
		}
	} else if c.NotRequested != 1 || len(c.Held) != 0 {
		t.Fatalf("completion %+v: want the closure on the frozen source not requested", c)
	}
	e.wantOpen(subjWeb01, omitted, lowered, mixed, newKEV)
	e.wantClosedUnconfirmed(subjWeb01, onFresh)

	if f := e.finding(newKEV, subjWeb01); f.Record.Scores.KEV == nil || !f.EpisodeKEV() {
		t.Errorf("new KEV finding: KEV %v, episode KEV %v", f.Record.Scores.KEV, f.EpisodeKEV())
	}
	for cve, was := range before {
		f := e.finding(cve, subjWeb01)
		r := f.Record
		if r.Fix.State != vulnfinding.FixFixed || r.Fix.Version != opensslFixedHigh {
			t.Errorf("%s: fix %+v lowered", cve, r.Fix)
		}
		if r.Scores.KEV == nil {
			t.Errorf("%s: KEV flag dropped", cve)
		}
		if r.Scores.CVSS == nil || r.Scores.CVSS.BaseScore != 9.8 {
			t.Errorf("%s: CVSS %+v lowered", cve, r.Scores.CVSS)
		}
		if r.Assessment.Text != "original assessment" {
			t.Errorf("%s: text replaced", cve)
		}
		if got, want := vulnTierOf(f.Subject, r), vulnTierOf(was.Subject, was.Record); got != want {
			t.Errorf("%s: tier %d, was %d", cve, got, want)
		}
		if f.EpisodeFixedVersion != was.EpisodeFixedVersion || f.EpisodeKEVDate != was.EpisodeKEVDate || f.EpisodePeakTier != was.EpisodePeakTier {
			t.Errorf("%s: episode marks changed: %q %q %d, were %q %q %d", cve, f.EpisodeFixedVersion, f.EpisodeKEVDate,
				f.EpisodePeakTier, was.EpisodeFixedVersion, was.EpisodeKEVDate, was.EpisodePeakTier)
		}
	}
	if tc.markKept {
		if got := e.markDate(S); !got.Equal(d) {
			t.Errorf("mark of %s %v, want %v", S, got, d)
		}
	}
	if tc.wantStatus == "unknown" {
		e.wantNoMark(S)
	}
}

// recordOf parses a test record the way the API does.
func recordOf(t *testing.T, r map[string]any) vulnfinding.Record {
	t.Helper()
	f, err := vulnfinding.ParseRecord(mustMarshal(t, r))
	if err != nil {
		t.Fatal(err)
	}
	return f.Record
}

// wantNoMark checks that no high-water mark row exists for id.
func (e *vulnEnv) wantNoMark(id string) {
	e.t.Helper()
	var n int
	if err := e.db.QueryRowContext(e.t.Context(), `SELECT COUNT(*) FROM vuln_source_marks WHERE source_id = ?`, id).Scan(&n); err != nil {
		e.t.Fatal(err)
	}
	if n != 0 {
		e.t.Errorf("source %s has a high-water mark", id)
	}
}

// Rolled-back data relabelled under a new source ID: the new ID is not on
// NOS's list, so it gets no mark, lowers nothing and closes nothing, and
// the real source's mark stays where it was.
func TestVulnRolledBackDataUnderNewSourceIDClosesNothing(t *testing.T) {
	e := newVulnEnv(t, nil)
	d := e.clk.Now().Add(-time.Hour)
	omitted, lowered := cveN(1), cveN(2)
	e.run(e.fresh(nil), host(), vulnRecord(omitted, basis("dsa")),
		vulnRecord(lowered, basis("dsa"), fixedIn(opensslFixedHigh), withText("original assessment")))

	relabelled := srcSpec{id: "dsa-rebuilt", at: d.Add(-30 * 24 * time.Hour)}
	s, b, c := e.run(e.fresh([]string{"dsa"}, relabelled), host(),
		vulnRecord(lowered, basis("dsa-rebuilt"), withText("rolled back")))
	if s.UnknownCount != 1 || s.UnknownSources[0] != "dsa-rebuilt" {
		t.Fatalf("unknown sources %v", s.UnknownSources)
	}
	if b.Ignored < 1 || c.ClosedUnconfirmed != 0 || len(c.Held) != 0 {
		t.Fatalf("relabelled run: batch %+v completion %+v", b, c)
	}
	// A second relabelled run omits both: still nothing closes.
	if _, _, c = e.run(e.fresh([]string{"dsa"}, relabelled), host()); c.ClosedUnconfirmed != 0 || len(c.Held) != 0 {
		t.Fatalf("second relabelled run: %+v", c)
	}
	e.wantOpen(subjWeb01, omitted, lowered)
	if f := e.finding(lowered, subjWeb01); f.Record.Fix.Version != opensslFixedHigh || f.Record.Assessment.Text != "original assessment" {
		t.Errorf("relabelled data lowered the finding: %+v %q", f.Record.Fix, f.Record.Assessment.Text)
	}
	if got := e.markDate("dsa"); !got.Equal(d) {
		t.Errorf("mark of dsa %v, want %v", got, d)
	}
	e.wantNoMark("dsa-rebuilt")
}

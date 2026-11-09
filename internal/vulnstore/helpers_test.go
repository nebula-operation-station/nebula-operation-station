// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnstore

import (
	"context"
	"crypto/sha256"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
)

var t0 = time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)

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

type fakeClassifier struct {
	mu      sync.Mutex
	classes map[vulnfinding.Key]Class
	errs    map[vulnfinding.Key]error
}

func (c *fakeClassifier) Classify(_ context.Context, f Finding) (Class, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.errs[f.Key]; err != nil {
		return 0, err
	}
	if cl, ok := c.classes[f.Key]; ok {
		return cl, nil
	}
	return ClassUnconfirmed, nil
}

func (c *fakeClassifier) set(k vulnfinding.Key, cl Class) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.classes[k] = cl
}

func testTier(_ Subject, r vulnfinding.Record) Tier {
	if r.Scores.KEV != nil {
		return TierCritical
	}
	if r.Scores.CVSS == nil {
		return TierUnknown
	}
	switch s := r.Scores.CVSS.BaseScore; {
	case s >= 9:
		return TierCritical
	case s >= 7:
		return TierHigh
	case s >= 4:
		return TierMedium
	default:
		return TierLow
	}
}

var testSources = []Source{
	{ID: "osv", MaxAge: 72 * time.Hour},
	{ID: "kev", MaxAge: 72 * time.Hour},
	{ID: "nvd", MaxAge: 72 * time.Hour},
	{ID: "debian-tracker", MaxAge: 72 * time.Hour},
	{ID: "dsa", MaxAge: 72 * time.Hour},
	{ID: "cisco-csaf", MaxAge: 30 * 24 * time.Hour},
}

type env struct {
	st  *Store
	clk *clock
	cls *fakeClassifier
	ctx context.Context
}

func newEnv(t *testing.T) *env {
	t.Helper()
	db, err := serverdb.Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	clk := &clock{t: t0}
	cls := &fakeClassifier{classes: map[vulnfinding.Key]Class{}, errs: map[vulnfinding.Key]error{}}
	st, err := New(db, Config{Sources: testSources, Tier: testTier, Classifier: cls, Now: clk.Now})
	if err != nil {
		t.Fatal(err)
	}
	return &env{st: st, clk: clk, cls: cls, ctx: context.Background()}
}

// src is a dated source named by a run, content date one hour ago.
func (e *env) src(id string) RunSource {
	return RunSource{ID: id, SnapshotID: "snap-" + id, Integrity: vulnfinding.IntegrityNone, DateKind: DateKindData, ContentDate: e.clk.Now().Add(-time.Hour)}
}

func (e *env) srcAt(id string, at time.Time) RunSource {
	s := e.src(id)
	s.ContentDate = at
	return s
}

// start starts a run with the given sources (default osv and kev).
func (e *env) start(t *testing.T, sources ...RunSource) Run {
	t.Helper()
	if len(sources) == 0 {
		sources = []RunSource{e.src("osv"), e.src("kev")}
	}
	r, err := e.st.StartRun(e.ctx, StartRequest{TokenID: "hermes-vuln", InventoryGeneration: 7, InventoryAt: e.clk.Now().Add(-time.Hour),
		MatcherVersion: "1.0", Sources: sources})
	if err != nil {
		t.Fatalf("start run: %v", err)
	}
	return r
}

func (e *env) submit(t *testing.T, r Run, seq int64, covered []Subject, items ...Item) BatchResult {
	t.Helper()
	res, err := e.st.SubmitBatch(e.ctx, r.ID, batchOf(seq, covered, items...))
	if err != nil {
		t.Fatalf("submit batch: %v", err)
	}
	return res
}

func batchOf(seq int64, covered []Subject, items ...Item) Batch {
	h := sha256.New()
	fmt.Fprintf(h, "%d", seq)
	for _, it := range items {
		h.Write(it.Finding.Key[:])
		fmt.Fprintf(h, "%+v", it.Finding.Record)
	}
	var sum [32]byte
	h.Sum(sum[:0])
	return Batch{Seq: seq, BodySHA256: sum, Items: items, Covered: covered}
}

func (e *env) complete(t *testing.T, r Run) Completion {
	t.Helper()
	c, err := e.st.Complete(e.ctx, r.ID)
	if err != nil {
		t.Fatalf("complete: %v", err)
	}
	return c
}

func (e *env) get(t *testing.T, k vulnfinding.Key) Finding {
	t.Helper()
	f, err := e.st.Get(e.ctx, k)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	return f
}

func (e *env) wantState(t *testing.T, k vulnfinding.Key, want State, by ClosedBy) {
	t.Helper()
	f := e.get(t, k)
	if f.State != want || f.ClosedBy != by {
		t.Fatalf("state = %s/%s, want %s/%s", f.State, f.ClosedBy, want, by)
	}
}

type opt func(*vulnfinding.Record)

func withSources(ids ...string) opt {
	return func(r *vulnfinding.Record) {
		r.Evidence.BasisSources = nil
		for _, id := range ids {
			r.Evidence.BasisSources = append(r.Evidence.BasisSources, vulnfinding.BasisSource{SourceID: id, SnapshotID: "snap-" + id, Integrity: vulnfinding.IntegrityNone})
		}
	}
}

func withKEV(date string) opt {
	return func(r *vulnfinding.Record) { r.Scores.KEV = &vulnfinding.KEV{DateAdded: date} }
}

func withCVSS(score float64) opt {
	return func(r *vulnfinding.Record) {
		r.Scores.CVSS = &vulnfinding.CVSS{Version: "3.1", Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", BaseScore: score, Source: vulnfinding.CVSSSourceNVD}
	}
}

func withFix(state vulnfinding.FixState, version string) opt {
	return func(r *vulnfinding.Record) { r.Fix = vulnfinding.Fix{State: state, Version: version} }
}

func withText(s string) opt {
	return func(r *vulnfinding.Record) { r.Assessment.Text = s }
}

func withPackage(pkg string) opt {
	return func(r *vulnfinding.Record) { r.Component.SourcePackage = pkg }
}

// item builds a validated Ubuntu host finding on package pkg (default
// "openssl") fixed in 1.0-2, resting on osv, CVSS 5.0.
func item(t *testing.T, hostID, cve string, opts ...opt) Item {
	t.Helper()
	r := vulnfinding.Record{
		SubjectKind: vulnfinding.SubjectHost,
		SubjectRef:  vulnfinding.SubjectRef{ID: hostID},
		Ecosystem:   "ubuntu:24.04",
		Component:   vulnfinding.Component{SourcePackage: "openssl", SourceVersion: "1.0-1"},
		Vuln:        vulnfinding.Vuln{ID: cve},
		Fix:         vulnfinding.Fix{State: vulnfinding.FixFixed, Version: "1.0-2"},
		MatchBasis:  vulnfinding.MatchDistroTracker,
		Evidence:    vulnfinding.Evidence{MatcherVersion: "1.0"},
		Assessment:  vulnfinding.Assessment{Text: "assessment v1"},
	}
	withSources("osv")(&r)
	withCVSS(5.0)(&r)
	for _, o := range opts {
		o(&r)
	}
	f, err := vulnfinding.Validate(r)
	if err != nil {
		t.Fatalf("fixture record invalid: %v", err)
	}
	return Item{Finding: f, NOSChecked: true}
}

func hostSubj(id string) Subject { return Subject{Kind: vulnfinding.SubjectHost, ID: id} }

func cve(i int) string { return fmt.Sprintf("CVE-2026-%04d", 1000+i) }

// seed opens n findings on host via one complete run that covers the host
// and returns their items.
func (e *env) seed(t *testing.T, host string, n int, opts ...opt) []Item {
	t.Helper()
	items := make([]Item, n)
	for i := range items {
		items[i] = item(t, host, cve(i), opts...)
	}
	r := e.start(t)
	e.submit(t, r, 0, []Subject{hostSubj(host)}, items...)
	e.complete(t, r)
	return items
}

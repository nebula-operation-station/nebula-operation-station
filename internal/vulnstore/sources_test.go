// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnstore

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
)

func TestStartRunRejectsMalformedSources(t *testing.T) {
	e := newEnv(t)
	tooMany := make([]RunSource, len(testSources)+1)
	for i := range tooMany {
		tooMany[i] = e.src(fmt.Sprintf("src%d", i))
	}
	cases := map[string][]RunSource{
		"none":            nil,
		"duplicate":       {e.src("osv"), e.src("osv")},
		"more than list":  tooMany,
		"bad pattern":     {e.src("OSV!")},
		"over 64 bytes":   {e.src(strings.Repeat("a", 65))},
		"bad date kind":   {func() RunSource { s := e.src("osv"); s.DateKind = "guess"; return s }()},
		"dated none":      {func() RunSource { s := e.src("osv"); s.DateKind = DateKindNone; return s }()},
		"undated data":    {func() RunSource { s := e.src("osv"); s.ContentDate = time.Time{}; return s }()},
		"bad integrity":   {func() RunSource { s := e.src("osv"); s.Integrity = "pgp"; return s }()},
		"bad snapshot id": {func() RunSource { s := e.src("osv"); s.SnapshotID = "a b"; return s }()},
	}
	for name, srcs := range cases {
		_, err := e.st.StartRun(e.ctx, StartRequest{TokenID: "tok", InventoryGeneration: 1, InventoryAt: e.clk.Now(), MatcherVersion: "1", Sources: srcs})
		if !errors.Is(err, ErrMalformedRun) {
			t.Errorf("%s: %v, want ErrMalformedRun", name, err)
		}
		if err != nil && strings.Contains(err.Error(), "OSV!") {
			t.Errorf("%s: error echoes the rejected ID", name)
		}
	}
	if _, err := e.st.StartRun(e.ctx, StartRequest{TokenID: "tok", InventoryGeneration: 1, InventoryAt: e.clk.Now().Add(-25 * time.Hour),
		MatcherVersion: "1", Sources: []RunSource{e.src("osv")}}); !errors.Is(err, ErrInventoryTooOld) {
		t.Errorf("old inventory: %v", err)
	}
}

func TestSourceVerdictsAndMarks(t *testing.T) {
	e := newEnv(t)
	now := e.clk.Now()
	seq := func(v int64) *int64 { return &v }
	r1 := e.start(t, e.srcAt("osv", now.Add(-time.Hour)), func() RunSource { s := e.src("cisco-csaf"); s.Sequence = seq(5); return s }())
	for _, v := range r1.Sources {
		if v.Status != SourceAccepted || v.Stale {
			t.Fatalf("run 1 verdict %+v", v)
		}
	}
	// Run 2: osv older than its mark (regressed), csaf sequence lower
	// (regressed), kev in the future (invalid), nvd undated.
	r2 := e.start(t,
		e.srcAt("osv", now.Add(-2*time.Hour)),
		func() RunSource { s := e.src("cisco-csaf"); s.Sequence = seq(4); return s }(),
		e.srcAt("kev", now.Add(MaxFutureSkew+time.Minute)),
		RunSource{ID: "nvd", SnapshotID: "s", Integrity: vulnfinding.IntegrityNone, DateKind: DateKindNone})
	want := map[string]SourceStatus{"osv": SourceRegressed, "cisco-csaf": SourceRegressed, "kev": SourceInvalid, "nvd": SourceUndated}
	for _, v := range r2.Sources {
		if want[v.ID] != v.Status || !v.Stale {
			t.Errorf("run 2 %s = %+v, want %s and stale", v.ID, v, want[v.ID])
		}
	}
	e.complete(t, r1)
	e.complete(t, r2)
	// The marks did not move: a run at the old mark is accepted again, and
	// the invalid date was never stored as kev's mark.
	r3 := e.start(t, e.srcAt("osv", now.Add(-time.Hour)), e.srcAt("kev", now.Add(-time.Hour)))
	for _, v := range r3.Sources {
		if v.Status != SourceAccepted {
			t.Errorf("run 3 %s = %s", v.ID, v.Status)
		}
	}
	// Omitting a source does not reset its mark.
	e.complete(t, r3)
	r4 := e.start(t, e.srcAt("kev", now.Add(-time.Hour)))
	e.complete(t, r4)
	r5 := e.start(t, e.srcAt("osv", now.Add(-90*time.Minute)))
	if r5.Sources[0].Status != SourceRegressed {
		t.Fatalf("osv after being omitted = %s, want regressed", r5.Sources[0].Status)
	}
}

func TestUnknownSourceIDs(t *testing.T) {
	e := newEnv(t)
	// The run start may not name more sources than the list holds, so 50
	// unknown IDs arrive over the list size... the check rejects them;
	// within the bound, unknown IDs are reported, at most 16 shown.
	srcs := []RunSource{e.src("osv")}
	for i := 0; i < len(testSources)-1; i++ {
		srcs = append(srcs, e.src(fmt.Sprintf("relabelled-%d", i)))
	}
	r := e.start(t, srcs...)
	if r.UnknownCount != len(testSources)-1 || len(r.UnknownSources) != len(testSources)-1 {
		t.Fatalf("unknown = %d %v", r.UnknownCount, r.UnknownSources)
	}
	// An unknown source gets no mark.
	var n int
	if err := e.st.db.QueryRow(`SELECT COUNT(*) FROM vuln_source_marks WHERE source_id LIKE 'relabelled-%'`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("marks for unknown IDs = %d, %v", n, err)
	}
	// A finding resting on it opens, raise-only, and is never closed by a
	// run closure.
	it := item(t, "web01", cve(0), withSources("relabelled-0"))
	if res := e.submit(t, r, 0, []Subject{hostSubj("web01")}, it); res.Opened != 1 {
		t.Fatalf("result = %+v", res)
	}
	e.complete(t, r)
	r2 := e.start(t, e.src("osv"), e.src("relabelled-0"))
	e.submit(t, r2, 0, []Subject{hostSubj("web01")})
	if c := e.complete(t, r2); c.NotRequested != 1 {
		t.Fatalf("completion = %+v", c)
	}
	e.wantState(t, it.Finding.Key, StateOpen, "")
}

func TestUnknownSourcesShownAtMost16(t *testing.T) {
	db := newEnv(t).st.db
	many := make([]Source, 60)
	for i := range many {
		many[i] = Source{ID: fmt.Sprintf("listed-%d", i), MaxAge: time.Hour}
	}
	clk := &clock{t: t0}
	st, err := New(db, Config{Sources: many, Tier: testTier, Classifier: &fakeClassifier{}, Now: clk.Now})
	if err != nil {
		t.Fatal(err)
	}
	var srcs []RunSource
	for i := 0; i < 50; i++ {
		srcs = append(srcs, RunSource{ID: fmt.Sprintf("unknown-%d", i), SnapshotID: "s", Integrity: vulnfinding.IntegrityNone, DateKind: DateKindData, ContentDate: t0})
	}
	r, err := st.StartRun(t.Context(), StartRequest{TokenID: "tok", InventoryGeneration: 1, InventoryAt: t0, MatcherVersion: "1", Sources: srcs})
	if err != nil {
		t.Fatal(err)
	}
	if r.UnknownCount != 50 || len(r.UnknownSources) != MaxUnknownSourcesShown {
		t.Fatalf("unknown = %d shown %d", r.UnknownCount, len(r.UnknownSources))
	}
}

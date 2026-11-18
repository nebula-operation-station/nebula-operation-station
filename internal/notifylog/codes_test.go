// SPDX-License-Identifier: AGPL-3.0-or-later

package notifylog

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
)

// allKinds lists every event kind the log accepts. It must match the kind
// CHECK in migration 0049 (and 0045 for the older kinds).
var allKinds = []KindCode{
	KindVulnKEVNew, KindVulnCriticalNew, KindVulnHermesStale, KindVulnFeedStale,
	KindVulnFeedRegressed, KindVulnFeedMarkReset,
	KindIntegrityNOSMismatch, KindIntegrityHostChange, KindIntegrityScanIncomplete,
	KindIntegrityBaselineTamper, KindIntegrityReferenceConflict,
	KindLeaseExpiring, KindLeaseRunFailed, KindDigest,
	KindOpsSuggestionNew, KindOpsSettingsChanged,
	KindExecution, KindOpsState, KindHostKeyMismatch, KindTest, KindExecutorLocked,
}

// allStates lists every state code. It must match the state CHECK in
// migration 0049.
var allStates = []StateCode{
	StateNew, StateEscalated, StateExpiring, StateFailed, StateStale,
	StateRegressed, StateMismatch, StateIncomplete, StateTamper, StateChanged,
	StateReset, StateSummary, StateWaiting, StatePartial, StateTest,
	StateLocked, StateConflict, StateOther,
}

// TestEveryKindAndStateCodeIsStored appends one record per kind and per state
// and checks that none is refused and each comes back unchanged.
func TestEveryKindAndStateCodeIsStored(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	for _, k := range allKinds {
		r := sampleRecord()
		r.Kind = k
		seq := mustAppend(t, s, r)
		entries, err := s.List(ctx, 0, 1)
		if err != nil || len(entries) != 1 {
			t.Fatalf("kind %q: list after append: %v (%d entries)", k, err, len(entries))
		}
		if entries[0].Seq != seq || entries[0].Kind != k {
			t.Fatalf("kind %q: stored as seq %d kind %q, want seq %d", k, entries[0].Seq, entries[0].Kind, seq)
		}
	}
	for _, st := range allStates {
		r := sampleRecord()
		r.State = st
		mustAppend(t, s, r)
	}
}

// TestCodeSetsHaveNoStrayValues checks that every constant in the closed sets
// is accepted by the Go side, and that a code outside the set is refused
// before it reaches the database.
func TestCodeSetsHaveNoStrayValues(t *testing.T) {
	for _, k := range allKinds {
		if !k.valid() {
			t.Errorf("kind %q is not valid", k)
		}
	}
	for _, st := range allStates {
		if !st.valid() {
			t.Errorf("state %q is not valid", st)
		}
	}
	s, _ := newTestStore(t)
	r := sampleRecord()
	r.Kind = KindCode("execution ")
	if _, err := s.Append(context.Background(), r); !errors.Is(err, ErrRefused) {
		t.Fatalf("kind with a trailing space: err = %v, want ErrRefused", err)
	}
	r = sampleRecord()
	r.State = StateCode("waiting-ish")
	if _, err := s.Append(context.Background(), r); !errors.Is(err, ErrRefused) {
		t.Fatalf("unknown state: err = %v, want ErrRefused", err)
	}
}

// TestMigrationRebuildKeepsRowsAndSequence opens a database at migration 47
// (before the rebuild), writes rows and prunes the newest one, then migrates
// to the latest version. The rows must survive, and the next sequence number
// must not reuse the pruned one.
func TestMigrationRebuildKeepsRowsAndSequence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nos.db")
	db, err := serverdb.OpenAt(path, 47)
	if err != nil {
		t.Fatalf("OpenAt 47: %v", err)
	}
	clk := &fakeClock{t: time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)}
	old, err := New(db, clk.now)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	mustAppend(t, old, sampleRecord())
	mustAppend(t, old, sampleRecord())
	if _, err := db.ExecContext(ctx, `INSERT INTO notify_log (at, kind, host, state, reason, execution_id, link, outcome, providers, changed)
		VALUES (1, 'lease.run_failed', 'web-1', 'failed', '', '', '', 'sent', 1, 0)`); err != nil {
		t.Fatalf("insert third row: %v", err)
	}
	if _, err := db.ExecContext(ctx, `DELETE FROM notify_log WHERE seq = 3`); err != nil {
		t.Fatalf("prune newest row: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	db, err = serverdb.Open(path)
	if err != nil {
		t.Fatalf("Open (latest): %v", err)
	}
	defer db.Close()
	s, err := New(db, clk.now)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := s.List(ctx, 0, MaxPage)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || entries[0].Seq != 2 || entries[1].Seq != 1 {
		t.Fatalf("rows after rebuild = %+v, want seq 2 and 1", entries)
	}
	seq := mustAppend(t, s, Record{Kind: KindExecution, State: StatePartial, Outcome: OutcomeSent, Providers: 1})
	if seq != 4 {
		t.Fatalf("seq after rebuild = %d, want 4 (3 was pruned before the rebuild and must not be reused)", seq)
	}
}

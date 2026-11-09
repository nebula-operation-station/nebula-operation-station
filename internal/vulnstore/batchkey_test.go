// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnstore

import (
	"errors"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
)

func TestBatchKeyNotMatchingRecordIsRefused(t *testing.T) {
	e := newEnv(t)
	victim := e.seed(t, "web02", 1)[0]
	before := e.get(t, victim.Finding.Key)

	// A record of web01 carrying web02's key: the whole batch is refused
	// and web02's finding keeps its values.
	bad := item(t, "web01", cve(0), withFix(vulnfinding.FixFixed, "9.9-9"), withText("other"))
	bad.Finding.Key = victim.Finding.Key
	r := e.start(t)
	if _, err := e.st.SubmitBatch(e.ctx, r.ID, batchOf(0, nil, bad)); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("mismatched key: %v, want ErrInvalidInput", err)
	}
	after := e.get(t, victim.Finding.Key)
	if after.Rev != before.Rev || after.Record.Fix.Version != "1.0-2" || after.Subject != hostSubj("web02") {
		t.Fatalf("victim changed: %+v", after)
	}

	// A record that does not validate at all is refused the same way.
	broken := item(t, "web01", cve(1))
	broken.Finding.Record.Vuln.ID = "not a vuln id"
	if _, err := e.st.SubmitBatch(e.ctx, r.ID, batchOf(1, nil, broken)); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("invalid record: %v, want ErrInvalidInput", err)
	}
	// The refused batches left no trace: the same seq is accepted later.
	if res := e.submit(t, r, 0, nil, item(t, "web01", cve(0))); res.Opened != 1 {
		t.Fatalf("clean batch = %+v", res)
	}
}

func TestBatchRecordForStoredRowOfOtherSubjectIsRefused(t *testing.T) {
	e := newEnv(t)
	it := e.seed(t, "web01", 1)[0]
	// Simulate a stored row whose subject column disagrees with the record's.
	if _, err := e.st.db.Exec(`UPDATE vuln_findings SET subject = 'host/web09' WHERE finding_key = ?`, it.Finding.Key[:]); err != nil {
		t.Fatal(err)
	}
	r := e.start(t)
	if _, err := e.st.SubmitBatch(e.ctx, r.ID, batchOf(0, nil, item(t, "web01", cve(0), withText("v2")))); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("subject mismatch: %v, want ErrInvalidInput", err)
	}
	if f := e.get(t, it.Finding.Key); f.Record.Assessment.Text != "assessment v1" {
		t.Fatal("finding of another subject was overwritten")
	}
}

func TestRejectedKeysCountAgainstRunLimit(t *testing.T) {
	e := newEnv(t)
	r := e.start(t)
	if _, err := e.st.db.Exec(`UPDATE vuln_runs SET finding_count = ? WHERE id = ?`, MaxFindingsPerRun-1, r.ID); err != nil {
		t.Fatal(err)
	}
	b := batchOf(0, nil)
	b.Rejected = []vulnfinding.Key{item(t, "web01", cve(0)).Finding.Key, item(t, "web01", cve(1)).Finding.Key}
	if _, err := e.st.SubmitBatch(e.ctx, r.ID, b); !errors.Is(err, ErrBatchTooLarge) {
		t.Fatalf("rejected-only batch past the run limit: %v, want ErrBatchTooLarge", err)
	}
	b.Rejected = b.Rejected[:1]
	if _, err := e.st.SubmitBatch(e.ctx, r.ID, b); err != nil {
		t.Fatalf("rejected-only batch at the limit: %v", err)
	}
}

func TestNotAffectedFromRaiseOnlySourceDoesNotClose(t *testing.T) {
	e := newEnv(t)
	seeded := e.seed(t, "web01", 1)
	undated := RunSource{ID: "kev", SnapshotID: "snap-kev", Integrity: vulnfinding.IntegrityNone, DateKind: DateKindNone}
	r := e.start(t, e.src("osv"), undated)
	na := item(t, "web01", cve(0), withFix(vulnfinding.FixNotAffected, ""), withSources("kev"))
	res := e.submit(t, r, 0, []Subject{hostSubj("web01")}, na)
	if res.ClosureRequests != 0 || len(res.Ignored) != 1 || res.Ignored[0].Field != "fix" {
		t.Fatalf("result = %+v", res)
	}
	c := e.complete(t, r)
	if c.ClosedUnconfirmed != 0 || len(c.Held) != 0 {
		t.Fatalf("completion = %+v", c)
	}
	e.wantState(t, seeded[0].Finding.Key, StateOpen, "")
}

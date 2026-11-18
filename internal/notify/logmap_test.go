// SPDX-License-Identifier: AGPL-3.0-or-later

package notify

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/notifylog"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
)

// appendCall is one Append seen by recordingStore, with the log's answer.
type appendCall struct {
	rec notifylog.Record
	err error
}

// recordingStore forwards to a real notification log, so the log's own
// validation decides whether a record is refused, and reports every call.
type recordingStore struct {
	store *notifylog.Store
	calls chan appendCall
}

func (r *recordingStore) Append(ctx context.Context, rec notifylog.Record) (int64, error) {
	seq, err := r.store.Append(ctx, rec)
	r.calls <- appendCall{rec: rec, err: err}
	return seq, err
}

// newRealLog opens a notification log in a temporary server database.
func newRealLog(t *testing.T) (*notifylog.Store, *recordingStore) {
	t.Helper()
	db, err := serverdb.Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	store, err := notifylog.New(db, func() time.Time { return testNow })
	if err != nil {
		t.Fatal(err)
	}
	return store, &recordingStore{store: store, calls: make(chan appendCall, 100)}
}

// nextCall waits for one Append and fails the test if none comes.
func nextCall(t *testing.T, rec *recordingStore) appendCall {
	t.Helper()
	select {
	case c := <-rec.calls:
		return c
	case <-time.After(5 * time.Second):
		t.Fatal("no record was appended")
	}
	return appendCall{}
}

// TestEveryLoggableKindIsRecordedNotRefused: each event kind that has a
// notification log code is recorded, and the log accepts the record. Before
// the mapping, state values such as tier names were refused by the log.
func TestEveryLoggableKindIsRecordedNotRefused(t *testing.T) {
	cases := []struct {
		name  string
		ev    Event
		kind  notifylog.KindCode
		state notifylog.StateCode
	}{
		{"kev new keeps tier out of the state", Event{Kind: kindVulnKEVNew, Host: "web01", State: "critical", Reason: "CVE"}, notifylog.KindVulnKEVNew, notifylog.StateNew},
		{"critical new", Event{Kind: kindVulnCriticalNew, Host: "web01", State: "high"}, notifylog.KindVulnCriticalNew, notifylog.StateNew},
		{"hermes stale", Event{Kind: kindVulnHermesStale, State: "stale"}, notifylog.KindVulnHermesStale, notifylog.StateStale},
		{"feed stale", Event{Kind: kindVulnFeedStale, State: "stale"}, notifylog.KindVulnFeedStale, notifylog.StateStale},
		{"feed regressed", Event{Kind: kindVulnFeedRegressed, State: "invalid"}, notifylog.KindVulnFeedRegressed, notifylog.StateRegressed},
		{"feed mark reset", Event{Kind: kindVulnFeedMarkReset, State: "reset"}, notifylog.KindVulnFeedMarkReset, notifylog.StateReset},
		{"vuln digest", Event{Kind: kindVulnDigest, State: "digest"}, notifylog.KindDigest, notifylog.StateSummary},
		{"integrity digest", Event{Kind: KindIntegrityDigest, State: "digest"}, notifylog.KindDigest, notifylog.StateSummary},
		{"integrity nos mismatch", Event{Kind: string(IntegrityNOSMismatch), Host: "nos", State: "critical"}, notifylog.KindIntegrityNOSMismatch, notifylog.StateMismatch},
		{"integrity host change", Event{Kind: string(IntegrityHostChange), Host: "web01", State: "high"}, notifylog.KindIntegrityHostChange, notifylog.StateChanged},
		{"integrity scan incomplete", Event{Kind: string(IntegrityScanIncomplete), Host: "web01", State: "low"}, notifylog.KindIntegrityScanIncomplete, notifylog.StateIncomplete},
		{"integrity baseline tamper", Event{Kind: string(IntegrityBaselineTamper), Host: "web01", State: "critical"}, notifylog.KindIntegrityBaselineTamper, notifylog.StateTamper},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, rec := newRealLog(t)
			sender := &stubSender{name: "ntfy"}
			n := NewWithSenders(quiet(), nil, sender)
			n.SetRecorder(rec)
			// send is the shared delivery path; Notify refuses integrity kinds
			// by design, and the mapping must hold for them too.
			if got := n.send(context.Background(), tc.ev, nil); len(got) != 1 {
				t.Fatalf("send accepted by %v, want 1 provider", got)
			}
			c := nextCall(t, rec)
			if c.err != nil {
				t.Fatalf("log refused the record: %v", c.err)
			}
			if c.rec.Kind != tc.kind || c.rec.State != tc.state || c.rec.Outcome != notifylog.OutcomeSent {
				t.Fatalf("record %+v, want kind %q state %q sent", c.rec, tc.kind, tc.state)
			}
		})
	}
}

// TestKindsWithoutLogCodeAreSentNotRecorded: the log's closed sets have no
// code for these kinds yet (ADR 0016 D10 extension needed). They are still
// sent, and nothing is appended, so no warning is produced for them.
func TestKindsWithoutLogCodeAreSentNotRecorded(t *testing.T) {
	kinds := []string{KindHostKeyMismatch, KindTest, KindOpsState, KindExecution, KindExecutorLocked,
		string(IntegrityReferenceConflict)}
	for _, kind := range kinds {
		t.Run(kind, func(t *testing.T) {
			_, rec := newRealLog(t)
			sender := &stubSender{name: "ntfy"}
			n := NewWithSenders(quiet(), nil, sender)
			n.SetRecorder(rec)
			if got := n.send(context.Background(), Event{Kind: kind, Host: "web01", State: "x", Time: testNow}, nil); len(got) != 1 {
				t.Fatalf("send accepted by %v, want 1 provider", got)
			}
			if sender.count() != 1 {
				t.Fatalf("sender called %d times, want 1", sender.count())
			}
			select {
			case c := <-rec.calls:
				t.Fatalf("unexpected append %+v", c.rec)
			default:
			}
		})
	}
}

// TestIntegrityLinkIsStoredAsNOSPath: the absolute link is sent, but the log
// keeps the NOS path, so the link is not dropped as "changed".
func TestIntegrityLinkIsStoredAsNOSPath(t *testing.T) {
	store, rec := newRealLog(t)
	n := NewWithSenders(quiet(), nil, &stubSender{name: "ntfy"})
	n.SetRecorder(rec)
	g, err := NewIntegrityGate(n, "https://nos.example.net/", func() time.Time { return testNow })
	if err != nil {
		t.Fatal(err)
	}
	ev := validEvent(IntegrityHostChange)
	ev.Link = "https://nos.example.net/integrity/findings/7"
	if d, err := g.Submit(context.Background(), ev, NewIntegrityKey("web01", string(ev.Class), "/etc/x")); err != nil || d != DecisionSent {
		t.Fatalf("Submit = %v, %v; want DecisionSent", d, err)
	}
	if c := nextCall(t, rec); c.err != nil {
		t.Fatalf("log refused the record: %v", c.err)
	}
	entries, err := store.List(context.Background(), 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(entries))
	}
	if got := entries[0].Link; got != "/integrity/findings/7" {
		t.Fatalf("stored link %q, want /integrity/findings/7", got)
	}
	if entries[0].Changed.Has(notifylog.FieldLink) {
		t.Fatal("link was dropped as changed")
	}
}

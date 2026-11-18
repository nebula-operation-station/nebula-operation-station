// SPDX-License-Identifier: AGPL-3.0-or-later

package notify

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/notifylog"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
)

// testExecID is a lowercase UUIDv4, the execution ID form the log accepts.
const testExecID = "3f2b8c1e-9a4d-4e7f-8c2a-1b2c3d4e5f60"

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
		{"integrity reference conflict", Event{Kind: string(IntegrityReferenceConflict), Host: "web01", State: "high"}, notifylog.KindIntegrityReferenceConflict, notifylog.StateConflict},
		{"execution waiting", Event{Kind: KindExecution, State: "WAITING", ExecutionID: testExecID}, notifylog.KindExecution, notifylog.StateWaiting},
		{"execution with some hosts failed", Event{Kind: KindExecution, State: "WARNING", ExecutionID: testExecID}, notifylog.KindExecution, notifylog.StatePartial},
		{"execution failed", Event{Kind: KindExecution, State: "FAILED", ExecutionID: testExecID}, notifylog.KindExecution, notifylog.StateFailed},
		{"execution with an unknown state is still logged", Event{Kind: KindExecution, State: "SOMETHING NEW", ExecutionID: testExecID}, notifylog.KindExecution, notifylog.StateOther},
		{"ops state change", Event{Kind: KindOpsState, Host: "web01", State: "down", Reason: "web01 is now down"}, notifylog.KindOpsState, notifylog.StateChanged},
		{"host key mismatch", Event{Kind: KindHostKeyMismatch, Host: "web01", State: "mismatch"}, notifylog.KindHostKeyMismatch, notifylog.StateMismatch},
		{"test notification", Event{Kind: KindTest, Reason: "still works"}, notifylog.KindTest, notifylog.StateTest},
		{"executor locked", Event{Kind: KindExecutorLocked, State: "LOCKED"}, notifylog.KindExecutorLocked, notifylog.StateLocked},
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

// allNotifyKinds lists every event kind this package sends. A kind added to
// the package must be added here and to logEntry; TestEveryNotifyKindHasLogCode
// fails until both are done.
var allNotifyKinds = []string{
	kindVulnKEVNew, kindVulnCriticalNew, kindVulnHermesStale, kindVulnFeedStale,
	kindVulnFeedRegressed, kindVulnFeedMarkReset, kindVulnDigest,
	string(IntegrityNOSMismatch), string(IntegrityHostChange), string(IntegrityScanIncomplete),
	string(IntegrityBaselineTamper), string(IntegrityReferenceConflict), KindIntegrityDigest,
	KindHostKeyMismatch, KindTest, KindOpsState, KindExecution, KindExecutorLocked,
}

// TestEveryNotifyKindHasLogCode: every kind this package sends has a log code,
// so none of them is sent without a record.
func TestEveryNotifyKindHasLogCode(t *testing.T) {
	for _, kind := range allNotifyKinds {
		if _, _, ok := logEntry(Event{Kind: kind, State: "WAITING"}); !ok {
			t.Errorf("kind %q has no notification log code", kind)
		}
	}
}

// TestEveryNotifyKindIsStoredNotRefused: for every kind, the send path appends
// a record and the real log accepts it. This is the table over all event
// kinds: each one is stored, none is refused.
func TestEveryNotifyKindIsStoredNotRefused(t *testing.T) {
	for _, kind := range allNotifyKinds {
		t.Run(kind, func(t *testing.T) {
			_, rec := newRealLog(t)
			sender := &stubSender{name: "ntfy"}
			n := NewWithSenders(quiet(), nil, sender)
			n.SetRecorder(rec)
			ev := Event{Kind: kind, Host: "web01", State: "WAITING", ExecutionID: testExecID, Reason: "x", Time: testNow}
			if got := n.send(context.Background(), ev, nil); len(got) != 1 {
				t.Fatalf("send accepted by %v, want 1 provider", got)
			}
			c := nextCall(t, rec)
			if c.err != nil {
				t.Fatalf("log refused the record for %q: %v", kind, c.err)
			}
			if c.rec.Outcome != notifylog.OutcomeSent {
				t.Fatalf("outcome %q, want sent", c.rec.Outcome)
			}
		})
	}
}

// TestUnknownKindIsSentNotRecorded: a kind this package does not send has no
// log code. It is still delivered, nothing is appended, and the decision is
// logged at debug level only.
func TestUnknownKindIsSentNotRecorded(t *testing.T) {
	_, rec := newRealLog(t)
	sender := &stubSender{name: "ntfy"}
	n := NewWithSenders(quiet(), nil, sender)
	n.SetRecorder(rec)
	if got := n.send(context.Background(), Event{Kind: "not.a.kind", Host: "web01", Time: testNow}, nil); len(got) != 1 {
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
}

// TestHostLabelThatIsNotAnIDIsStoredEmpty: a display label that is not an
// inventory host ID (uppercase, or longer than 63 bytes) must not cost the
// whole record. The log is given an empty host, the event is recorded as
// sent, and the message is unchanged. An execution ID that is not a UUIDv4 is
// stored empty the same way.
func TestHostLabelThatIsNotAnIDIsStoredEmpty(t *testing.T) {
	long := strings.Repeat("a", 64)
	cases := []struct {
		name string
		ev   Event
		host string
		exec string
	}{
		{"uppercase label", Event{Kind: string(IntegrityHostChange), Host: "Web01", State: "x"}, "", ""},
		{"64-byte label", Event{Kind: string(IntegrityHostChange), Host: long, State: "x"}, "", ""},
		{"63-byte host ID is kept", Event{Kind: string(IntegrityHostChange), Host: strings.Repeat("a", 63), State: "x"}, strings.Repeat("a", 63), ""},
		{"execution ID that is not a UUIDv4", Event{Kind: KindExecution, Host: "web01", State: "FAILED", ExecutionID: "Ex-1"}, "web01", ""},
		{"valid host and execution ID", Event{Kind: KindExecution, Host: "web01", State: "FAILED", ExecutionID: testExecID}, "web01", testExecID},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, rec := newRealLog(t)
			sender := &stubSender{name: "ntfy"}
			n := NewWithSenders(quiet(), nil, sender)
			n.SetRecorder(rec)
			tc.ev.Time = testNow
			if got := n.send(context.Background(), tc.ev, nil); len(got) != 1 {
				t.Fatalf("send accepted by %v, want 1 provider", got)
			}
			if sender.count() != 1 {
				t.Fatalf("sender called %d times, want 1", sender.count())
			}
			c := nextCall(t, rec)
			if c.err != nil {
				t.Fatalf("log refused the record: %v", c.err)
			}
			if c.rec.Host != tc.host || c.rec.ExecutionID != tc.exec || c.rec.Outcome != notifylog.OutcomeSent {
				t.Fatalf("record host %q exec %q outcome %q, want host %q exec %q sent",
					c.rec.Host, c.rec.ExecutionID, c.rec.Outcome, tc.host, tc.exec)
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

// SPDX-License-Identifier: AGPL-3.0-or-later

package notify

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/notifylog"
)

var testNow = time.Unix(1791960000, 0)

// fakeRecorder is a Recorder that keeps every record. err, when set, is
// returned from every Append.
type fakeRecorder struct {
	mu   sync.Mutex
	recs []notifylog.Record
	err  error
}

func (f *fakeRecorder) Append(_ context.Context, r notifylog.Record) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.recs = append(f.recs, r)
	if f.err != nil {
		return 0, f.err
	}
	return int64(len(f.recs)), nil
}

func (f *fakeRecorder) got() []notifylog.Record {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]notifylog.Record(nil), f.recs...)
}

// stubSender is a provider that counts calls and returns err.
type stubSender struct {
	name string
	err  error
	mu   sync.Mutex
	sent int
}

func (s *stubSender) Name() string { return s.name }

func (s *stubSender) Send(context.Context, Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sent++
	return s.err
}

func (s *stubSender) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sent
}

// TestHeldIntegrityEventIsLogged: events beyond the hourly limit are held
// back and must appear in the log as held_rate_limit, next to the sent ones.
func TestHeldIntegrityEventIsLogged(t *testing.T) {
	rec := &fakeRecorder{}
	sender := &stubSender{name: "ntfy"}
	n := NewWithSenders(quiet(), nil, sender)
	n.SetRecorder(rec)
	g, err := NewIntegrityGate(n, "https://nos.example.net", func() time.Time { return testNow })
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for i := 0; i < MaxIntegrityPerHour+1; i++ {
		ev := IntegrityEvent{Kind: IntegrityHostChange, Host: "web01", Class: "pkg_hash", Severity: SeverityHigh, Count: 1}
		key := NewIntegrityKey("host-"+strconv.Itoa(i), "pkg_hash", "/etc/x")
		if _, err := g.Submit(ctx, ev, key); err != nil {
			t.Fatal(err)
		}
	}
	recs := rec.got()
	if len(recs) != MaxIntegrityPerHour+1 {
		t.Fatalf("got %d records, want %d", len(recs), MaxIntegrityPerHour+1)
	}
	var sent, held int
	for _, r := range recs {
		if r.Kind != notifylog.KindIntegrityHostChange || r.State != notifylog.StateChanged || r.Host != "web01" {
			t.Fatalf("record %+v: wrong kind, state or host", r)
		}
		switch r.Outcome {
		case notifylog.OutcomeSent:
			sent++
		case notifylog.OutcomeHeldRateLimit:
			held++
			if r.Reason != notifylog.ReasonRateLimited {
				t.Errorf("held record reason %q, want rate_limited", r.Reason)
			}
		default:
			t.Errorf("unexpected outcome %q", r.Outcome)
		}
	}
	if sent != MaxIntegrityPerHour || held != 1 {
		t.Fatalf("sent %d, held %d; want %d and 1", sent, held, MaxIntegrityPerHour)
	}
}

// TestSendFailureIsLoggedWithoutToken: a failed Telegram send is recorded as
// failed with a closed reason, and no record holds the bot token.
func TestSendFailureIsLoggedWithoutToken(t *testing.T) {
	var c captured
	srv := c.server(t, http.StatusInternalServerError)
	rec := &fakeRecorder{}
	tg := &telegram{base: srv.URL, token: botToken, chatID: "42", client: srv.Client()}
	n := NewWithSenders(quiet(), nil, tg)
	n.SetRecorder(rec)
	// A kind with a log code: a host key mismatch has none (see
	// TestKindsWithoutLogCodeAreSentNotRecorded).
	ev := Event{Kind: kindVulnKEVNew, Host: "web01", State: "critical", Reason: "CVE-2026-0001", Time: testNow}
	if got := n.Notify(context.Background(), ev); got != 0 {
		t.Fatalf("Notify = %d, want 0", got)
	}
	recs := rec.got()
	if len(recs) != 1 {
		t.Fatalf("got %d records, want 1", len(recs))
	}
	r := recs[0]
	if r.Outcome != notifylog.OutcomeFailed || r.Reason != notifylog.ReasonProviderRejected || r.Providers != 1 {
		t.Fatalf("record %+v: want failed, provider_rejected, 1 provider", r)
	}
	if dump := fmt.Sprintf("%+v", recs); strings.Contains(dump, botToken) || strings.Contains(dump, "123456:") {
		t.Fatal("notification log holds the provider token")
	}
}

// TestRecorderErrorDoesNotChangeDelivery: a failing recorder must not change
// what is sent or the number of providers that accepted it.
func TestRecorderErrorDoesNotChangeDelivery(t *testing.T) {
	rec := &fakeRecorder{err: errors.New("database is locked")}
	sender := &stubSender{name: "ntfy"}
	n := NewWithSenders(quiet(), nil, sender)
	n.SetRecorder(rec)
	if got := n.Notify(context.Background(), mismatch); got != 1 {
		t.Fatalf("Notify = %d, want 1", got)
	}
	if sender.count() != 1 {
		t.Fatalf("sender called %d times, want 1", sender.count())
	}
	g, err := NewIntegrityGate(n, "https://nos.example.net", func() time.Time { return testNow })
	if err != nil {
		t.Fatal(err)
	}
	ev := IntegrityEvent{Kind: IntegrityNOSMismatch, Host: "nos", Class: "binary", Severity: SeverityCritical, Count: 1}
	d, err := g.Submit(context.Background(), ev, NewIntegrityKey("nos", "binary", "/usr/bin/nebula"))
	if err != nil || d != DecisionSent {
		t.Fatalf("Submit = %v, %v; want DecisionSent", d, err)
	}
}

// TestHostKeyMismatchIsSentWithRecorder: a host key mismatch is still sent
// once when a recorder is set. Its kind has no code in the log's closed sets,
// so nothing is appended (see TestKindsWithoutLogCodeAreSentNotRecorded); the
// send is unaffected.
func TestHostKeyMismatchIsSentWithRecorder(t *testing.T) {
	rec := &fakeRecorder{}
	sender := &stubSender{name: "ntfy"}
	n := NewWithSenders(quiet(), nil, sender)
	n.SetRecorder(rec)
	if got := n.Notify(context.Background(), mismatch); got != 1 {
		t.Fatalf("Notify = %d, want 1", got)
	}
	if sender.count() != 1 {
		t.Fatalf("sender called %d times, want 1", sender.count())
	}
	if n := len(rec.got()); n != 0 {
		t.Fatalf("recorded %d entries for an unloggable kind, want 0", n)
	}
}

// TestSkippedProvidersAreNotRecorded: when every provider is skipped (the
// host key watcher's already-delivered case), nothing was sent or held, so
// nothing is recorded.
func TestSkippedProvidersAreNotRecorded(t *testing.T) {
	rec := &fakeRecorder{}
	sender := &stubSender{name: "ntfy"}
	n := NewWithSenders(quiet(), nil, sender)
	n.SetRecorder(rec)
	n.NotifyProviders(context.Background(), mismatch, func(string) bool { return true })
	if sender.count() != 0 || len(rec.got()) != 0 {
		t.Fatalf("sent %d, recorded %d; want 0 and 0", sender.count(), len(rec.got()))
	}
}

// TestTelegramOnlySendsMessages fixes ADR 0016 D10 "outbound only": the
// Telegram sender calls sendMessage and nothing else, and the package has no
// method for reading from a provider and no inbound HTTP handler.
func TestTelegramOnlySendsMessages(t *testing.T) {
	var c captured
	srv := c.server(t, http.StatusOK)
	tg := &telegram{base: srv.URL, token: botToken, chatID: "42", client: srv.Client()}
	if err := tg.Send(context.Background(), mismatch); err != nil {
		t.Fatal(err)
	}
	if len(c.reqs) != 1 {
		t.Fatalf("Telegram sender made %d requests, want 1", len(c.reqs))
	}
	if r := c.reqs[0]; r.Method != http.MethodPost || r.URL.Path != "/bot"+botToken+"/sendMessage" {
		t.Fatalf("Telegram request %s %s, want POST sendMessage", r.Method, r.URL.Path)
	}

	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	banned := []string{"getUpdates", "setWebhook", "deleteWebhook", "getWebhookInfo",
		"HandleFunc(", "Handle(", "ServeHTTP", "ListenAndServe", "http.Serve"}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, b := range banned {
			if strings.Contains(string(src), b) {
				t.Errorf("%s contains %q: NOS must not read from providers (ADR 0016 D10)", f, b)
			}
		}
	}
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/notify"
	"github.com/nebula-operation-station/nebula-operation-station/internal/integritystore"
	"github.com/nebula-operation-station/nebula-operation-station/internal/notifylog"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverconfig"
)

// notifySink is an httptest webhook receiver. It keeps every raw body it got.
type notifySink struct {
	mu     sync.Mutex
	bodies []string
}

func (s *notifySink) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.bodies)
}

func (s *notifySink) last(t *testing.T) notify.WebhookPayload {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.bodies) == 0 {
		t.Fatal("sink received no message")
	}
	var p notify.WebhookPayload
	if err := json.Unmarshal([]byte(s.bodies[len(s.bodies)-1]), &p); err != nil {
		t.Fatalf("message is not a webhook payload: %v", err)
	}
	return p
}

// newNotifySink starts a loopback webhook receiver and returns it with a
// notifier that sends to it over real HTTP.
func newNotifySink(t *testing.T) (*notifySink, *notify.Notifier) {
	t.Helper()
	sink := &notifySink{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		sink.mu.Lock()
		sink.bodies = append(sink.bodies, string(b))
		sink.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	n := notify.New(serverconfig.Notifications{Webhook: &serverconfig.WebhookConfig{URL: srv.URL + "/hook"}}, nil, slog.Default())
	return sink, n
}

// recordSink is a notification log that keeps the records it was given.
type recordSink struct {
	mu   sync.Mutex
	recs []notifylog.Record
}

func (r *recordSink) Append(_ context.Context, rec notifylog.Record) (int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.recs = append(r.recs, rec)
	return int64(len(r.recs)), nil
}

// tamperStatus is an executor reply with one open I2 baseline tamper finding
// for each host.
func tamperStatus(hosts ...string) *pb.GetIntegrityStatusResponse {
	resp := &pb.GetIntegrityStatusResponse{}
	for _, h := range hosts {
		resp.BaselineTamperFindings = append(resp.BaselineTamperFindings, &pb.BaselineTamperFinding{
			HostId: h, PresentedDigest: "9f2c7e1d0a", Count: 1,
		})
	}
	return resp
}

// fixedReader returns a status reader that answers with *cur on every call.
func fixedReader(cur **pb.GetIntegrityStatusResponse) integrityStatusReader {
	return func(context.Context, *pb.GetIntegrityStatusRequest) (*pb.GetIntegrityStatusResponse, error) {
		return *cur, nil
	}
}

// newTestGate returns the gate of the server wiring over n, with a fixed clock.
func newTestGate(t *testing.T, n *notify.Notifier) *notify.IntegrityGate {
	t.Helper()
	now := time.Date(2026, 11, 26, 10, 0, 0, 0, time.UTC)
	g, err := notify.NewIntegrityGate(n, "https://nos.example.net", func() time.Time { return now })
	if err != nil {
		t.Fatalf("new gate: %v", err)
	}
	return g
}

func TestIntegrityTamperReachesWebhookOverHTTP(t *testing.T) {
	sink, n := newNotifySink(t)
	cur := tamperStatus("web-01")
	prev, err := syncIntegrityTamper(context.Background(), newTestGate(t, n), fixedReader(&cur), nil, slog.Default())
	if err != nil {
		t.Fatalf("sync: %v", err)
	}
	if sink.count() != 1 {
		t.Fatalf("sink got %d messages, want 1", sink.count())
	}
	p := sink.last(t)
	if p.Kind != string(notify.IntegrityBaselineTamper) {
		t.Errorf("kind = %q, want %q", p.Kind, notify.IntegrityBaselineTamper)
	}
	if p.Host != "web-01" {
		t.Errorf("host = %q, want web-01", p.Host)
	}
	if !strings.Contains(p.Reason, "Class: "+integrityTamperClass) {
		t.Errorf("reason %q does not carry the class", p.Reason)
	}
	if len(prev) != 1 {
		t.Errorf("open findings after sync = %d, want 1", len(prev))
	}
}

func TestIntegrityTamperResendsAfterStatusChange(t *testing.T) {
	sink, n := newNotifySink(t)
	g := newTestGate(t, n)
	ctx := context.Background()
	cur := tamperStatus("web-01")
	read := fixedReader(&cur)

	open, err := syncIntegrityTamper(ctx, g, read, nil, slog.Default())
	if err != nil {
		t.Fatalf("first sync: %v", err)
	}
	// Same finding again: de-duplicated, nothing new is sent.
	open, err = syncIntegrityTamper(ctx, g, read, open, slog.Default())
	if err != nil {
		t.Fatalf("second sync: %v", err)
	}
	if sink.count() != 1 {
		t.Fatalf("after unchanged status sink got %d messages, want 1", sink.count())
	}
	// The finding closes: the gate forgets it.
	cur = tamperStatus()
	open, err = syncIntegrityTamper(ctx, g, read, open, slog.Default())
	if err != nil {
		t.Fatalf("closing sync: %v", err)
	}
	if len(open) != 0 {
		t.Fatalf("closed finding still open: %d", len(open))
	}
	// It opens again: notified again.
	cur = tamperStatus("web-01")
	if _, err := syncIntegrityTamper(ctx, g, read, open, slog.Default()); err != nil {
		t.Fatalf("reopening sync: %v", err)
	}
	if sink.count() != 2 {
		t.Fatalf("after reopening sink got %d messages, want 2", sink.count())
	}
}

func TestIntegrityTamperMessageCarriesNoHostPath(t *testing.T) {
	sink, n := newNotifySink(t)
	cur := tamperStatus("/etc/shadow")
	if _, err := syncIntegrityTamper(context.Background(), newTestGate(t, n), fixedReader(&cur), nil, slog.Default()); err != nil {
		t.Fatalf("sync: %v", err)
	}
	if sink.count() != 1 {
		t.Fatalf("sink got %d messages, want 1", sink.count())
	}
	sink.mu.Lock()
	raw := sink.bodies[0]
	sink.mu.Unlock()
	if strings.Contains(raw, "/etc") {
		t.Errorf("message carries a host path: %s", raw)
	}
	if strings.Contains(raw, "9f2c7e1d0a") {
		t.Errorf("message carries the presented digest: %s", raw)
	}
	if p := sink.last(t); strings.Contains(p.Host, "/") {
		t.Errorf("host label %q carries a slash", p.Host)
	}
}

func TestIntegrityTamperOverHourlyLimitIsHeldAndRecorded(t *testing.T) {
	sink, n := newNotifySink(t)
	rec := &recordSink{}
	n.SetRecorder(rec)
	hosts := make([]string, 0, notify.MaxIntegrityPerHour+1)
	for i := range notify.MaxIntegrityPerHour + 1 {
		hosts = append(hosts, "web-"+string(rune('a'+i)))
	}
	cur := tamperStatus(hosts...)
	if _, err := syncIntegrityTamper(context.Background(), newTestGate(t, n), fixedReader(&cur), nil, slog.Default()); err != nil {
		t.Fatalf("sync: %v", err)
	}
	if err := n.FlushRecords(context.Background()); err != nil {
		t.Fatalf("flush records: %v", err)
	}
	if sink.count() != notify.MaxIntegrityPerHour {
		t.Fatalf("sink got %d messages, want %d (the limit)", sink.count(), notify.MaxIntegrityPerHour)
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	var held int
	for _, r := range rec.recs {
		if r.Outcome == notifylog.OutcomeHeldRateLimit {
			held++
		}
	}
	if held != 1 {
		t.Fatalf("recorded %d held messages, want 1", held)
	}
}

// TestIntegrityTamperClassIsTheGateSpellingOfTheStoreClass pins the one
// place where the baseline tamper class is named: the integritystore class
// with '-' replaced by '_', because the gate accepts only a-z, 0-9 and '_'.
func TestIntegrityTamperClassIsTheGateSpellingOfTheStoreClass(t *testing.T) {
	want := strings.ReplaceAll(string(integritystore.ClassBaselineDigestMismatch), "-", "_")
	if integrityTamperClass != want {
		t.Fatalf("integrityTamperClass = %q, want %q", integrityTamperClass, want)
	}
}

func TestIntegrityGateRejectsEventWithoutClass(t *testing.T) {
	sink, n := newNotifySink(t)
	g := newTestGate(t, n)
	ev := notify.IntegrityEvent{Kind: notify.IntegrityBaselineTamper, Host: "web-01", Class: "", Severity: notify.SeverityHigh, Count: 1}
	d, err := g.Submit(context.Background(), ev, notify.NewIntegrityKey("web-01", "", ""))
	if !errors.Is(err, notify.ErrInvalidIntegrityEvent) || d != notify.DecisionNone {
		t.Fatalf("Submit without class = (%v, %v), want DecisionNone and ErrInvalidIntegrityEvent", d, err)
	}
	if sink.count() != 0 {
		t.Fatalf("event without class was sent (%d messages)", sink.count())
	}
}

func TestIntegrityNotifyWithoutNotifierStartsNormally(t *testing.T) {
	failIfRun := func(func(context.Context)) error {
		t.Error("loop started without a notifier")
		return nil
	}
	cases := []struct {
		name     string
		notifier *notify.Notifier
	}{
		{name: "no notifier", notifier: nil},
		{name: "notifier without providers", notifier: notify.New(serverconfig.Notifications{}, nil, slog.Default())},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := serverDeps{notifier: tc.notifier, log: slog.Default(), run: failIfRun}
			if err := wireIntegrityNotify(d, http.NewServeMux()); err != nil {
				t.Fatalf("wireIntegrityNotify: %v", err)
			}
		})
	}
}

func TestIntegrityNotifyStartsLoopWithNotifier(t *testing.T) {
	_, n := newNotifySink(t)
	var started int
	d := serverDeps{
		cfg:      serverconfig.Config{PublicOrigin: "https://nos.example.net"},
		notifier: n,
		log:      slog.Default(),
		run: func(func(context.Context)) error {
			started++
			return nil
		},
	}
	if err := wireIntegrityNotify(d, http.NewServeMux()); err != nil {
		t.Fatalf("wireIntegrityNotify: %v", err)
	}
	if started != 1 {
		t.Fatalf("loop started %d times, want 1", started)
	}
}

func TestIntegrityNotifyRefusesInvalidNOSBase(t *testing.T) {
	_, n := newNotifySink(t)
	d := serverDeps{
		cfg:      serverconfig.Config{PublicOrigin: "nos.example.net"},
		notifier: n,
		log:      slog.Default(),
		run:      func(func(context.Context)) error { return nil },
	}
	err := wireIntegrityNotify(d, http.NewServeMux())
	if !errors.Is(err, notify.ErrInvalidNOSBase) {
		t.Fatalf("wireIntegrityNotify with bad origin = %v, want ErrInvalidNOSBase", err)
	}
}

func TestIntegrityNotifyKeepsOpenFindingsWhenReadFails(t *testing.T) {
	sink, n := newNotifySink(t)
	g := newTestGate(t, n)
	ctx := context.Background()
	cur := tamperStatus("web-01")
	open, err := syncIntegrityTamper(ctx, g, fixedReader(&cur), nil, slog.Default())
	if err != nil {
		t.Fatalf("first sync: %v", err)
	}
	failing := func(context.Context, *pb.GetIntegrityStatusRequest) (*pb.GetIntegrityStatusResponse, error) {
		return nil, errors.New("executor unreachable")
	}
	kept, err := syncIntegrityTamper(ctx, g, failing, open, slog.Default())
	if err == nil {
		t.Fatal("failed read returned no error")
	}
	if len(kept) != len(open) {
		t.Fatalf("failed read changed the open findings: %d, want %d", len(kept), len(open))
	}
	// Still open after the failed read: no new message for the same finding.
	if _, err := syncIntegrityTamper(ctx, g, fixedReader(&cur), kept, slog.Default()); err != nil {
		t.Fatalf("sync after failed read: %v", err)
	}
	if sink.count() != 1 {
		t.Fatalf("sink got %d messages, want 1", sink.count())
	}
}

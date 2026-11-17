// SPDX-License-Identifier: AGPL-3.0-or-later

package notify

import (
	"context"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/notifylog"
)

// gateRecorder is a Recorder whose writes wait for release. Each write reports
// its context state at the moment it starts, before the write returns.
type gateRecorder struct {
	release chan struct{}
	starts  chan writeStart
}

type writeStart struct {
	ctxErr      error
	deadline    time.Time
	hasDeadline bool
}

func newGateRecorder(t *testing.T) *gateRecorder {
	t.Helper()
	g := &gateRecorder{release: make(chan struct{}), starts: make(chan writeStart, 100)}
	t.Cleanup(func() { close(g.release) })
	return g
}

func (g *gateRecorder) Append(ctx context.Context, _ notifylog.Record) (int64, error) {
	d, ok := ctx.Deadline()
	g.starts <- writeStart{ctxErr: ctx.Err(), deadline: d, hasDeadline: ok}
	<-g.release
	return 1, nil
}

// TestSlowRecorderDoesNotDelaySends: a log write that blocks must not hold up
// the sends that follow it (ADR 0016 D10: the log never blocks a notification).
func TestSlowRecorderDoesNotDelaySends(t *testing.T) {
	rec := newGateRecorder(t)
	sender := &stubSender{name: "ntfy"}
	n := NewWithSenders(quiet(), nil, sender)
	n.SetRecorder(rec)
	ev := Event{Kind: kindVulnKEVNew, Host: "web01", State: "critical", Time: testNow}

	done := make(chan int, 1)
	go func() {
		total := 0
		for i := 0; i < 5; i++ {
			total += n.Notify(context.Background(), ev)
		}
		done <- total
	}()
	select {
	case got := <-done:
		if got != 5 {
			t.Fatalf("%d sends accepted, want 5", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("sends waited for a blocked log write")
	}
	if sender.count() != 5 {
		t.Fatalf("sender called %d times, want 5", sender.count())
	}
}

// TestFullQueueDropsRecordsAndCountsThem: when every write slot is taken, the
// next record is dropped and counted, and the send still happens.
func TestFullQueueDropsRecordsAndCountsThem(t *testing.T) {
	rec := newGateRecorder(t)
	sender := &stubSender{name: "ntfy"}
	n := NewWithSenders(quiet(), nil, sender)
	n.SetRecorder(rec)
	ev := Event{Kind: kindVulnKEVNew, Host: "web01", State: "critical", Time: testNow}

	const extra = 3
	for i := 0; i < maxPendingRecords+extra; i++ {
		if got := n.Notify(context.Background(), ev); got != 1 {
			t.Fatalf("send %d accepted by %d providers, want 1", i, got)
		}
	}
	if got := n.RecordsDropped(); got != extra {
		t.Fatalf("RecordsDropped = %d, want %d", got, extra)
	}
	if sender.count() != maxPendingRecords+extra {
		t.Fatalf("sender called %d times, want %d", sender.count(), maxPendingRecords+extra)
	}
}

// TestRecordContextIgnoresSendCancellation: a send that is cancelled after it
// succeeded must not cancel the log write of its decision.
func TestRecordContextIgnoresSendCancellation(t *testing.T) {
	rec := newGateRecorder(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cancelling := &cancelSender{cancel: cancel}
	n := NewWithSenders(quiet(), nil, cancelling)
	n.SetRecorder(rec)
	if got := n.Notify(ctx, Event{Kind: kindVulnKEVNew, Host: "web01", State: "critical", Time: testNow}); got != 1 {
		t.Fatalf("Notify = %d, want 1", got)
	}
	s := waitStart(t, rec)
	if s.ctxErr != nil {
		t.Fatalf("log write context already done: %v", s.ctxErr)
	}
}

// TestRecordWriteIsBoundedByRecordTimeout: a log write gets a deadline of
// recordTimeout, so a stuck database cannot hold its slot forever.
func TestRecordWriteIsBoundedByRecordTimeout(t *testing.T) {
	rec := newGateRecorder(t)
	n := NewWithSenders(quiet(), nil, &stubSender{name: "ntfy"})
	n.SetRecorder(rec)
	if got := n.Notify(context.Background(), Event{Kind: kindVulnKEVNew, Host: "web01", State: "critical", Time: testNow}); got != 1 {
		t.Fatalf("Notify = %d, want 1", got)
	}
	s := waitStart(t, rec)
	if !s.hasDeadline {
		t.Fatal("log write has no deadline")
	}
	left := time.Until(s.deadline)
	if left > recordTimeout || left < recordTimeout-time.Second {
		t.Fatalf("log write deadline in %v, want about %v", left, recordTimeout)
	}
}

// cancelSender succeeds and then cancels the send's context.
type cancelSender struct {
	cancel context.CancelFunc
}

func (c *cancelSender) Name() string { return "ntfy" }

func (c *cancelSender) Send(context.Context, Event) error {
	c.cancel()
	return nil
}

// waitStart waits for one log write to start and returns its state.
func waitStart(t *testing.T, g *gateRecorder) writeStart {
	t.Helper()
	select {
	case s := <-g.starts:
		return s
	case <-time.After(5 * time.Second):
		t.Fatal("no log write started")
	}
	return writeStart{}
}

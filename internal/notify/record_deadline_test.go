// SPDX-License-Identifier: AGPL-3.0-or-later

package notify

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/notifylog"
)

// scriptedRecorder is a Recorder whose behaviour depends on the call index:
// calls whose index is in block wait until their context ends; every other
// call sleeps for delay (honouring the context) and then stores, or fails
// with err when err is set.
type scriptedRecorder struct {
	mu     sync.Mutex
	calls  int
	block  map[int]bool
	delay  time.Duration
	err    error
	stored int
}

func (s *scriptedRecorder) Append(ctx context.Context, _ notifylog.Record) (int64, error) {
	s.mu.Lock()
	idx := s.calls
	s.calls++
	blocked := s.block[idx]
	s.mu.Unlock()

	if blocked {
		<-ctx.Done()
		return 0, ctx.Err()
	}
	if s.delay > 0 {
		t := time.NewTimer(s.delay)
		defer t.Stop()
		select {
		case <-t.C:
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	}
	if s.err != nil {
		return 0, s.err
	}
	s.mu.Lock()
	s.stored++
	s.mu.Unlock()
	return int64(idx + 1), nil
}

func (s *scriptedRecorder) counts() (attempted, stored int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls, s.stored
}

// heldBatch returns size events that RecordHeld logs as held_rate_limit.
func heldBatch(size int) []Event {
	batch := make([]Event, size)
	for i := range batch {
		batch[i] = Event{Kind: kindVulnKEVNew, Host: "web01", State: "new", Time: testNow}
	}
	return batch
}

// TestHeldBatchLongerThanOneDeadlineStoresEveryRecord: a batch whose writes
// take longer in total than one recordTimeout still stores every record. Each
// record has its own deadline, so the tail of a large batch is not lost to a
// shared deadline that ran out.
func TestHeldBatchLongerThanOneDeadlineStoresEveryRecord(t *testing.T) {
	rec := &scriptedRecorder{delay: 15 * time.Millisecond}
	n := NewWithSenders(quiet(), nil, &stubSender{name: "ntfy"})
	n.SetRecorder(rec)
	n.recTimeout = 40 * time.Millisecond
	const size = 5 // 5 x 15ms = 75ms, longer than the 40ms deadline
	n.RecordHeld(context.Background(), heldBatch(size)...)
	if err := n.FlushRecords(context.Background()); err != nil {
		t.Fatalf("FlushRecords = %v", err)
	}
	attempted, stored := rec.counts()
	if attempted != size || stored != size {
		t.Fatalf("attempted %d, stored %d; want both %d", attempted, stored, size)
	}
	if got := n.RecordsDropped(); got != 0 {
		t.Fatalf("RecordsDropped = %d, want 0", got)
	}
}

// TestExpiredRecordsAreCountedAndTheRestAreTried: when some writes hit their
// deadline, every other record of the batch is still tried and stored, the
// expired ones are counted in RecordsDropped, and one warning gives the exact
// count.
func TestExpiredRecordsAreCountedAndTheRestAreTried(t *testing.T) {
	rec := &scriptedRecorder{block: map[int]bool{1: true, 3: true}}
	var buf syncBuffer
	n := NewWithSenders(slog.New(slog.NewTextHandler(&buf, nil)), nil, &stubSender{name: "ntfy"})
	n.SetRecorder(rec)
	n.recTimeout = 20 * time.Millisecond
	const size = 5
	n.RecordHeld(context.Background(), heldBatch(size)...)
	if err := n.FlushRecords(context.Background()); err != nil {
		t.Fatalf("FlushRecords = %v", err)
	}
	attempted, stored := rec.counts()
	if attempted != size {
		t.Fatalf("attempted %d records, want all %d", attempted, size)
	}
	if stored != 3 {
		t.Fatalf("stored %d records, want 3 (two expired)", stored)
	}
	if got := n.RecordsDropped(); got != 2 {
		t.Fatalf("RecordsDropped = %d, want 2", got)
	}
	out := buf.String()
	if c := strings.Count(out, "notification log write failed"); c != 1 {
		t.Fatalf("got %d warnings, want 1: %q", c, out)
	}
	if !strings.Contains(out, "count=2") || !strings.Contains(out, "of=5") {
		t.Fatalf("warning does not give count=2 of=5: %q", out)
	}
	if !strings.Contains(out, "deadline exceeded") {
		t.Fatalf("warning does not name the deadline: %q", out)
	}
}

// TestFailedAppendsAreCountedInRecordsDropped: records whose Append fails are
// not in the log, so they are counted in RecordsDropped as well as in the
// warning.
func TestFailedAppendsAreCountedInRecordsDropped(t *testing.T) {
	rec := &scriptedRecorder{err: errors.New("sql: database is closed")}
	n := NewWithSenders(quiet(), nil, &stubSender{name: "ntfy"})
	n.SetRecorder(rec)
	const size = 4
	n.RecordHeld(context.Background(), heldBatch(size)...)
	if err := n.FlushRecords(context.Background()); err != nil {
		t.Fatalf("FlushRecords = %v", err)
	}
	if got := n.RecordsDropped(); got != size {
		t.Fatalf("RecordsDropped = %d, want %d", got, size)
	}
}

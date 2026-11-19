// SPDX-License-Identifier: AGPL-3.0-or-later

package notify

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/notifylog"
)

// syncBuffer is a log sink that is safe for the write goroutine and the test.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// deadlineRecorder records the deadline of each Append's context and the time
// of the call.
type deadlineRecorder struct {
	mu        sync.Mutex
	deadlines []time.Time
	starts    []time.Time
	hasDL     []bool
}

func (d *deadlineRecorder) Append(ctx context.Context, _ notifylog.Record) (int64, error) {
	start := time.Now()
	dl, ok := ctx.Deadline()
	d.mu.Lock()
	d.deadlines = append(d.deadlines, dl)
	d.starts = append(d.starts, start)
	d.hasDL = append(d.hasDL, ok)
	d.mu.Unlock()
	return 1, nil
}

// TestHeldBatchRecordsEachGetOneDeadline: a batch from RecordHeld is written
// as one write slot, and each of its records has its own deadline of about
// recordTimeout from the moment it is written, so a long batch never loses its
// tail to a deadline that ran out early.
func TestHeldBatchRecordsEachGetOneDeadline(t *testing.T) {
	rec := &deadlineRecorder{}
	n := NewWithSenders(quiet(), nil, &stubSender{name: "ntfy"})
	n.SetRecorder(rec)
	const size = 5
	batch := make([]Event, size)
	for i := range batch {
		batch[i] = Event{Kind: kindVulnKEVNew, Host: "web01", State: "new", Time: testNow}
	}
	n.RecordHeld(context.Background(), batch...)
	if err := n.FlushRecords(context.Background()); err != nil {
		t.Fatalf("FlushRecords = %v", err)
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if len(rec.deadlines) != size {
		t.Fatalf("got %d appends, want %d", len(rec.deadlines), size)
	}
	for i, dl := range rec.deadlines {
		if !rec.hasDL[i] {
			t.Fatalf("record %d write has no deadline", i)
		}
		budget := dl.Sub(rec.starts[i])
		if budget > recordTimeout || budget < recordTimeout-time.Second {
			t.Fatalf("record %d deadline budget %v, want about %v", i, budget, recordTimeout)
		}
	}
}

// TestFailedBatchLogsOneWarning: when the log refuses every record of a batch
// (for example after the database has closed), the batch is logged as one
// warning with the count, not one warning per record.
func TestFailedBatchLogsOneWarning(t *testing.T) {
	rec := &fakeRecorder{err: errors.New("sql: database is closed")}
	var buf syncBuffer
	n := NewWithSenders(slog.New(slog.NewTextHandler(&buf, nil)), nil, &stubSender{name: "ntfy"})
	n.SetRecorder(rec)
	const size = 5
	batch := make([]Event, size)
	for i := range batch {
		batch[i] = Event{Kind: kindVulnKEVNew, Host: "web01", State: "new", Time: testNow}
	}
	n.RecordHeld(context.Background(), batch...)
	if err := n.FlushRecords(context.Background()); err != nil {
		t.Fatalf("FlushRecords = %v", err)
	}
	if got := len(rec.got()); got != size {
		t.Fatalf("got %d appends, want %d", got, size)
	}
	out := buf.String()
	if c := strings.Count(out, "notification log write failed"); c != 1 {
		t.Fatalf("got %d warnings, want 1 for the batch: %q", c, out)
	}
	if !strings.Contains(out, "count=5") {
		t.Fatalf("warning does not count the failed records: %q", out)
	}
}

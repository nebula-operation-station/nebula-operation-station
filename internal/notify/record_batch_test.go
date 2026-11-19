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

// deadlineRecorder records the deadline of each Append's context.
type deadlineRecorder struct {
	mu        sync.Mutex
	deadlines []time.Time
	hasDL     []bool
}

func (d *deadlineRecorder) Append(ctx context.Context, _ notifylog.Record) (int64, error) {
	dl, ok := ctx.Deadline()
	d.mu.Lock()
	d.deadlines = append(d.deadlines, dl)
	d.hasDL = append(d.hasDL, ok)
	d.mu.Unlock()
	return 1, nil
}

// TestHeldBatchIsOneWriteWithOneDeadline: a batch from RecordHeld is written
// as one write operation. All of its records share one deadline of about
// recordTimeout, so a batch cannot take recordTimeout per record and outlast
// the shutdown flush.
func TestHeldBatchIsOneWriteWithOneDeadline(t *testing.T) {
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
	first := rec.deadlines[0]
	if !rec.hasDL[0] {
		t.Fatal("batch write has no deadline")
	}
	for i, dl := range rec.deadlines {
		if !rec.hasDL[i] || !dl.Equal(first) {
			t.Fatalf("record %d deadline %v, want the batch deadline %v", i, dl, first)
		}
	}
	left := time.Until(first)
	if left > recordTimeout || left < recordTimeout-time.Second {
		t.Fatalf("batch deadline in %v, want about %v", left, recordTimeout)
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

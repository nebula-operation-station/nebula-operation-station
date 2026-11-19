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

// TestHeldBatchEachRecordGetsItsOwnDeadline: the records of one batch take
// longer in total than one record deadline (5 x 60ms against 100ms). With a
// deadline shared by the whole batch, only the first record would be stored;
// each record has its own deadline, so every record is stored.
func TestHeldBatchEachRecordGetsItsOwnDeadline(t *testing.T) {
	rec := &scriptedRecorder{delay: 60 * time.Millisecond}
	n := NewWithSenders(quiet(), nil, &stubSender{name: "ntfy"})
	n.SetRecorder(rec)
	n.recTimeout = 100 * time.Millisecond
	const size = 5
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

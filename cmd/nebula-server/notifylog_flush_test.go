// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/notify"
	"github.com/nebula-operation-station/nebula-operation-station/internal/notifylog"
)

// flushTestSender is a provider that always accepts.
type flushTestSender struct{}

func (flushTestSender) Name() string                             { return "test" }
func (flushTestSender) Send(context.Context, notify.Event) error { return nil }

// blockingRecorder stores records after release is closed (or immediately if
// release is nil), so a test can see a write in flight at shutdown.
type blockingRecorder struct {
	release <-chan struct{}
	mu      sync.Mutex
	stored  int
}

func (b *blockingRecorder) Append(ctx context.Context, _ notifylog.Record) (int64, error) {
	if b.release != nil {
		select {
		case <-b.release:
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	}
	b.mu.Lock()
	b.stored++
	b.mu.Unlock()
	return 1, nil
}

func (b *blockingRecorder) count() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.stored
}

func flushTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// TestShutdownFlushWaitsForLogWrites: a decision made just before shutdown
// is in the log when the flush returns. The write here is slow, so without the
// flush the record would still be in flight when the database would close.
func TestShutdownFlushWaitsForLogWrites(t *testing.T) {
	release := make(chan struct{})
	rec := &blockingRecorder{release: release}
	n := notify.NewWithSenders(flushTestLogger(), nil, flushTestSender{})
	n.SetRecorder(rec)
	n.Notify(context.Background(), notify.Event{Kind: notify.KindTest, Reason: "x", Time: time.Unix(1791960000, 0)})

	// Let the slow write finish shortly after the flush starts.
	go func() {
		time.Sleep(50 * time.Millisecond)
		close(release)
	}()
	flushNotifyRecords(n, flushTestLogger(), 5*time.Second)
	if got := rec.count(); got != 1 {
		t.Fatalf("stored records after flush = %d, want 1", got)
	}
}

// TestShutdownFlushIsBoundedByTimeout: a write that never ends does not hold
// shutdown past the timeout. The flush returns and logs a warning.
func TestShutdownFlushIsBoundedByTimeout(t *testing.T) {
	stuck := make(chan struct{})
	defer close(stuck)
	rec := &blockingRecorder{release: stuck}
	n := notify.NewWithSenders(flushTestLogger(), nil, flushTestSender{})
	n.SetRecorder(rec)
	n.Notify(context.Background(), notify.Event{Kind: notify.KindTest, Reason: "x", Time: time.Unix(1791960000, 0)})

	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	start := time.Now()
	flushNotifyRecords(n, log, 50*time.Millisecond)
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("flush took %v with a 50ms timeout", elapsed)
	}
	if !bytes.Contains(buf.Bytes(), []byte("notification log writes not finished at shutdown")) {
		t.Fatalf("no warning logged for the timed-out flush: %q", buf.String())
	}
}

// TestShutdownFlushWithoutLogIsNoOp: with no log attached (the log could not
// be opened), the flush returns at once and logs nothing.
func TestShutdownFlushWithoutLogIsNoOp(t *testing.T) {
	n := notify.NewWithSenders(flushTestLogger(), nil, flushTestSender{})
	var buf bytes.Buffer
	flushNotifyRecords(n, slog.New(slog.NewTextHandler(&buf, nil)), time.Second)
	if buf.Len() != 0 {
		t.Fatalf("flush without a log logged %q", buf.String())
	}
}

// slowRecorder stores each record after delay (honouring its context), so a
// batch takes delay times its size in total.
type slowRecorder struct {
	delay time.Duration
	mu    sync.Mutex
	n     int
}

func (s *slowRecorder) Append(ctx context.Context, _ notifylog.Record) (int64, error) {
	t := time.NewTimer(s.delay)
	defer t.Stop()
	select {
	case <-t.C:
	case <-ctx.Done():
		return 0, ctx.Err()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.n++
	return int64(s.n), nil
}

func (s *slowRecorder) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.n
}

// TestShutdownFlushCoversWholeHeldBatch: the records of one held batch (the
// vulnerability digest hands its holds over in one call) are all in the log
// when the flush returns. The batch takes 6 seconds in total, longer than one
// 5-second record deadline, so the flush must wait for the whole batch and no
// record may be lost to a deadline shared by the batch.
func TestShutdownFlushCoversWholeHeldBatch(t *testing.T) {
	const size = 3
	rec := &slowRecorder{delay: 2 * time.Second}
	n := notify.NewWithSenders(flushTestLogger(), nil, flushTestSender{})
	n.SetRecorder(rec)
	batch := make([]notify.Event, size)
	for i := range batch {
		batch[i] = notify.Event{Kind: notify.KindTest, Reason: "x", Time: time.Unix(1791960000, 0)}
	}
	n.RecordHeld(context.Background(), batch...)

	flushNotifyRecords(n, flushTestLogger(), notifyFlushTimeout)
	if got := rec.count(); got != size {
		t.Fatalf("stored records after flush = %d, want %d", got, size)
	}
}

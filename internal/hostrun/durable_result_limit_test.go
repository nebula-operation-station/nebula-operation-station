// SPDX-License-Identifier: AGPL-3.0-or-later

package hostrun_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"hash"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/fimscan"
	"github.com/nebula-operation-station/nebula-operation-station/internal/hostrun"
)

// raisedLimit is an action-specific limit above the 1 MiB default, small
// enough to keep the loopback tests fast.
const raisedLimit = 3 << 20

// jsonDoc returns one JSON document of exactly n bytes (n >= 10).
func jsonDoc(n int) []byte {
	return []byte(`{"p":"` + strings.Repeat("a", n-9) + `"}` + "\n")
}

// hashWriter counts and hashes what it receives; it keeps no document
// bytes, like a streaming parser.
type hashWriter struct {
	h        hash.Hash
	n        int
	maxWrite int
}

func newHashWriter() *hashWriter { return &hashWriter{h: sha256.New()} }

func (w *hashWriter) Write(p []byte) (int, error) {
	w.n += len(p)
	w.maxWrite = max(w.maxWrite, len(p))
	return w.h.Write(p)
}

// runDurableDoc runs a durable job that prints doc and returns the
// finished job's exit code.
func runDurableDoc(t *testing.T, cfg hostrun.JobConfig, id string, doc []byte, script string) int {
	t.Helper()
	c := client(t)
	ctx := context.Background()
	f := filepath.Join(t.TempDir(), "doc.json")
	if err := os.WriteFile(f, doc, 0o600); err != nil {
		t.Fatal(err)
	}
	if script == "" {
		script = "cat " + f + "\n"
	}
	if out, detail, err := hostrun.Dispatch(ctx, c, cfg, id, []byte(`{}`), []byte(script), time.Minute); err != nil || out != hostrun.Dispatched {
		t.Fatalf("dispatch: %v %s %v", out, detail, err)
	}
	st := waitPhase(t, func() hostrun.JobState {
		st, err := hostrun.Check(ctx, c, cfg, id)
		if err != nil {
			t.Fatal(err)
		}
		return st
	}, "finished")
	return st.ExitCode
}

func TestDurableResultLimitMaximumIsTheFimScanDocumentLimit(t *testing.T) {
	if hostrun.MaxDurableResultLimit != fimscan.MaxDocumentBytes {
		t.Fatalf("MaxDurableResultLimit %d, fimscan.MaxDocumentBytes %d", hostrun.MaxDurableResultLimit, fimscan.MaxDocumentBytes)
	}
	// The defaults of every other action stay as they are.
	if hostrun.MaxResult != 1<<20 || hostrun.MaxTimeout != 10*time.Minute {
		t.Fatalf("defaults changed: %d %s", hostrun.MaxResult, hostrun.MaxTimeout)
	}
}

func TestDurableResultWithinRaisedLimitIsComplete(t *testing.T) {
	for _, size := range []int{raisedLimit - 1, raisedLimit} {
		cfg := jobConfig(t)
		doc := jsonDoc(size)
		exit := runDurableDoc(t, cfg, execID, doc, "")
		w := newHashWriter()
		r, err := hostrun.CollectStream(context.Background(), client(t), cfg, execID, exit, raisedLimit, w)
		if err != nil {
			t.Fatal(err)
		}
		want := sha256.Sum256(doc)
		if r.Class != hostrun.ClassSuccess || r.Truncated || r.Bytes != int64(size) || w.n != size || !bytes.Equal(w.h.Sum(nil), want[:]) {
			t.Fatalf("size %d: %+v, writer got %d bytes", size, r, w.n)
		}
	}
}

func TestDurableResultAboveRaisedLimitIsTruncated(t *testing.T) {
	cfg := jobConfig(t)
	doc := jsonDoc(raisedLimit + 1)
	exit := runDurableDoc(t, cfg, execID, doc, "")
	w := newHashWriter()
	r, err := hostrun.CollectStream(context.Background(), client(t), cfg, execID, exit, raisedLimit, w)
	if err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256(doc[:raisedLimit])
	if !r.Truncated || r.Class == hostrun.ClassSuccess || r.Class != hostrun.ClassScriptFailed || r.Bytes != raisedLimit {
		t.Fatalf("over the limit: %+v", r)
	}
	// The writer never sees more than the limit.
	if w.n != raisedLimit || !bytes.Equal(w.h.Sum(nil), want[:]) {
		t.Fatalf("writer got %d bytes", w.n)
	}
}

func TestDurableResultWithoutRaisedLimitKeepsOneMiB(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		size      int
		truncated bool
	}{
		{hostrun.MaxResult, false},
		{hostrun.MaxResult + 1, true},
	}
	for _, tc := range cases {
		cfg := jobConfig(t)
		exit := runDurableDoc(t, cfg, execID, jsonDoc(tc.size), "")
		w := newHashWriter()
		r, err := hostrun.CollectStream(ctx, client(t), cfg, execID, exit, 0, w)
		if err != nil {
			t.Fatal(err)
		}
		if r.Truncated != tc.truncated || (r.Class == hostrun.ClassSuccess) == tc.truncated || w.n > hostrun.MaxResult {
			t.Fatalf("size %d: %+v, writer got %d bytes", tc.size, r, w.n)
		}
		// The buffered read keeps its 1 MiB limit as well.
		b, err := hostrun.Collect(ctx, client(t), cfg, execID, exit)
		if err != nil || (b.Class == hostrun.ClassSuccess) == tc.truncated {
			t.Fatalf("collect size %d: %s %s %v", tc.size, b.Class, b.Detail, err)
		}
	}
}

// heapWriter is a hashWriter that samples the heap while the document
// passes through it.
type heapWriter struct {
	*hashWriter
	calls int
	peak  uint64
}

func (w *heapWriter) Write(p []byte) (int, error) {
	if w.calls++; w.calls%16 == 0 {
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		w.peak = max(w.peak, m.HeapAlloc)
	}
	return w.hashWriter.Write(p)
}

// maxStreamHeapGrowth is how much the heap may grow while a 128 MiB
// document streams: far below the document, so holding it would show.
const maxStreamHeapGrowth = 32 << 20

// The whole fim.scan document limit, streamed: a document one byte under
// 128 MiB is complete and never held in memory by hostrun.
func TestDurableResultAtFimScanLimitIsStreamed(t *testing.T) {
	cfg := jobConfig(t)
	limit := hostrun.MaxDurableResultLimit
	doc := jsonDoc(limit - 1)
	exit := runDurableDoc(t, cfg, execID, doc, "")
	want := sha256.Sum256(doc)
	doc = nil
	c := client(t)
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	w := &heapWriter{hashWriter: newHashWriter()}
	r, err := hostrun.CollectStream(context.Background(), c, cfg, execID, exit, limit, w)
	if err != nil {
		t.Fatal(err)
	}
	if r.Class != hostrun.ClassSuccess || r.Truncated || w.n != limit-1 || !bytes.Equal(w.h.Sum(nil), want[:]) {
		t.Fatalf("%+v, writer got %d bytes", r, w.n)
	}
	// The document arrives in pieces, not as one buffer.
	if w.maxWrite >= 1<<20 {
		t.Fatalf("largest write %d bytes", w.maxWrite)
	}
	// And hostrun does not keep it: the heap stays far below its size.
	t.Logf("heap %d -> peak %d bytes over %d writes", before.HeapAlloc, w.peak, w.calls)
	if w.calls < 16 || w.peak > before.HeapAlloc+maxStreamHeapGrowth {
		t.Fatalf("heap grew from %d to %d bytes (%d writes)", before.HeapAlloc, w.peak, w.calls)
	}
}

// A result above the limit with a failed exit is the failed exit, as in
// Collect, and still never more than the limit reaches the writer.
func TestDurableResultTruncatedWithNonZeroExit(t *testing.T) {
	f := filepath.Join(t.TempDir(), "big.json")
	if err := os.WriteFile(f, jsonDoc(hostrun.MaxResult+10), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := jobConfig(t)
	exit := runDurableDoc(t, cfg, execID, nil, "cat "+f+"\nexit 4\n")
	w := newHashWriter()
	r, err := hostrun.CollectStream(context.Background(), client(t), cfg, execID, exit, 0, w)
	if err != nil {
		t.Fatal(err)
	}
	b, err := hostrun.Collect(context.Background(), client(t), cfg, execID, exit)
	if err != nil {
		t.Fatal(err)
	}
	if exit != 4 || !r.Truncated || r.Class != hostrun.ClassScriptFailed || r.Detail != "exit status 4" || r.Class != b.Class || w.n != hostrun.MaxResult {
		t.Fatalf("%+v, Collect %s, writer got %d bytes", r, b.Class, w.n)
	}
}

func TestDurableResultLimitOutOfRangeIsRejected(t *testing.T) {
	cfg := jobConfig(t)
	for _, limit := range []int{hostrun.MaxDurableResultLimit + 1, -1, 1 << 40} {
		w := newHashWriter()
		_, err := hostrun.CollectStream(context.Background(), client(t), cfg, execID, 0, limit, w)
		if !errors.Is(err, hostrun.ErrResultLimit) || w.n != 0 {
			t.Fatalf("limit %d: %v, writer got %d bytes", limit, err, w.n)
		}
	}
}

func TestCollectStreamRejectsBadInput(t *testing.T) {
	cfg := jobConfig(t)
	ctx := context.Background()
	if _, err := hostrun.CollectStream(ctx, client(t), cfg, strings.ToUpper(execID), 0, 0, newHashWriter()); err == nil {
		t.Error("bad execution ID accepted")
	}
	bad := cfg
	bad.JobRoot = "/var/lib/nebula/jobs; reboot"
	if _, err := hostrun.CollectStream(ctx, client(t), bad, execID, 0, 0, newHashWriter()); err == nil {
		t.Error("unsafe job root accepted")
	}
	if _, err := hostrun.CollectStream(ctx, client(t), cfg, execID, 0, 0, nil); err == nil {
		t.Error("nil writer accepted")
	}
}

// CollectStream gives every result the class Collect gives it, with the
// default and with a raised limit; only ClassSuccess is a usable document.
func TestCollectStreamClassifiesLikeCollect(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name, script, class string
	}{
		{"success", "echo '{\"a\":[1,\"x\"]}'\n", hostrun.ClassSuccess},
		{"success number", "echo 42\n", hostrun.ClassSuccess},
		{"empty", "printf ' \\n'\n", hostrun.ClassResultMissing},
		{"nothing", "true\n", hostrun.ClassResultMissing},
		{"vertical tab and form feed", "printf '\\v\\f'\n", hostrun.ClassResultMissing},
		{"no-break space", "printf '\\302\\240\\n'\n", hostrun.ClassResultMissing},
		{"not JSON", "echo hello\n", hostrun.ClassScriptFailed},
		{"two documents", "echo '{}'; echo '{}'\n", hostrun.ClassScriptFailed},
		{"trailing data", "echo '{} x'\n", hostrun.ClassScriptFailed},
		{"cut document", "printf '{\"a\":'\n", hostrun.ClassScriptFailed},
		{"invalid UTF-8", "printf '\"\\377\"'\n", hostrun.ClassScriptFailed},
		{"duplicate member", "echo '{\"exit\":3,\"exit\":0}'\n", hostrun.ClassScriptFailed},
		{"escaped duplicate", "echo '{\"exit\":3,\"\\u0065xit\":0}'\n", hostrun.ClassScriptFailed},
		{"failed", "echo '{}'; exit 4\n", hostrun.ClassScriptFailed},
		{"precheck", "exit 10\n", hostrun.ClassPrecheckFailed},
		{"postcheck", "echo '{}'; exit 11\n", hostrun.ClassPostcheckFailed},
		{"hangup", "exit 129\n", hostrun.ClassScriptInterrupted},
		{"killed", "echo '{}'; exit 137\n", hostrun.ClassScriptInterrupted},
		{"interrupted", "exit 143\n", hostrun.ClassScriptInterrupted},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := jobConfig(t)
			exit := runDurableDoc(t, cfg, execID, nil, "echo log >&2\n"+tc.script)
			c := client(t)
			b, err := hostrun.Collect(ctx, c, cfg, execID, exit)
			if err != nil || b.Class != tc.class {
				t.Fatalf("Collect: %s %s %v, want %s", b.Class, b.Detail, err, tc.class)
			}
			for _, limit := range []int{0, raisedLimit} {
				r, err := hostrun.CollectStream(ctx, c, cfg, execID, exit, limit, newHashWriter())
				if err != nil || r.Class != b.Class || r.Detail != b.Detail || r.ExitCode != exit || string(r.Log) != "log\n" || r.LogTruncated {
					t.Fatalf("limit %d: %+v %v, Collect %s %q", limit, r, err, b.Class, b.Detail)
				}
			}
		})
	}
}

// fifoResult makes the job's result.json a named pipe nobody writes, so a
// read of it hangs until the session is closed.
func fifoResult(t *testing.T, cfg hostrun.JobConfig) {
	t.Helper()
	dir := filepath.Join(cfg.JobRoot, execID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(dir, "result.json"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestCollectStreamStopsOnContextCancel(t *testing.T) {
	cfg := jobConfig(t)
	fifoResult(t, cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := hostrun.CollectStream(ctx, client(t), cfg, execID, 0, raisedLimit, newHashWriter())
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 10*time.Second {
		t.Fatalf("%v after %s", err, time.Since(start))
	}
}

func TestCollectStreamStopsAtTimeout(t *testing.T) {
	cfg := jobConfig(t)
	fifoResult(t, cfg)
	start := time.Now()
	_, err := hostrun.CollectStreamWithin(context.Background(), client(t), cfg, execID, 0, raisedLimit, newHashWriter(), 300*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "did not finish within") || time.Since(start) > 10*time.Second {
		t.Fatalf("%v after %s", err, time.Since(start))
	}
}

// stuckWriter blocks in its first Write until release is closed.
type stuckWriter struct {
	entered, release chan struct{}
	calls            atomic.Int32
}

func (s *stuckWriter) Write(p []byte) (int, error) {
	if s.calls.Add(1) == 1 {
		close(s.entered)
	}
	<-s.release
	return len(p), nil
}

// A writer that blocks does not keep CollectStream from returning on
// cancellation or at the timeout, and gets no further call afterwards.
func TestCollectStreamReturnsWhileWriterBlocks(t *testing.T) {
	for _, viaTimeout := range []bool{false, true} {
		cfg := jobConfig(t)
		exit := runDurableDoc(t, cfg, execID, jsonDoc(raisedLimit), "")
		w := &stuckWriter{entered: make(chan struct{}), release: make(chan struct{})}
		ctx, cancel := context.WithCancel(context.Background())
		timeout := time.Hour
		if viaTimeout {
			timeout = time.Second
		} else {
			go func() {
				<-w.entered
				cancel()
			}()
		}
		start := time.Now()
		_, err := hostrun.CollectStreamWithin(ctx, client(t), cfg, execID, exit, raisedLimit, w, timeout)
		took := time.Since(start)
		cancel()
		close(w.release)
		if err == nil || took > 10*time.Second {
			t.Fatalf("timeout %v: %v after %s", viaTimeout, err, took)
		}
		time.Sleep(100 * time.Millisecond)
		if n := w.calls.Load(); n != 1 {
			t.Fatalf("timeout %v: writer called %d times", viaTimeout, n)
		}
	}
}

type failingWriter struct{ calls int }

var errSink = errors.New("sink full")

func (f *failingWriter) Write(p []byte) (int, error) {
	f.calls++
	return 0, errSink
}

// A writer that fails ends the read with its error; the read still ends
// (the rest is drained up to the limit, never stored).
func TestCollectStreamReportsWriterError(t *testing.T) {
	cfg := jobConfig(t)
	exit := runDurableDoc(t, cfg, execID, jsonDoc(raisedLimit), "")
	w := &failingWriter{}
	_, err := hostrun.CollectStream(context.Background(), client(t), cfg, execID, exit, raisedLimit, w)
	if !errors.Is(err, errSink) || w.calls != 1 {
		t.Fatalf("%v, %d calls", err, w.calls)
	}
}

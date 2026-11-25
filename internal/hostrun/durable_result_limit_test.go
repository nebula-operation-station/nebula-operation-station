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
	"strings"
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

// The whole fim.scan document limit, streamed: a document one byte under
// 128 MiB is complete and never held in memory by hostrun.
func TestDurableResultAtFimScanLimitIsStreamed(t *testing.T) {
	cfg := jobConfig(t)
	limit := hostrun.MaxDurableResultLimit
	doc := jsonDoc(limit - 1)
	exit := runDurableDoc(t, cfg, execID, doc, "")
	want := sha256.Sum256(doc)
	doc = nil
	w := newHashWriter()
	r, err := hostrun.CollectStream(context.Background(), client(t), cfg, execID, exit, limit, w)
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

func TestCollectStreamClassifiesLikeCollect(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name, script, class string
	}{
		{"empty", "printf ' \\n'\n", hostrun.ClassResultMissing},
		{"failed", "echo '{}'; exit 4\n", hostrun.ClassScriptFailed},
		{"precheck", "exit 10\n", hostrun.ClassPrecheckFailed},
		{"interrupted", "exit 143\n", hostrun.ClassScriptInterrupted},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := jobConfig(t)
			exit := runDurableDoc(t, cfg, execID, nil, "echo log >&2\n"+tc.script)
			r, err := hostrun.CollectStream(ctx, client(t), cfg, execID, exit, raisedLimit, newHashWriter())
			if err != nil || r.Class != tc.class || r.ExitCode != exit || string(r.Log) != "log\n" || r.LogTruncated {
				t.Fatalf("%+v %v", r, err)
			}
		})
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

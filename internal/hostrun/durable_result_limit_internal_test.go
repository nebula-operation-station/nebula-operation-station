// SPDX-License-Identifier: AGPL-3.0-or-later

package hostrun

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// collectCheck is what classify decides about a buffered result within
// the limit: blank, and whether it is one valid result document.
func collectCheck(doc []byte) (nonBlank, valid bool) {
	nonBlank = len(bytes.TrimSpace(doc)) > 0
	return nonBlank, nonBlank && utf8.Valid(doc) && oneJSONDocument(doc)
}

// streamCheck feeds doc to a jsonStream in pieces of size n.
func streamCheck(doc []byte, n int) (nonBlank, valid bool) {
	var j jsonStream
	for p := doc; len(p) > 0; {
		k := min(n, len(p))
		j.write(p[:k])
		p = p[k:]
	}
	return j.finish()
}

var streamCorpus = []string{
	``, ` `, "\t\r\n", "\v\f", "\u00a0", "\u0085 \u2003", "\u00a0{}", "\ufeff{}",
	`{}`, `[]`, "{}\n", "\t\r\n{}\n ", `{}x`, `{} {}`, `{"a":1} {"b":2}`, `1 2`, `[1 2]`,
	`{"a":1}`, `{"a":1,"a":2}`, `{"a":1,"\u0061":2}`, `{"":1,"":2}`, `{"a\\b":1,"a\\b":1}`,
	`{"a\nb":1,"a\u000ab":2}`, `{"\/":1,"/":2}`, `{"\b\f\n\r\t\"\\":1,"\u0008\u000c\u000a\u000d\u0009\u0022\u005c":2}`,
	`{"\ud83d\ude00":1,"😀":2}`, `{"\ud800":1,"\ufffd":2}`, `{"\ud800\ud800":1,"\ufffd\ufffd":2}`,
	`{"\udc00\ud83d\ude00":1,"\ufffd😀":2}`, `{"\ud800x":1,"\ufffdx":2}`, `{"\ud800\n":1,"\ufffd\n":2}`,
	`{"\ud800\u0041":1,"\ufffdA":2}`, `{"\ud800\ud83d\ude00":1,"\ufffd😀":2}`, `{"\ud83d":1,"\ude00":2}`,
	`{"\uD83D\uDE00":1,"😀":2}`, `{"€":1,"\u20ac":2}`, `{"€":1,"\u20AC":1,"x":3}`,
	`{"a":{"x":1,"x":2}}`, `[{"a":1,"a":2}]`, `{"a":[1,{"b":null}],"c":"d","e":true,"f":false}`,
	`[1,2]`, `1`, `-0`, `-0.5e+10`, `1E-3`, `12.25e5`, `0.0`, `01`, `1.`, `-`, `-a`, `1e`, `1e+`, `.5`, `+1`,
	` true `, `tru`, `nul`, `null`, `false`, `falsey`, `"x"`, `"\ud800"`, "\"\x01\"", `"\q"`, `"\u12g4"`, `"\u12`,
	"\xff", "\"\xe2\x82\"", "\"\xe2\x82\xac\"", "\"\xed\xa0\x80\"", "\"\xf4\x90\x80\x80\"", "\"\xc0\x80\"",
	"\"\xf0\x9f\x98\x80\"", "\xe2\x82", "{}\xe2", `{"a":}`, `{,}`, `[1,]`, `{"a":1,}`, `{"a" 1}`, `{"a",1}`,
	`{"a":1:2}`, `[`, `]`, `{`, `}`, `{"a"`, `{1:2}`, `["a":1]`, `[}`, `{]`, `"abc`,
}

func TestJSONStreamMatchesCollectCheck(t *testing.T) {
	for _, doc := range streamCorpus {
		wantBlank, wantValid := collectCheck([]byte(doc))
		for _, n := range []int{1, 2, 3, 5, 1 << 20} {
			gotBlank, gotValid := streamCheck([]byte(doc), n)
			if gotBlank != wantBlank || gotValid != wantValid {
				t.Errorf("%q in pieces of %d: nonBlank %v valid %v, Collect: %v %v", doc, n, gotBlank, gotValid, wantBlank, wantValid)
			}
		}
	}
}

func FuzzJSONStreamMatchesCollectCheck(f *testing.F) {
	for i, doc := range streamCorpus {
		f.Add([]byte(doc), uint8(i%7))
	}
	f.Fuzz(func(t *testing.T, doc []byte, split uint8) {
		wantBlank, wantValid := collectCheck(doc)
		gotBlank, gotValid := streamCheck(doc, int(split)+1)
		if gotBlank != wantBlank || gotValid != wantValid {
			t.Fatalf("%q in pieces of %d: nonBlank %v valid %v, Collect: %v %v", doc, int(split)+1, gotBlank, gotValid, wantBlank, wantValid)
		}
	})
}

func TestJSONStreamNestingLimitIsEncodingJSONs(t *testing.T) {
	for _, depth := range []int{maxJSONDepth, maxJSONDepth + 1} {
		doc := []byte(strings.Repeat("[", depth) + strings.Repeat("]", depth))
		_, want := collectCheck(doc)
		if _, got := streamCheck(doc, 4096); got != want || want != (depth <= maxJSONDepth) {
			t.Errorf("depth %d: %v, Collect %v", depth, got, want)
		}
	}
}

func TestJSONStreamRefusesTooManyTopLevelMembers(t *testing.T) {
	var j jsonStream
	j.write([]byte(`{`))
	for i := 0; i < maxTopLevelMembers; i++ {
		if i > 0 {
			j.write([]byte(`,`))
		}
		j.write([]byte(`"` + strings.Repeat("k", 1+i%3) + string(rune('A'+i%26)) + itoa(i) + `":0`))
	}
	if _, valid := j.finishCopy(`}`); !valid {
		t.Fatal("document with maxTopLevelMembers members refused")
	}
	j.write([]byte(`,"one-more":0`))
	if _, valid := j.finishCopy(`}`); valid {
		t.Fatal("document above maxTopLevelMembers accepted")
	}
}

// finishCopy finishes a copy of j after tail, so j can go on.
func (j *jsonStream) finishCopy(tail string) (bool, bool) {
	c := *j
	c.stack = append([]byte(nil), j.stack...)
	c.write([]byte(tail))
	return c.finish()
}

func itoa(i int) string {
	var b []byte
	for {
		b = append([]byte{byte('0' + i%10)}, b...)
		if i /= 10; i == 0 {
			return string(b)
		}
	}
}

// Checking a long string keeps no bytes of it: pieces in the middle of a
// string allocate nothing.
func TestJSONStreamKeepsNoDocumentBytes(t *testing.T) {
	var j jsonStream
	j.write([]byte(`{"k":"`))
	piece := bytes.Repeat([]byte("ab€"), 32<<10/5)
	if n := testing.AllocsPerRun(100, func() { j.write(piece) }); n != 0 {
		t.Fatalf("%v allocations per piece", n)
	}
	j.write([]byte(`"}`))
	if nonBlank, valid := j.finish(); !nonBlank || !valid {
		t.Fatal("long string document refused")
	}
}

func TestStreamReadTimeoutGrowsWithTheLimit(t *testing.T) {
	if got := streamReadTimeout(MaxResult); got != 2*time.Minute {
		t.Fatalf("default limit: %s, want Collect's 2m", got)
	}
	if got := streamReadTimeout(1); got != 2*time.Minute {
		t.Fatalf("small limit: %s", got)
	}
	got := streamReadTimeout(MaxDurableResultLimit)
	if got <= 2*time.Minute || got > 30*time.Minute {
		t.Fatalf("fim.scan limit: %s", got)
	}
	if streamReadTimeout(MaxResult+1<<20) >= got {
		t.Fatal("timeout does not grow with the limit")
	}
}

// blockingWriter blocks in Write until release is closed.
type blockingWriter struct {
	entered chan struct{}
	release chan struct{}
	calls   int
}

func (b *blockingWriter) Write(p []byte) (int, error) {
	b.calls++
	if b.calls == 1 {
		close(b.entered)
	}
	<-b.release
	return len(p), nil
}

// finish never waits for the caller's writer, and once it returned no new
// write reaches the writer.
func TestStreamWriterFinishDoesNotWaitForWriter(t *testing.T) {
	bw := &blockingWriter{entered: make(chan struct{}), release: make(chan struct{})}
	sw := newStreamWriter(bw, 100)
	wrote := make(chan struct{})
	go func() {
		_, _ = sw.Write([]byte(`{"a":`))
		close(wrote)
	}()
	<-bw.entered
	finished := make(chan streamState, 1)
	go func() { finished <- sw.finish() }()
	select {
	case <-finished:
	case <-time.After(5 * time.Second):
		t.Fatal("finish waited for a blocked writer")
	}
	close(bw.release)
	<-wrote
	// A late write from the session after finish is dropped.
	if n, err := sw.Write([]byte(`1}`)); n != 2 || err != nil || bw.calls != 1 {
		t.Fatalf("late write: %d %v, writer called %d times", n, err, bw.calls)
	}
	if st := sw.finish(); st.written != 5 || st.total != 7 {
		t.Fatalf("%+v", st)
	}
}

// liarWriter reports n bytes written whatever it got.
type liarWriter struct{ n int }

func (l liarWriter) Write(p []byte) (int, error) { return l.n, nil }

func TestStreamWriterNeverCountsMoreThanTheChunk(t *testing.T) {
	for _, tc := range []struct {
		n         int
		written   int64
		shortWrit bool
	}{
		{1 << 30, 4, false},
		{-5, 0, true},
		{2, 2, true},
	} {
		sw := newStreamWriter(liarWriter{tc.n}, 4)
		_, _ = sw.Write([]byte(`"abc"`))
		st := sw.finish()
		if st.written != tc.written || st.written > 4 || errors.Is(st.err, io.ErrShortWrite) != tc.shortWrit {
			t.Errorf("writer n %d: %+v", tc.n, st)
		}
	}
}

func TestStreamWriterStopsAtLimitAndOnWriterError(t *testing.T) {
	var got bytes.Buffer
	sw := newStreamWriter(&got, 4)
	_, _ = sw.Write([]byte(`"ab`))
	select {
	case <-sw.stop:
		t.Fatal("stopped within the limit")
	default:
	}
	_, _ = sw.Write([]byte(`cdef"`))
	<-sw.stop
	if st := sw.finish(); got.String() != `"abc` || st.written != 4 || st.total != 8 || st.valid {
		t.Fatalf("%q %+v", got.String(), st)
	}

	errSink := errors.New("sink full")
	sw = newStreamWriter(errWriter{errSink}, 100)
	_, _ = sw.Write([]byte(`{}`))
	<-sw.stop
	if st := sw.finish(); !errors.Is(st.err, errSink) {
		t.Fatalf("%+v", st)
	}
}

type errWriter struct{ err error }

func (e errWriter) Write(p []byte) (int, error) { return 0, e.err }

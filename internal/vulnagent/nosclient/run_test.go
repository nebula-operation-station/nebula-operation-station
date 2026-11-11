// SPDX-License-Identifier: AGPL-3.0-or-later

package nosclient

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
)

func (e *env) started(t *testing.T) (*Client, *Run) {
	t.Helper()
	c := e.client(t)
	snap := e.export(t, c)
	run, err := c.StartRun(context.Background(), snap, startReq())
	if err != nil {
		t.Fatal(err)
	}
	return c, run
}

func TestRunProtocolStartBatchComplete(t *testing.T) {
	e := newEnv(t)
	_, run := e.started(t)
	if run.InventorySnapshotID != "inv-1" || run.Seq < 1 || len(run.ID) != 32 || len(run.Sources) != 2 {
		t.Fatalf("%+v", run)
	}
	for _, v := range run.Sources {
		if v.Status != "accepted" {
			t.Fatalf("source %+v", v)
		}
	}
	res, err := run.Submit(context.Background(), Batch{Seq: 1, Subjects: []BatchSubject{web01Host()},
		Findings: []json.RawMessage{record(t, "CVE-2024-0001")}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Opened != 1 || res.Covered != 1 || res.Duplicate {
		t.Fatalf("%+v", res)
	}
	cr, err := run.Complete(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if cr.RunID != run.ID || cr.Completion == nil || cr.Completion.BatchRejected {
		t.Fatalf("%+v", cr)
	}
	if _, err := run.Submit(context.Background(), Batch{Seq: 2}); !errors.Is(err, ErrRunCompleted) {
		t.Fatalf("batch after complete: %v", err)
	}
	if strings.Contains(e.log.String(), testToken) {
		t.Fatal("token in the server log")
	}
}

func TestStartNamesSourcesWithDatesAndSequences(t *testing.T) {
	e := newEnv(t)
	var got startJSON
	e.setWrap(func(w http.ResponseWriter, r *http.Request, next http.Handler) bool {
		if r.URL.Path == runsPath {
			body := readAll(t, r)
			got = startJSON{}
			if err := json.Unmarshal(body, &got); err != nil {
				t.Error(err)
			}
			r.Body = bodyOf(body)
		}
		return false
	})
	c := e.client(t)
	snap := e.export(t, c)
	seq := int64(42)
	req := startReq()
	req.Sources[1] = SourceSnapshot{SourceID: "kev", SnapshotID: "kev-bundle-42", Integrity: vulnfinding.IntegritySigned,
		DateKind: DateKindProxyPrefix + "debian-tracker", ContentDate: time.Date(2026, 11, 9, 10, 0, 0, 0, time.FixedZone("x", 3600)), Sequence: &seq}
	run, err := c.StartRun(context.Background(), snap, req)
	if err != nil {
		t.Fatal(err)
	}
	if got.InventorySnapshotID != "inv-1" || got.MatcherVersion != "1.4.0" || len(got.Sources) != 2 {
		t.Fatalf("%+v", got)
	}
	k := got.Sources[1]
	if k.ContentDate != "2026-11-09T09:00:00Z" || k.Sequence == nil || *k.Sequence != 42 || k.DateKind != "proxy:debian-tracker" || k.Integrity != "signed" {
		t.Fatalf("%+v", k)
	}
	if run.Sources[1].SourceID != "kev" {
		t.Fatalf("%+v", run.Sources)
	}
	// An undated source carries no content date.
	req = startReq()
	req.Sources[0].DateKind, req.Sources[0].ContentDate = DateKindNone, time.Time{}
	if _, err := c.StartRun(context.Background(), snap, req); err != nil {
		t.Fatal(err)
	}
	if got.Sources[0].ContentDate != "" || got.Sources[0].DateKind != "none" {
		t.Fatalf("%+v", got.Sources[0])
	}
}

func TestStartRefusesMalformedSourceListsBeforeSending(t *testing.T) {
	e := newEnv(t)
	c := e.client(t)
	snap := e.export(t, c)
	mod := func(f func(*StartRequest)) StartRequest { r := startReq(); f(&r); return r }
	neg := int64(-1)
	cases := map[string]StartRequest{
		"no sources":            mod(func(r *StartRequest) { r.Sources = nil }),
		"duplicate source":      mod(func(r *StartRequest) { r.Sources[1].SourceID = r.Sources[0].SourceID }),
		"source id pattern":     mod(func(r *StartRequest) { r.Sources[0].SourceID = "Debian Tracker" }),
		"bad snapshot id":       mod(func(r *StartRequest) { r.Sources[0].SnapshotID = "" }),
		"bad integrity":         mod(func(r *StartRequest) { r.Sources[0].Integrity = "trusted" }),
		"negative sequence":     mod(func(r *StartRequest) { r.Sources[0].Sequence = &neg }),
		"date with kind none":   mod(func(r *StartRequest) { r.Sources[0].DateKind = DateKindNone }),
		"no date for kind data": mod(func(r *StartRequest) { r.Sources[0].ContentDate = time.Time{} }),
		"bad date kind":         mod(func(r *StartRequest) { r.Sources[0].DateKind = "guess" }),
		"bad proxy companion":   mod(func(r *StartRequest) { r.Sources[0].DateKind = "proxy:" }),
		"bad matcher version":   mod(func(r *StartRequest) { r.MatcherVersion = "" }),
	}
	for name, req := range cases {
		if _, err := c.StartRun(context.Background(), snap, req); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := c.StartRun(context.Background(), nil, startReq()); !errors.Is(err, ErrInvalidRequest) {
		t.Errorf("no snapshot: %v", err)
	}
	if e.count(runsPath) != 0 {
		t.Fatalf("%d starts sent", e.count(runsPath))
	}
}

func TestStartRefusesARunBoundToAnotherSnapshot(t *testing.T) {
	e := newEnv(t)
	c := e.client(t)
	snap := e.export(t, c)
	e.setWrap(func(w http.ResponseWriter, r *http.Request, next http.Handler) bool {
		if r.URL.Path != runsPath {
			return false
		}
		fixed(http.StatusCreated, `{"run_id":"0123456789abcdef0123456789abcdef","run_seq":1,"started_at":"2026-11-09T12:00:00Z",`+
			`"inventory_snapshot_id":"inv-other","sources":[],"unknown_sources":[],"unknown_count":0,"omitted_sources":[]}`)(w, r)
		return true
	})
	if _, err := c.StartRun(context.Background(), snap, startReq()); !errors.Is(err, ErrProtocol) {
		t.Fatalf("%v", err)
	}
}

func TestStartIsNotRetriedAfterATransportError(t *testing.T) {
	e := newEnv(t)
	c := e.client(t)
	snap := e.export(t, c)
	e.setWrap(dropOnce(runsPath))
	if _, err := c.StartRun(context.Background(), snap, startReq()); err == nil {
		t.Fatal("dropped start succeeded")
	}
	if n := e.count(runsPath); n != 1 {
		t.Fatalf("start sent %d times", n)
	}
}

func TestStartIsRetriedWhenTheServerSaysNoRunWasCreated(t *testing.T) {
	e := newEnv(t)
	c := e.client(t)
	snap := e.export(t, c)
	var n atomic.Int32
	e.setWrap(func(w http.ResponseWriter, r *http.Request, next http.Handler) bool {
		if r.URL.Path == runsPath && n.Add(1) == 1 {
			fixed(http.StatusServiceUnavailable, `{"error":"inventory unavailable"}`)(w, r)
			return true
		}
		return false
	})
	run, err := c.StartRun(context.Background(), snap, startReq())
	if err != nil || run == nil {
		t.Fatal(err)
	}
	if e.count(runsPath) != 2 {
		t.Fatalf("%d starts", e.count(runsPath))
	}
}

func TestStartReportsASnapshotGoneAsConflict(t *testing.T) {
	e := newEnv(t)
	c := e.client(t)
	snap := e.export(t, c)
	e.inv.set(baseSnapshot("inv-2", 8, t0))
	_, err := c.StartRun(context.Background(), snap, startReq())
	var se *StatusError
	if !errors.Is(err, ErrConflict) || !errors.As(err, &se) || !strings.Contains(se.Message, "export again") {
		t.Fatalf("%v", err)
	}
}

func TestBatchRetriedAfterALostAnswerIsADuplicate(t *testing.T) {
	e := newEnv(t)
	_, run := e.started(t)
	path := runsPath + "/" + run.ID + "/findings"
	e.setWrap(dropOnce(path))
	b := Batch{Seq: 1, Subjects: []BatchSubject{web01Host()}, Findings: []json.RawMessage{record(t, "CVE-2024-0001")}}
	res, err := run.Submit(context.Background(), b)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Duplicate || res.BatchSeq != 1 || e.count(path) != 2 {
		t.Fatalf("%+v after %d requests", res, e.count(path))
	}
	// A later explicit retry with the same content is a duplicate too.
	if res, err := run.Submit(context.Background(), b); err != nil || !res.Duplicate {
		t.Fatalf("%+v %v", res, err)
	}
	cr, err := run.Complete(context.Background())
	if err != nil || cr.Completion.BatchRejected {
		t.Fatalf("%+v %v", cr, err)
	}
}

func TestBatchSeqReusedWithOtherContentIsRefusedBeforeSending(t *testing.T) {
	e := newEnv(t)
	_, run := e.started(t)
	path := runsPath + "/" + run.ID + "/findings"
	if _, err := run.Submit(context.Background(), Batch{Seq: 1, Findings: []json.RawMessage{record(t, "CVE-2024-0001")}}); err != nil {
		t.Fatal(err)
	}
	_, err := run.Submit(context.Background(), Batch{Seq: 1, Findings: []json.RawMessage{record(t, "CVE-2024-0002")}})
	if !errors.Is(err, ErrInvalidRequest) || e.count(path) != 1 {
		t.Fatalf("%v after %d requests", err, e.count(path))
	}
}

func TestBatchConflictFromTheServerIsNotRetried(t *testing.T) {
	e := newEnv(t)
	_, run := e.started(t)
	path := runsPath + "/" + run.ID + "/findings"
	e.setWrap(func(w http.ResponseWriter, r *http.Request, next http.Handler) bool {
		if r.URL.Path == path {
			fixed(http.StatusConflict, `{"error":"batch repeated with a different body"}`)(w, r)
			return true
		}
		return false
	})
	_, err := run.Submit(context.Background(), Batch{Seq: 1})
	if !errors.Is(err, ErrConflict) || e.count(path) != 1 {
		t.Fatalf("%v after %d requests", err, e.count(path))
	}
}

func TestBatchLimitsAreCheckedBeforeSending(t *testing.T) {
	e := newEnv(t)
	_, run := e.started(t)
	path := runsPath + "/" + run.ID + "/findings"
	many := make([]json.RawMessage, MaxFindingsPerBatch+1)
	for i := range many {
		many[i] = json.RawMessage(`{}`)
	}
	huge := json.RawMessage(`{"pad":"` + strings.Repeat("x", MaxBatchBytes) + `"}`)
	subs := make([]BatchSubject, MaxCoveredPerBatch+1)
	cases := map[string]struct {
		b    Batch
		want error
	}{
		"too many findings": {Batch{Seq: 1, Findings: many}, ErrTooLarge},
		"too many subjects": {Batch{Seq: 1, Subjects: subs}, ErrTooLarge},
		"body over 1 MiB":   {Batch{Seq: 1, Findings: []json.RawMessage{huge}}, ErrTooLarge},
		"negative seq":      {Batch{Seq: -1}, ErrInvalidRequest},
		"seq above max":     {Batch{Seq: MaxBatchSeq + 1}, ErrInvalidRequest},
		"finding not obj":   {Batch{Seq: 1, Findings: []json.RawMessage{json.RawMessage(`[1]`)}}, ErrInvalidRequest},
		"finding not json":  {Batch{Seq: 1, Findings: []json.RawMessage{json.RawMessage(`{"a":`)}}, ErrInvalidRequest},
		"finding bad utf8":  {Batch{Seq: 1, Findings: []json.RawMessage{json.RawMessage("{\"a\":\"\xff\"}")}}, ErrInvalidRequest},
	}
	for name, c := range cases {
		if _, err := run.Submit(context.Background(), c.b); !errors.Is(err, c.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if e.count(path) != 0 {
		t.Fatalf("%d batches sent", e.count(path))
	}
}

func TestBatchFindingsPerRunAreBounded(t *testing.T) {
	r := &Run{ID: "r", snap: &Snapshot{byKey: map[string]int{}}, next: map[string]int{}, sent: map[int64][32]byte{}, findings: MaxFindingsPerRun}
	if _, err := r.Submit(context.Background(), Batch{Seq: 9, Findings: []json.RawMessage{json.RawMessage(`{}`)}}); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("%v", err)
	}
}

func TestBatchSubjectPartsAreCheckedAgainstTheRunSnapshot(t *testing.T) {
	e := newEnv(t)
	e.inv.set(bigSnapshot("inv-big"))
	c := e.client(t)
	snap := e.export(t, c)
	run, err := c.StartRun(context.Background(), snap, startReq())
	if err != nil {
		t.Fatal(err)
	}
	path := runsPath + "/" + run.ID + "/findings"
	big, _ := snap.Subject(vulnfinding.SubjectHost, vulnfinding.SubjectRef{ID: "big01"})
	parts := big.BatchSubjects()
	unknown := BatchSubject{Kind: vulnfinding.SubjectHost, Ref: vulnfinding.SubjectRef{ID: "web01"}, Part: 1, LastPart: true}
	badLast := parts[0]
	badLast.LastPart = true
	cases := map[string][]BatchSubject{
		"subject not in snapshot": {unknown},
		"part out of order":       {parts[1]},
		"last_part on non-last":   {badLast},
		"part beyond the export":  {{Kind: big.Kind, Ref: big.Ref, Part: big.Parts + 1, LastPart: true}},
		"part zero":               {{Kind: big.Kind, Ref: big.Ref, Part: 0}},
	}
	for name, subs := range cases {
		if _, err := run.Submit(context.Background(), Batch{Seq: 1, Subjects: subs}); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if e.count(path) != 0 {
		t.Fatalf("%d batches sent", e.count(path))
	}
	// Part 1 only: complete is refused before sending.
	if _, err := run.Submit(context.Background(), Batch{Seq: 1, Subjects: parts[:1]}); err != nil {
		t.Fatal(err)
	}
	_, err = run.Complete(context.Background())
	var ie *IncompleteError
	if !errors.Is(err, ErrIncompleteSubjects) || !errors.As(err, &ie) || ie.Count != 1 || ie.Subjects[0].ID != "big01" {
		t.Fatalf("%v", err)
	}
	if e.count(runsPath+"/"+run.ID+"/complete") != 0 {
		t.Fatal("incomplete run's complete was sent")
	}
	// The remaining parts, with part 1 repeated, complete the subject.
	if _, err := run.Submit(context.Background(), Batch{Seq: 2, Subjects: parts}); err != nil {
		t.Fatal(err)
	}
	cr, err := run.Complete(context.Background())
	if err != nil || cr.Completion.BatchRejected {
		t.Fatalf("%+v %v", cr, err)
	}
}

func TestCompleteRetriedAfterALostAnswerGetsTheSavedCompletion(t *testing.T) {
	e := newEnv(t)
	_, run := e.started(t)
	if _, err := run.Submit(context.Background(), Batch{Seq: 1, Subjects: []BatchSubject{web01Host()},
		Findings: []json.RawMessage{record(t, "CVE-2024-0001")}}); err != nil {
		t.Fatal(err)
	}
	path := runsPath + "/" + run.ID + "/complete"
	e.setWrap(dropOnce(path))
	cr, err := run.Complete(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !cr.Repeat || cr.Completion == nil || e.count(path) != 2 {
		t.Fatalf("%+v after %d requests", cr, e.count(path))
	}
	// Once completed, the run answers from memory.
	if again, err := run.Complete(context.Background()); err != nil || again.RunID != run.ID || e.count(path) != 2 {
		t.Fatalf("%+v %v", again, err)
	}
}

func TestCompleteParsesTheServersIncompleteAnswer(t *testing.T) {
	cfg := fakeServer(t, fixed(http.StatusUnprocessableEntity,
		`{"error":"subjects named without all their parts","incomplete_subjects":[{"id":"big01"}],"incomplete_count":3}`))
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	run := &Run{ID: "0123456789abcdef0123456789abcdef", c: c, snap: &Snapshot{byKey: map[string]int{}}, next: map[string]int{}}
	_, err = run.Complete(context.Background())
	var ie *IncompleteError
	if !errors.As(err, &ie) || ie.Count != 3 || len(ie.Subjects) != 1 {
		t.Fatalf("%v", err)
	}
}

func TestCompleteRefusesAnAnswerForAnotherRun(t *testing.T) {
	cfg := fakeServer(t, fixed(http.StatusOK, `{"run_id":"ffffffffffffffffffffffffffffffff","repeat":false,"completion":{}}`))
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	run := &Run{ID: "0123456789abcdef0123456789abcdef", c: c, snap: &Snapshot{byKey: map[string]int{}}, next: map[string]int{}}
	if _, err := run.Complete(context.Background()); !errors.Is(err, ErrProtocol) {
		t.Fatalf("%v", err)
	}
}

func TestBatchRetriedOnServerUnavailable(t *testing.T) {
	e := newEnv(t)
	_, run := e.started(t)
	path := runsPath + "/" + run.ID + "/findings"
	var n atomic.Int32
	e.setWrap(func(w http.ResponseWriter, r *http.Request, next http.Handler) bool {
		if r.URL.Path == path && n.Add(1) <= 2 {
			fixed(http.StatusServiceUnavailable, `{"error":"findings store unavailable"}`)(w, r)
			return true
		}
		return false
	})
	res, err := run.Submit(context.Background(), Batch{Seq: 1, Subjects: []BatchSubject{web01Host()}})
	if err != nil || res.Covered != 1 || e.count(path) != 3 {
		t.Fatalf("%+v %v after %d", res, err, e.count(path))
	}
}

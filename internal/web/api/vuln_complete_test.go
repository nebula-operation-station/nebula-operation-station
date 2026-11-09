// SPDX-License-Identifier: AGPL-3.0-or-later

package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/serverconfig"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnstore"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/api"
)

// restart replaces the handler by a new one on the same store, as after a
// server restart: every in-memory run state is gone.
func (e *venv) restart(t *testing.T, store api.VulnStore) {
	t.Helper()
	h, err := api.NewVuln(api.VulnOptions{Tokens: []serverconfig.APIToken{vulnToken()}, Inventory: e.inv, Store: store, Sources: vulnSources,
		Log: slog.New(slog.NewJSONHandler(e.log, nil)), Now: e.clk.Now})
	if err != nil {
		t.Fatal(err)
	}
	e.h = h
}

func (e *venv) serve(req *http.Request) resp {
	req.RemoteAddr = hermesAddr
	req.Header.Set("Authorization", "Bearer "+vulnTok)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	return resp{code: rec.Code, body: rec.Body.String(), hdr: rec.Header()}
}

// A retried complete after a restart (or after the run state was evicted)
// gets the completion the store saved, not 409.
func TestVulnCompleteRetryAfterRestartReturnsSavedCompletion(t *testing.T) {
	e := newVulnEnv(t)
	run := e.start(t)
	if r := e.batch(t, run, batchBody(t, 0, []subj{web01(1, true)}, record("CVE-2025-0001"))); r.code != http.StatusOK {
		t.Fatalf("batch: %d %s", r.code, r.body)
	}
	first := e.complete(t, run)
	want := completion(t, first)
	if first.json(t)["repeat"] != false {
		t.Fatalf("first complete marked repeat: %s", first.body)
	}

	e.restart(t, e.st)
	again := e.complete(t, run)
	if got := completion(t, again); !reflect.DeepEqual(got, want) {
		t.Fatalf("completion after restart = %v, want %v", got, want)
	}
	if again.json(t)["repeat"] != true {
		t.Fatalf("retry after restart not marked repeat: %s", again.body)
	}
	// Batches to the completed run are still refused.
	if r := e.batch(t, run, batchBody(t, 1, []subj{web01(1, true)})); r.code != http.StatusConflict {
		t.Fatalf("batch to completed run after restart: %d %s", r.code, r.body)
	}
}

// recordingStore records the context Complete ran under.
type recordingStore struct {
	*vulnstore.Store
	mu       sync.Mutex
	ctxErr   error
	deadline time.Duration
	hasDL    bool
}

func (s *recordingStore) Complete(ctx context.Context, runID string) (vulnstore.Completion, error) {
	s.mu.Lock()
	s.ctxErr = ctx.Err()
	dl, ok := ctx.Deadline()
	s.hasDL, s.deadline = ok, time.Until(dl)
	s.mu.Unlock()
	return s.Store.Complete(ctx, runID)
}

// complete runs under its own budget, larger than the per-request call
// timeout, and is not cancelled when the client goes away: the client's
// retry then finds the completion saved.
func TestVulnCompleteRunsUnderItsOwnBudgetDetachedFromTheClient(t *testing.T) {
	e := newVulnEnv(t)
	rs := &recordingStore{Store: e.st}
	e.restart(t, rs)
	run := e.start(t)
	if r := e.batch(t, run, batchBody(t, 0, []subj{web01(1, true)}, record("CVE-2025-0001"))); r.code != http.StatusOK {
		t.Fatalf("batch: %d %s", r.code, r.body)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // the client already gave up
	req := httptest.NewRequest(http.MethodPost, "/api/v1/vuln/runs/"+run+"/complete", nil).WithContext(ctx)
	r := e.serve(req)
	if r.code != http.StatusOK {
		t.Fatalf("complete with a cancelled client: %d %s", r.code, r.body)
	}
	rs.mu.Lock()
	defer rs.mu.Unlock()
	if rs.ctxErr != nil {
		t.Fatalf("store saw a cancelled context: %v", rs.ctxErr)
	}
	if !rs.hasDL || rs.deadline < time.Minute {
		t.Fatalf("complete budget = %v (deadline %v), want at least a minute", rs.deadline, rs.hasDL)
	}
	if _, err := e.st.CompletionOf(context.Background(), run, serverconfig.DefaultVulnTokenName); err != nil {
		t.Fatalf("completion not saved: %v", err)
	}
}

// resumingStore stands for a store whose first complete stopped after
// part of its closures committed: that Complete fails, and ResumeComplete
// finishes the run as the store does for a completing run.
type resumingStore struct {
	*vulnstore.Store
	mu       sync.Mutex
	failed   bool
	resumes  int
	resumeOf string
}

func (s *resumingStore) Complete(ctx context.Context, runID string) (vulnstore.Completion, error) {
	s.mu.Lock()
	first := !s.failed
	s.failed = true
	s.mu.Unlock()
	if first {
		return vulnstore.Completion{}, context.DeadlineExceeded
	}
	return s.Store.Complete(ctx, runID)
}

func (s *resumingStore) ResumeComplete(ctx context.Context, runID, tokenID string) (vulnstore.Completion, error) {
	s.mu.Lock()
	s.resumes++
	s.resumeOf = tokenID
	s.mu.Unlock()
	return s.Store.Complete(ctx, runID)
}

// After a restart a retried complete of a run left completing resumes it
// in the store and answers with its completion, not 409.
func TestVulnCompleteRetryAfterRestartResumesACompletingRun(t *testing.T) {
	e := newVulnEnv(t)
	rs := &resumingStore{Store: e.st}
	e.restart(t, rs)
	run := e.start(t)
	if r := e.batch(t, run, batchBody(t, 0, []subj{web01(1, true)}, record("CVE-2025-0001"))); r.code != http.StatusOK {
		t.Fatalf("batch: %d %s", r.code, r.body)
	}
	if r := e.complete(t, run); r.code != http.StatusServiceUnavailable {
		t.Fatalf("interrupted complete: %d %s", r.code, r.body)
	}

	e.restart(t, rs)
	r := e.complete(t, run)
	if r.code != http.StatusOK {
		t.Fatalf("complete after restart: %d %s", r.code, r.body)
	}
	saved, err := e.st.CompletionOf(context.Background(), run, serverconfig.DefaultVulnTokenName)
	if err != nil {
		t.Fatalf("completion not saved: %v", err)
	}
	if got, want := completion(t, r), completionMap(t, saved); !reflect.DeepEqual(got, want) {
		t.Fatalf("resumed completion = %v, want %v", got, want)
	}
	rs.mu.Lock()
	resumes, of := rs.resumes, rs.resumeOf
	rs.mu.Unlock()
	if resumes != 1 || of != serverconfig.DefaultVulnTokenName {
		t.Fatalf("ResumeComplete calls = %d for %q, want 1 for the run's token", resumes, of)
	}
	if !bytes.Contains(e.log.Bytes(), []byte(`"kind":"vuln_run_completed"`)) || !bytes.Contains(e.log.Bytes(), []byte(`"resumed":true`)) {
		t.Fatalf("no audit record of the resumed completion: %s", e.log.String())
	}
	// The next retry gets the saved completion.
	if again := e.complete(t, run); again.code != http.StatusOK || again.json(t)["repeat"] != true {
		t.Fatalf("retry after resume: %d %s", again.code, again.body)
	}
}

// completionMap is c as the API encodes it.
func completionMap(t *testing.T, c vulnstore.Completion) map[string]any {
	t.Helper()
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

type failingBody struct{}

func (failingBody) Read([]byte) (int, error) { return 0, errors.New("connection reset") }

// A body that cannot be read is 400, not 413; only an oversized body is 413.
func TestVulnCompleteBodyErrors(t *testing.T) {
	e := newVulnEnv(t)
	run := e.start(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/vuln/runs/"+run+"/complete", failingBody{})
	if r := e.serve(req); r.code != http.StatusBadRequest {
		t.Fatalf("unreadable body: %d %s", r.code, r.body)
	}
	big := bytes.Repeat([]byte(" "), 1024)
	req = httptest.NewRequest(http.MethodPost, "/api/v1/vuln/runs/"+run+"/complete", bytes.NewReader(big))
	if r := e.serve(req); r.code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body: %d %s", r.code, r.body)
	}
}

// signalReader signals on its first Read and then reads from r.
type signalReader struct {
	once    sync.Once
	reading chan struct{}
	r       io.Reader
}

func (s *signalReader) Read(p []byte) (int, error) {
	s.once.Do(func() { close(s.reading) })
	return s.r.Read(p)
}

// A stalled batch upload does not block other requests: the body is read
// before the batch lock is taken.
func TestVulnSlowBatchUploadDoesNotBlockComplete(t *testing.T) {
	e := newVulnEnv(t)
	slowRun := e.start(t)
	otherRun := e.start(t)

	pr, pw := io.Pipe()
	body := &signalReader{reading: make(chan struct{}), r: pr}
	done := make(chan resp, 1)
	go func() {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/vuln/runs/"+slowRun+"/findings", body)
		done <- e.serve(req)
	}()
	<-body.reading

	completed := make(chan resp, 1)
	go func() { completed <- e.complete(t, otherRun) }()
	select {
	case r := <-completed:
		if r.code != http.StatusOK {
			t.Fatalf("complete: %d %s", r.code, r.body)
		}
	case <-time.After(10 * time.Second):
		pw.CloseWithError(errors.New("test timeout"))
		t.Fatal("complete blocked by a stalled batch upload")
	}

	if _, err := pw.Write(batchBody(t, 0, []subj{web01(1, true)}, record("CVE-2025-0001"))); err != nil {
		t.Fatal(err)
	}
	pw.Close()
	if r := <-done; r.code != http.StatusOK {
		t.Fatalf("slow batch: %d %s", r.code, r.body)
	}
}

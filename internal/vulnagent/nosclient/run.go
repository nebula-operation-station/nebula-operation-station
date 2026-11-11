// SPDX-License-Identifier: AGPL-3.0-or-later

package nosclient

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
)

// Date kinds of a feed source's content date (ADR 0011 D4).
const (
	DateKindData = "data"
	DateKindNone = "none"
	// DateKindProxyPrefix is followed by the companion source ID.
	DateKindProxyPrefix = "proxy:"
)

var (
	sourceIDRe       = regexp.MustCompile(`^[a-z0-9][a-z0-9._:-]{0,63}$`)
	matcherVersionRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.+_-]{0,63}$`)
	runIDRe          = regexp.MustCompile(`^[0-9a-f]{32}$`)
)

var (
	// ErrInvalidRequest: the request breaks a rule the client checks before
	// sending, so it was not sent.
	ErrInvalidRequest = errors.New("invalid request")
	// ErrIncompleteSubjects: the run named subjects without all their
	// parts; the server rejects such a complete (D3).
	ErrIncompleteSubjects = errors.New("subjects named without all their parts")
	// ErrRunCompleted: the run already completed; no more batches.
	ErrRunCompleted = errors.New("run already completed")
)

// SourceSnapshot is one feed source a run names at start (D4, D5).
type SourceSnapshot struct {
	// SourceID is on NOS's fixed source list.
	SourceID   string
	SnapshotID string
	Integrity  vulnfinding.IntegrityMode
	// DateKind is DateKindData, DateKindNone or DateKindProxyPrefix plus
	// the companion source ID.
	DateKind string
	// ContentDate is required unless DateKind is DateKindNone, where it
	// must be zero.
	ContentDate time.Time
	// Sequence is the bundle sequence where the source has one.
	Sequence *int64
}

// StartRequest starts a run.
type StartRequest struct {
	MatcherVersion string
	Sources        []SourceSnapshot
}

type startSourceJSON struct {
	SourceID    string                    `json:"source_id"`
	SnapshotID  string                    `json:"snapshot_id"`
	Integrity   vulnfinding.IntegrityMode `json:"integrity"`
	DateKind    string                    `json:"date_kind"`
	ContentDate string                    `json:"content_date,omitempty"`
	Sequence    *int64                    `json:"sequence,omitempty"`
}

type startJSON struct {
	InventorySnapshotID string            `json:"inventory_snapshot_id"`
	MatcherVersion      string            `json:"matcher_version"`
	Sources             []startSourceJSON `json:"sources"`
}

// SourceVerdict is NOS's judgement of one named source for the run.
type SourceVerdict struct {
	SourceID  string `json:"source_id"`
	Status    string `json:"status"`
	Stale     bool   `json:"stale"`
	Probation bool   `json:"probation"`
}

type startResultJSON struct {
	RunID               string          `json:"run_id"`
	RunSeq              int64           `json:"run_seq"`
	StartedAt           string          `json:"started_at"`
	InventorySnapshotID string          `json:"inventory_snapshot_id"`
	Sources             []SourceVerdict `json:"sources"`
	UnknownSources      []string        `json:"unknown_sources"`
	UnknownCount        int             `json:"unknown_count"`
	OmittedSources      []string        `json:"omitted_sources"`
}

// Run is a started run. Its methods check batches against the snapshot
// the run started on before sending, so a mistake of the agent does not
// get a batch rejected as a whole (which makes the run close nothing).
// A Run is safe for concurrent use; batches are sent one at a time.
type Run struct {
	ID                  string
	Seq                 int64
	StartedAt           time.Time
	InventorySnapshotID string
	Sources             []SourceVerdict
	UnknownSources      []string
	UnknownCount        int
	OmittedSources      []string

	c    *Client
	snap *Snapshot

	mu sync.Mutex
	// next is the highest part of each named subject the server accepted.
	next map[string]int
	// sent is the body hash of each batch_seq sent.
	sent map[int64][32]byte
	// findings counts findings of the accepted batches.
	findings   int
	completion *CompleteResult
}

func validateStart(snap *Snapshot, req StartRequest) error {
	if snap == nil || !snapshotIDRe.MatchString(snap.ID) {
		return errors.New("no exported snapshot")
	}
	if !matcherVersionRe.MatchString(req.MatcherVersion) {
		return errors.New("malformed matcher_version")
	}
	if len(req.Sources) == 0 || len(req.Sources) > MaxRunSources {
		return fmt.Errorf("a run names between 1 and %d sources", MaxRunSources)
	}
	seen := map[string]bool{}
	for i, s := range req.Sources {
		if !utf8.ValidString(s.SourceID) || !sourceIDRe.MatchString(s.SourceID) {
			return fmt.Errorf("sources[%d]: source ID fails the pattern", i)
		}
		if seen[s.SourceID] {
			return fmt.Errorf("sources[%d]: source ID named twice", i)
		}
		seen[s.SourceID] = true
		if !snapshotIDRe.MatchString(s.SnapshotID) {
			return fmt.Errorf("sources[%d]: malformed snapshot_id", i)
		}
		switch s.Integrity {
		case vulnfinding.IntegritySigned, vulnfinding.IntegrityChecksum, vulnfinding.IntegrityNone:
		default:
			return fmt.Errorf("sources[%d]: unknown integrity mode", i)
		}
		if s.Sequence != nil && *s.Sequence < 0 {
			return fmt.Errorf("sources[%d]: negative sequence", i)
		}
		switch {
		case s.DateKind == DateKindNone:
			if !s.ContentDate.IsZero() {
				return fmt.Errorf("sources[%d]: content date with date kind none", i)
			}
			continue
		case s.DateKind == DateKindData:
		case strings.HasPrefix(s.DateKind, DateKindProxyPrefix) && sourceIDRe.MatchString(strings.TrimPrefix(s.DateKind, DateKindProxyPrefix)):
		default:
			return fmt.Errorf("sources[%d]: malformed date kind", i)
		}
		if s.ContentDate.IsZero() {
			return fmt.Errorf("sources[%d]: content date missing", i)
		}
	}
	return nil
}

// StartRun starts a run on snap, the snapshot Export returned. The run
// start is not idempotent, so only answers that say no run was created
// (429, 503) are retried; after a transport error the caller decides
// (an unknown run times out after MaxRunDuration without closures).
func (c *Client) StartRun(ctx context.Context, snap *Snapshot, req StartRequest) (*Run, error) {
	if err := validateStart(snap, req); err != nil {
		return nil, fmt.Errorf("start run: %w: %w", ErrInvalidRequest, err)
	}
	sj := startJSON{InventorySnapshotID: snap.ID, MatcherVersion: req.MatcherVersion}
	for _, s := range req.Sources {
		j := startSourceJSON{SourceID: s.SourceID, SnapshotID: s.SnapshotID, Integrity: s.Integrity, DateKind: s.DateKind, Sequence: s.Sequence}
		if !s.ContentDate.IsZero() {
			j.ContentDate = s.ContentDate.UTC().Format(time.RFC3339)
		}
		sj.Sources = append(sj.Sources, j)
	}
	body, err := json.Marshal(sj)
	if err != nil {
		return nil, fmt.Errorf("start run: encode: %w", err)
	}
	if len(body) > MaxStartBytes {
		return nil, fmt.Errorf("start run: body over %d bytes: %w", MaxStartBytes, ErrTooLarge)
	}
	out, err := c.do(ctx, request{op: "start run", method: http.MethodPost, path: runsPath, body: body, limit: maxResultBytes,
		window: &c.write, retry: retryStart, timeout: requestTimeout, okStatus: http.StatusCreated})
	if err != nil {
		return nil, err
	}
	var res startResultJSON
	if err := decodeJSON("start run", out, &res, false); err != nil {
		return nil, err
	}
	started, err := time.Parse(time.RFC3339, res.StartedAt)
	if err != nil || !runIDRe.MatchString(res.RunID) || res.RunSeq < 1 {
		return nil, fmt.Errorf("start run: malformed run identity: %w", ErrProtocol)
	}
	if res.InventorySnapshotID != snap.ID {
		return nil, fmt.Errorf("start run: run %s is bound to another inventory snapshot: %w", res.RunID, ErrProtocol)
	}
	return &Run{ID: res.RunID, Seq: res.RunSeq, StartedAt: started.UTC(), InventorySnapshotID: res.InventorySnapshotID,
		Sources: res.Sources, UnknownSources: res.UnknownSources, UnknownCount: res.UnknownCount, OmittedSources: res.OmittedSources,
		c: c, snap: snap, next: map[string]int{}, sent: map[int64][32]byte{}}, nil
}

// BatchSubject names one part of a subject a batch covers (D3).
type BatchSubject struct {
	Kind     vulnfinding.SubjectKind `json:"subject_kind"`
	Ref      vulnfinding.SubjectRef  `json:"subject_ref"`
	Part     int                     `json:"part"`
	LastPart bool                    `json:"last_part"`
}

// Batch is one findings batch. Findings are D5 finding records as JSON
// objects; the server validates them.
type Batch struct {
	// Seq is the batch_seq, unique per run; a retry uses the same Seq and
	// the same content.
	Seq      int64
	Subjects []BatchSubject
	Findings []json.RawMessage
}

type batchJSON struct {
	BatchSeq int64             `json:"batch_seq"`
	Subjects []BatchSubject    `json:"subjects"`
	Findings []json.RawMessage `json:"findings"`
}

// RecordRejection is a finding record the server rejected.
type RecordRejection struct {
	Index  int    `json:"index"`
	Key    string `json:"finding_key,omitempty"`
	Reason string `json:"reason"`
}

// BatchResult is the server's answer to a batch.
type BatchResult struct {
	BatchSeq        int64             `json:"batch_seq"`
	Duplicate       bool              `json:"duplicate"`
	Opened          int               `json:"opened"`
	Updated         int               `json:"updated"`
	Reopened        int               `json:"reopened"`
	Superseded      int               `json:"superseded"`
	Rejected        int               `json:"rejected"`
	ClosureRequests int               `json:"closure_requests"`
	Ignored         int               `json:"ignored_changes"`
	NotChecked      int               `json:"not_checked_by_nos"`
	Covered         int               `json:"subjects_covered"`
	NotCoverable    int               `json:"subjects_not_coverable"`
	Rejections      []RecordRejection `json:"rejections"`
}

// encodeBatch checks the batch limits and encodes it.
func encodeBatch(b Batch) ([]byte, error) {
	if b.Seq < 0 || b.Seq > MaxBatchSeq {
		return nil, fmt.Errorf("batch_seq out of range: %w", ErrInvalidRequest)
	}
	if len(b.Findings) > MaxFindingsPerBatch || len(b.Subjects) > MaxCoveredPerBatch {
		return nil, fmt.Errorf("more than %d findings or %d subjects: %w", MaxFindingsPerBatch, MaxCoveredPerBatch, ErrTooLarge)
	}
	for i, f := range b.Findings {
		f = bytes.TrimSpace(f)
		if len(f) == 0 || f[0] != '{' || !utf8.Valid(f) || !json.Valid(f) {
			return nil, fmt.Errorf("finding %d is not a JSON object: %w", i, ErrInvalidRequest)
		}
	}
	bj := batchJSON{BatchSeq: b.Seq, Subjects: b.Subjects, Findings: b.Findings}
	if bj.Subjects == nil {
		bj.Subjects = []BatchSubject{}
	}
	if bj.Findings == nil {
		bj.Findings = []json.RawMessage{}
	}
	body, err := json.Marshal(bj)
	if err != nil {
		return nil, fmt.Errorf("encode batch: %w", err)
	}
	if len(body) > MaxBatchBytes {
		return nil, fmt.Errorf("batch body over %d bytes: %w", MaxBatchBytes, ErrTooLarge)
	}
	return body, nil
}

// checkParts mirrors the server's D3 part check: every subject is in the
// run's snapshot, parts arrive in order, last_part only on the last part.
// It returns the new part positions. The caller holds r.mu.
func (r *Run) checkParts(subs []BatchSubject) (map[string]int, error) {
	next := map[string]int{}
	for i, s := range subs {
		cov, ok := r.snap.Subject(s.Kind, s.Ref)
		if !ok {
			return nil, fmt.Errorf("subjects[%d] is not in the run's inventory snapshot: %w", i, ErrInvalidRequest)
		}
		if s.Part < 1 || s.Part > cov.Parts || s.LastPart != (s.Part == cov.Parts) {
			return nil, fmt.Errorf("subjects[%d]: part or last_part does not match the export: %w", i, ErrInvalidRequest)
		}
		key := subjectKey(s.Kind, s.Ref)
		have, seen := next[key]
		if !seen {
			have = r.next[key]
		}
		switch {
		case s.Part <= have:
			continue
		case s.Part != have+1:
			return nil, fmt.Errorf("subjects[%d]: parts out of order: %w", i, ErrInvalidRequest)
		}
		next[key] = s.Part
	}
	return next, nil
}

// Submit sends one batch. It is retried with the same run ID, batch_seq and
// body after transport errors, 429 and 5xx; the server answers a repeat of
// an accepted batch as a duplicate. Submitting a batch_seq again with other
// content is refused before sending.
func (r *Run) Submit(ctx context.Context, b Batch) (BatchResult, error) {
	body, err := encodeBatch(b)
	if err != nil {
		return BatchResult{}, fmt.Errorf("run %s batch %d: %w", r.ID, b.Seq, err)
	}
	sum := sha256.Sum256(body)
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.completion != nil {
		return BatchResult{}, fmt.Errorf("run %s batch %d: %w", r.ID, b.Seq, ErrRunCompleted)
	}
	prev, repeat := r.sent[b.Seq]
	if repeat && prev != sum {
		return BatchResult{}, fmt.Errorf("run %s batch %d: batch_seq reused with other content: %w", r.ID, b.Seq, ErrInvalidRequest)
	}
	next, err := r.checkParts(b.Subjects)
	if err != nil {
		return BatchResult{}, fmt.Errorf("run %s batch %d: %w", r.ID, b.Seq, err)
	}
	if !repeat && r.findings+len(b.Findings) > MaxFindingsPerRun {
		return BatchResult{}, fmt.Errorf("run %s batch %d: more than %d findings per run: %w", r.ID, b.Seq, MaxFindingsPerRun, ErrTooLarge)
	}
	// Recorded before sending: an attempt may have reached the server, so
	// the seq is taken with this body from now on.
	r.sent[b.Seq] = sum
	op := fmt.Sprintf("run %s batch %d", r.ID, b.Seq)
	out, err := r.c.do(ctx, request{op: op, method: http.MethodPost, path: runsPath + "/" + r.ID + "/findings", body: body,
		limit: maxResultBytes, window: &r.c.write, retry: retryIdempotent, timeout: requestTimeout, okStatus: http.StatusOK})
	if err != nil {
		return BatchResult{}, err
	}
	var res BatchResult
	if err := decodeJSON(op, out, &res, false); err != nil {
		return BatchResult{}, err
	}
	if res.BatchSeq != b.Seq {
		return BatchResult{}, fmt.Errorf("%s: answer for another batch_seq: %w", op, ErrProtocol)
	}
	for k, n := range next {
		if n > r.next[k] {
			r.next[k] = n
		}
	}
	if !repeat {
		r.findings += len(b.Findings)
	}
	return res, nil
}

// Completion reports what completing a run did (vulnstore.Completion).
type Completion struct {
	ClosedEvidenced        int            `json:"closed_evidenced"`
	ClosedUnconfirmed      int            `json:"closed_unconfirmed"`
	Held                   map[string]int `json:"held,omitempty"`
	NotRequested           int            `json:"not_requested"`
	BlockedRejected        int            `json:"blocked_rejected"`
	SubjectsBelowWatermark int            `json:"subjects_below_watermark"`
	Superseded             int            `json:"superseded"`
	BatchRejected          bool           `json:"batch_rejected"`
	RunGuard               bool           `json:"run_guard"`
	WindowGuard            bool           `json:"window_guard"`
}

// CompleteResult is the server's answer to complete.
type CompleteResult struct {
	RunID string `json:"run_id"`
	// Repeat: the run had completed before; this is the saved completion.
	Repeat     bool        `json:"repeat"`
	Completion *Completion `json:"completion"`
}

// IncompleteError is the server's 422 answer to a complete of a run that
// named subjects without all their parts.
type IncompleteError struct {
	Subjects []vulnfinding.SubjectRef `json:"incomplete_subjects"`
	Count    int                      `json:"incomplete_count"`
}

// Error implements error.
func (e *IncompleteError) Error() string {
	return fmt.Sprintf("%d subjects named without all their parts", e.Count)
}

// Unwrap returns ErrIncompleteSubjects.
func (e *IncompleteError) Unwrap() error { return ErrIncompleteSubjects }

// incompleteLocked returns the subjects named without all their parts. The
// caller holds r.mu.
func (r *Run) incompleteLocked() *IncompleteError {
	var e IncompleteError
	for key, n := range r.next {
		cov := r.snap.Subjects[r.snap.byKey[key]]
		if n < cov.Parts {
			e.Count++
			if len(e.Subjects) < 16 {
				e.Subjects = append(e.Subjects, cov.Ref)
			}
		}
	}
	if e.Count == 0 {
		return nil
	}
	return &e
}

// Complete completes the run. It is retried with the same run ID after
// transport errors, 429 and 5xx; the server answers a repeat with the
// saved completion. A run that named a subject without all its parts is
// refused before sending.
func (r *Run) Complete(ctx context.Context) (CompleteResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.completion != nil {
		return *r.completion, nil
	}
	if e := r.incompleteLocked(); e != nil {
		return CompleteResult{}, fmt.Errorf("run %s complete: %w", r.ID, e)
	}
	op := "run " + r.ID + " complete"
	out, err := r.c.do(ctx, request{op: op, method: http.MethodPost, path: runsPath + "/" + r.ID + "/complete", body: []byte("{}"),
		limit: maxResultBytes, window: &r.c.write, retry: retryIdempotent, timeout: completeTimeout, okStatus: http.StatusOK,
		keepStatus: http.StatusUnprocessableEntity})
	var se *StatusError
	if err != nil && errors.As(err, &se) && se.Status == http.StatusUnprocessableEntity && out != nil {
		var ie IncompleteError
		if decodeJSON(op, out, &ie, false) == nil && ie.Count > 0 {
			if len(ie.Subjects) > 16 {
				ie.Subjects = ie.Subjects[:16]
			}
			return CompleteResult{}, fmt.Errorf("%s: %w", op, &ie)
		}
	}
	if err != nil {
		return CompleteResult{}, err
	}
	var res CompleteResult
	if err := decodeJSON(op, out, &res, false); err != nil {
		return CompleteResult{}, err
	}
	if res.RunID != r.ID || res.Completion == nil {
		return CompleteResult{}, fmt.Errorf("%s: answer for another run or without completion: %w", op, ErrProtocol)
	}
	r.completion = &res
	return res, nil
}

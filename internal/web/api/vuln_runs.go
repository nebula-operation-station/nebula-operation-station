// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"time"
	"unicode/utf8"

	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnstore"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnver"
)

// MaxBatchSeq is the highest batch_seq a client may use (exact in a JSON
// double).
const MaxBatchSeq = 1<<53 - 1

// unparsedBatchSeq is the batch_seq, above MaxBatchSeq, under which a
// batch whose envelope could not be read is recorded as rejected; the run
// then closes nothing.
const unparsedBatchSeq = 1 << 62

// runState is what the handler keeps per run: the inventory snapshot it
// started on (for the re-check and the part counts) and the parts of each
// subject the run named so far. It is in memory: after a restart a run
// cannot complete and times out without closures (fail closed).
type runState struct {
	token   string
	started time.Time
	snap    *prepared
	// next is the highest part of each named subject received in order.
	next map[string]int
	// completion is the result of complete, kept for an idempotent retry.
	completion *vulnstore.Completion
}

// Run start JSON (D5).
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

type verdictJSON struct {
	SourceID  string `json:"source_id"`
	Status    string `json:"status"`
	Stale     bool   `json:"stale"`
	Probation bool   `json:"probation"`
}

type startResultJSON struct {
	RunID               string        `json:"run_id"`
	RunSeq              int64         `json:"run_seq"`
	StartedAt           string        `json:"started_at"`
	InventorySnapshotID string        `json:"inventory_snapshot_id"`
	Sources             []verdictJSON `json:"sources"`
	UnknownSources      []string      `json:"unknown_sources"`
	UnknownCount        int           `json:"unknown_count"`
	OmittedSources      []string      `json:"omitted_sources"`
}

// sourceIDRe is the D5 source ID pattern (at most 64 bytes).
var sourceIDRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._:-]{0,63}$`)

func sha256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func (h *VulnHandler) startRun(ctx context.Context, w http.ResponseWriter, r *http.Request, t *token) {
	body, err := readBody(r, maxStartBytes)
	if err != nil {
		h.log.Warn("audit", "kind", "vuln_run_rejected", "token", t.name, "reason", "body", "bytes", len(body))
		writeError(w, http.StatusRequestEntityTooLarge, "run start body too large")
		return
	}
	var req startJSON
	if err := decodeStrict(body, &req); err != nil {
		h.log.Warn("audit", "kind", "vuln_run_rejected", "token", t.name, "reason", reasonOf(err), "bytes", len(body), "sha256", sha256Hex(body))
		writeError(w, http.StatusBadRequest, "malformed run start: "+reasonOf(err))
		return
	}
	// Source IDs are checked here first so that an ID failing the pattern
	// is audited by length and hash only, never verbatim (D5).
	seen := map[string]bool{}
	for i, s := range req.Sources {
		if !utf8.ValidString(s.SourceID) || !sourceIDRe.MatchString(s.SourceID) {
			h.log.Warn("audit", "kind", "vuln_run_rejected", "token", t.name, "reason", "source_id_pattern", "index", i,
				"id_bytes", len(s.SourceID), "id_sha256", sha256Hex([]byte(s.SourceID)))
			writeError(w, http.StatusBadRequest, "malformed run start: a source ID fails the pattern")
			return
		}
		if seen[s.SourceID] {
			h.log.Warn("audit", "kind", "vuln_run_rejected", "token", t.name, "reason", "source_id_repeated", "source", s.SourceID)
			writeError(w, http.StatusBadRequest, "malformed run start: a source ID is named twice")
			return
		}
		seen[s.SourceID] = true
	}
	if len(req.Sources) == 0 || len(req.Sources) > len(h.sources) {
		h.log.Warn("audit", "kind", "vuln_run_rejected", "token", t.name, "reason", "source_count", "count", len(req.Sources))
		writeError(w, http.StatusBadRequest, "malformed run start: the run must name between 1 and the listed number of sources")
		return
	}
	sreq := vulnstore.StartRequest{TokenID: t.name, MatcherVersion: req.MatcherVersion}
	for _, s := range req.Sources {
		rs := vulnstore.RunSource{ID: s.SourceID, SnapshotID: s.SnapshotID, Integrity: s.Integrity, DateKind: s.DateKind, Sequence: s.Sequence}
		if s.ContentDate != "" {
			d, err := time.Parse(time.RFC3339, s.ContentDate)
			if err != nil {
				h.log.Warn("audit", "kind", "vuln_run_rejected", "token", t.name, "reason", "content_date", "source", s.SourceID)
				writeError(w, http.StatusBadRequest, "malformed run start: content_date is not RFC 3339")
				return
			}
			rs.ContentDate = d.UTC()
		}
		sreq.Sources = append(sreq.Sources, rs)
	}
	if !exportSnapshotIDRe.MatchString(req.InventorySnapshotID) {
		h.log.Warn("audit", "kind", "vuln_run_rejected", "token", t.name, "reason", "inventory_snapshot_id")
		writeError(w, http.StatusBadRequest, "malformed run start: inventory_snapshot_id")
		return
	}
	// Generation and time come from NOS's own snapshot, not from Hermes.
	snap, err := h.snapshot(ctx, req.InventorySnapshotID)
	if errors.Is(err, ErrVulnSnapshotGone) {
		h.log.Warn("audit", "kind", "vuln_run_rejected", "token", t.name, "reason", "snapshot_gone")
		writeError(w, http.StatusConflict, "inventory snapshot no longer available; export again")
		return
	}
	if err != nil {
		h.log.Error("vuln run start", "error", err)
		writeError(w, http.StatusServiceUnavailable, "inventory unavailable")
		return
	}
	sreq.InventoryGeneration, sreq.InventoryAt = snap.generation, snap.takenAt
	run, err := h.store.StartRun(ctx, sreq)
	if err != nil {
		code, msg := storeError(err)
		h.log.Warn("audit", "kind", "vuln_run_rejected", "token", t.name, "reason", msg)
		writeError(w, code, msg)
		return
	}
	h.mu.Lock()
	h.pruneRuns()
	h.runs[run.ID] = &runState{token: t.name, started: run.Started, snap: snap, next: map[string]int{}}
	h.mu.Unlock()

	res := startResultJSON{RunID: run.ID, RunSeq: run.Seq, StartedAt: rfc3339(run.Started), InventorySnapshotID: snap.id,
		Sources: []verdictJSON{}, UnknownSources: append([]string{}, run.UnknownSources...), UnknownCount: run.UnknownCount, OmittedSources: []string{}}
	var behind []string
	for _, v := range run.Sources {
		res.Sources = append(res.Sources, verdictJSON{SourceID: v.ID, Status: string(v.Status), Stale: v.Stale, Probation: v.Probation})
		if v.Status == vulnstore.SourceRegressed || v.Status == vulnstore.SourceInvalid {
			behind = append(behind, v.ID+":"+string(v.Status))
		}
	}
	for _, id := range h.sources {
		if !seen[id] {
			res.OmittedSources = append(res.OmittedSources, id)
		}
	}
	h.log.Info("audit", "kind", "vuln_run_started", "token", t.name, "run", run.ID, "run_seq", run.Seq, "snapshot", snap.id,
		"generation", snap.generation, "sources", len(req.Sources), "not_accepted", behind, "omitted", res.OmittedSources)
	if run.UnknownCount > 0 {
		h.log.Warn("audit", "kind", "vuln_run_unknown_sources", "token", t.name, "run", run.ID, "unknown", run.UnknownSources,
			"unknown_count", run.UnknownCount)
	}
	writeJSON(w, http.StatusCreated, res)
}

// pruneRuns drops run states past the run time limit and, above
// maxRunStates, the oldest ones. The caller holds h.mu.
func (h *VulnHandler) pruneRuns() {
	now := h.now()
	for id, s := range h.runs {
		if now.Sub(s.started) > vulnstore.MaxRunDuration {
			delete(h.runs, id)
		}
	}
	for len(h.runs) >= maxRunStates {
		var oldest string
		for id, s := range h.runs {
			if oldest == "" || s.started.Before(h.runs[oldest].started) {
				oldest = id
			}
		}
		delete(h.runs, oldest)
	}
}

// storeError maps a store error to a status and a message that never
// quotes input.
func storeError(err error) (int, string) {
	switch {
	case errors.Is(err, vulnstore.ErrMalformedRun):
		return http.StatusBadRequest, "malformed run start"
	case errors.Is(err, vulnstore.ErrInventoryRegressed):
		return http.StatusConflict, "inventory generation lower than an earlier run's"
	case errors.Is(err, vulnstore.ErrInventoryTooOld):
		return http.StatusConflict, "inventory snapshot too old; export again"
	case errors.Is(err, vulnstore.ErrTooManyRuns):
		return http.StatusTooManyRequests, "too many concurrent runs"
	case errors.Is(err, vulnstore.ErrRunNotFound):
		return http.StatusNotFound, "no such run"
	case errors.Is(err, vulnstore.ErrRunNotRunning):
		return http.StatusConflict, "run is not running"
	case errors.Is(err, vulnstore.ErrRunExpired):
		return http.StatusConflict, "run exceeded its time limit and was aborted"
	case errors.Is(err, vulnstore.ErrBatchConflict):
		return http.StatusConflict, "batch repeated with a different body"
	case errors.Is(err, vulnstore.ErrBatchTooLarge):
		return http.StatusRequestEntityTooLarge, "batch exceeds finding limits"
	case errors.Is(err, vulnstore.ErrInvalidInput):
		return http.StatusBadRequest, "invalid input"
	default:
		return http.StatusServiceUnavailable, "findings store unavailable"
	}
}

func reasonOf(err error) string {
	switch {
	case errors.Is(err, errUnknownJSONField), errors.Is(err, vulnfinding.ErrUnknownField):
		return "unknown field"
	case errors.Is(err, vulnfinding.ErrInvalidUTF8):
		return "invalid UTF-8"
	case errors.Is(err, vulnfinding.ErrTooLarge):
		return "record too large"
	case errors.Is(err, vulnfinding.ErrMissingField):
		return "required field missing"
	case errors.Is(err, vulnfinding.ErrEmptyBasisSources):
		return "empty basis_sources"
	case errors.Is(err, vulnfinding.ErrKernelSourcePackage):
		return "signed or meta kernel source package"
	case errors.Is(err, vulnfinding.ErrCoverageOnly):
		return "coverage-only ecosystem"
	case errors.Is(err, vulnfinding.ErrInconsistent):
		return "inconsistent record"
	case errors.Is(err, vulnfinding.ErrInvalidField):
		return "invalid field"
	default:
		return "malformed JSON"
	}
}

// Batch JSON (D3 parts, D5 records).
type batchSubjectJSON struct {
	SubjectKind vulnfinding.SubjectKind `json:"subject_kind"`
	SubjectRef  vulnfinding.SubjectRef  `json:"subject_ref"`
	Part        int                     `json:"part"`
	LastPart    bool                    `json:"last_part"`
}

type batchJSON struct {
	BatchSeq *int64             `json:"batch_seq"`
	Subjects []batchSubjectJSON `json:"subjects"`
	Findings []json.RawMessage  `json:"findings"`
}

type recordRejectionJSON struct {
	Index  int    `json:"index"`
	Key    string `json:"finding_key,omitempty"`
	Reason string `json:"reason"`
}

type batchResultJSON struct {
	BatchSeq        int64                 `json:"batch_seq"`
	Duplicate       bool                  `json:"duplicate"`
	Opened          int                   `json:"opened"`
	Updated         int                   `json:"updated"`
	Reopened        int                   `json:"reopened"`
	Superseded      int                   `json:"superseded"`
	Rejected        int                   `json:"rejected"`
	ClosureRequests int                   `json:"closure_requests"`
	Ignored         int                   `json:"ignored_changes"`
	NotChecked      int                   `json:"not_checked_by_nos"`
	Covered         int                   `json:"subjects_covered"`
	NotCoverable    int                   `json:"subjects_not_coverable"`
	Rejections      []recordRejectionJSON `json:"rejections"`
}

// rejectWhole records the batch as rejected as a whole (the run then
// closes nothing, D5 precondition 5e), audits it and answers.
func (h *VulnHandler) rejectWhole(ctx context.Context, w http.ResponseWriter, t *token, runID string, seq int64, body []byte, code int, reason string, extra ...any) {
	sum := sha256.Sum256(body)
	if err := h.store.RejectBatch(ctx, runID, seq, sum); err != nil {
		c, msg := storeError(err)
		h.log.Warn("audit", "kind", "vuln_batch_rejected", "token", t.name, "run", runID, "batch_seq", seq, "reason", reason, "store", msg)
		writeError(w, c, msg)
		return
	}
	args := []any{"kind", "vuln_batch_rejected", "token", t.name, "run", runID, "batch_seq", seq, "reason", reason,
		"bytes", len(body), "sha256", hex.EncodeToString(sum[:])}
	h.log.Warn("audit", append(args, extra...)...)
	writeError(w, code, "batch rejected: "+reason)
}

func (h *VulnHandler) submitBatch(ctx context.Context, w http.ResponseWriter, r *http.Request, t *token, runID string) {
	// Batches of one handler are applied one at a time, so the part
	// bookkeeping follows the store's order.
	h.batchMu.Lock()
	defer h.batchMu.Unlock()
	h.mu.Lock()
	st := h.runs[runID]
	h.mu.Unlock()

	body, err := readBody(r, MaxBatchBytes)
	if errors.Is(err, errBodyTooLarge) {
		h.rejectWhole(ctx, w, t, runID, unparsedBatchSeq, body, http.StatusRequestEntityTooLarge, "body over 1 MiB")
		return
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, "could not read the body")
		return
	}
	var b batchJSON
	if err := decodeStrict(body, &b); err != nil {
		h.rejectWhole(ctx, w, t, runID, unparsedBatchSeq, body, http.StatusBadRequest, reasonOf(err))
		return
	}
	if b.BatchSeq == nil || *b.BatchSeq < 0 || *b.BatchSeq > MaxBatchSeq {
		h.rejectWhole(ctx, w, t, runID, unparsedBatchSeq, body, http.StatusBadRequest, "batch_seq missing or out of range")
		return
	}
	seq := *b.BatchSeq
	if len(b.Findings) > vulnstore.MaxFindingsPerBatch || len(b.Subjects) > vulnstore.MaxCoveredPerBatch {
		h.rejectWhole(ctx, w, t, runID, seq, body, http.StatusRequestEntityTooLarge, "too many findings or subjects")
		return
	}
	if st == nil || st.token != t.name {
		// Not a run of this server instance (restart) or of this token:
		// nothing can be checked against its snapshot, so it closes
		// nothing.
		h.rejectWhole(ctx, w, t, runID, seq, body, http.StatusConflict, "run state not held by this server; start a new run")
		return
	}
	if st.completion != nil {
		writeError(w, http.StatusConflict, "run is not running")
		return
	}
	next, covered, notCoverable, bad := h.checkParts(st, b.Subjects)
	if bad != "" {
		h.rejectWhole(ctx, w, t, runID, seq, body, http.StatusUnprocessableEntity, bad)
		return
	}
	res := batchResultJSON{BatchSeq: seq, Rejections: []recordRejectionJSON{}, Covered: len(covered), NotCoverable: notCoverable}
	batch := vulnstore.Batch{Seq: seq, BodySHA256: sha256.Sum256(body), Covered: covered}
	for i, raw := range b.Findings {
		f, err := vulnfinding.ParseRecord(raw)
		if err != nil {
			// Without a valid record NOS has no finding_key to block, so
			// the whole batch is rejected (D5 precondition 5e).
			h.rejectWhole(ctx, w, t, runID, seq, body, http.StatusUnprocessableEntity, "record "+itoa(i)+": "+reasonOf(err), "record", i)
			return
		}
		checked, why := recheck(st.snap, f)
		if why != "" {
			batch.Rejected = append(batch.Rejected, f.Key)
			res.Rejections = append(res.Rejections, recordRejectionJSON{Index: i, Key: f.Key.String(), Reason: why})
			continue
		}
		if !checked {
			res.NotChecked++
		}
		batch.Items = append(batch.Items, vulnstore.Item{Finding: f, NOSChecked: checked})
	}
	out, err := h.store.SubmitBatch(ctx, runID, batch)
	if err != nil {
		code, msg := storeError(err)
		if errors.Is(err, vulnstore.ErrBatchTooLarge) {
			h.rejectWhole(ctx, w, t, runID, seq, body, code, msg)
			return
		}
		h.log.Warn("audit", "kind", "vuln_batch_refused", "token", t.name, "run", runID, "batch_seq", seq, "reason", msg,
			"sha256", hex.EncodeToString(batch.BodySHA256[:]))
		writeError(w, code, msg)
		return
	}
	h.mu.Lock()
	for k, n := range next {
		if n > st.next[k] {
			st.next[k] = n
		}
	}
	h.mu.Unlock()
	res.Duplicate, res.Opened, res.Updated, res.Reopened = out.Duplicate, out.Opened, out.Updated, out.Reopened
	res.Superseded, res.Rejected, res.ClosureRequests, res.Ignored = out.Superseded, out.Rejected, out.ClosureRequests, len(out.Ignored)
	if out.Duplicate {
		res.Rejections, res.NotChecked, res.Covered, res.NotCoverable = []recordRejectionJSON{}, 0, 0, 0
	}
	h.log.Info("audit", "kind", "vuln_batch", "token", t.name, "run", runID, "batch_seq", seq, "duplicate", out.Duplicate,
		"records", len(b.Findings), "opened", out.Opened, "updated", out.Updated, "reopened", out.Reopened, "superseded", out.Superseded,
		"rejected", out.Rejected, "closure_requests", out.ClosureRequests, "ignored", len(out.Ignored), "downgrades", out.Downgrades,
		"covered", len(covered), "sha256", hex.EncodeToString(batch.BodySHA256[:]))
	for _, d := range out.Dropped {
		h.log.Warn("audit", "kind", "vuln_finding_downgrade", "token", t.name, "run", runID, "finding", d.Key, "change", d.Field)
	}
	writeJSON(w, http.StatusOK, res)
}

func itoa(i int) string {
	b, _ := json.Marshal(i)
	return string(b)
}

// checkParts checks the subject parts a batch names against the run's
// snapshot (D3): every subject is in it, parts arrive in order, last_part
// is set exactly on its last part. It returns the new part positions, the
// subjects the batch completes (only those NOS exported as complete are
// covered) and a rejection reason.
func (h *VulnHandler) checkParts(st *runState, subs []batchSubjectJSON) (map[string]int, []vulnstore.Subject, int, string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	next := map[string]int{}
	var covered []vulnstore.Subject
	notCoverable := 0
	for _, s := range subs {
		key := subjectKey(s.SubjectKind, s.SubjectRef)
		idx, ok := st.snap.byKey[key]
		if !ok {
			return nil, nil, 0, "a named subject is not in the run's inventory snapshot"
		}
		parts := st.snap.parts[key]
		if s.Part < 1 || s.Part > parts || s.LastPart != (s.Part == parts) {
			return nil, nil, 0, "a subject part or last_part does not match the export"
		}
		have, seen := next[key]
		if !seen {
			have = st.next[key]
		}
		switch {
		case s.Part <= have:
			// A repeat of a part already received (a retried batch).
			continue
		case s.Part != have+1:
			return nil, nil, 0, "subject parts out of order"
		}
		next[key] = s.Part
		if s.LastPart {
			if st.snap.subjects[idx].coverable {
				covered = append(covered, vulnstore.Subject{Kind: s.SubjectKind, ID: s.SubjectRef.ID, ImageDigest: s.SubjectRef.ImageDigest})
			} else {
				notCoverable++
			}
		}
	}
	return next, covered, notCoverable, ""
}

// recheck is the V5 re-check of one record against the run's inventory
// snapshot (D4): the subject must be in it; for Debian, Ubuntu and Alpine
// records the ecosystem must be the subject's, the reported source version
// must be NOS's source:Version (kernel: the mapped running kernel's) and
// an open record must still be affected (installed < fixed). It returns
// whether NOS could check the record (nos_checked) and, for a rejected
// record, the reason.
func recheck(p *prepared, f vulnfinding.Finding) (bool, string) {
	rec := f.Record
	idx, ok := p.byKey[subjectKey(rec.SubjectKind, rec.SubjectRef)]
	if !ok {
		return false, "subject not in the run's inventory snapshot"
	}
	s := p.subjects[idx]
	scheme, err := vulnver.SchemeForEcosystem(rec.Ecosystem)
	if err != nil || (rec.MatchBasis != vulnfinding.MatchDistroTracker && rec.MatchBasis != vulnfinding.MatchOSVRange) {
		// Language ecosystems, vendor and CPE matches: NOS cannot re-check.
		return false, ""
	}
	if s.head.Ecosystem == "" {
		return false, ""
	}
	if rec.Ecosystem != s.head.Ecosystem {
		return false, "ecosystem is not the subject's"
	}
	src := rec.Component.SourcePackage
	var installed string
	if rec.SubjectKind == vulnfinding.SubjectHost && vulnver.IsKernelSource(src) {
		if s.kernelSource == "" {
			// Kernel version unknown: stored, labelled not re-checked.
			return false, ""
		}
		if src != s.kernelSource {
			return false, "kernel source is not the running kernel's"
		}
		installed = s.kernelVersion
	} else {
		v, ok := s.basis[src]
		if !ok {
			if s.coverable {
				return false, "source package not installed"
			}
			return false, ""
		}
		installed = v
	}
	c, err := vulnver.Compare(scheme, rec.Component.SourceVersion, installed)
	if err != nil {
		return false, "source version does not parse"
	}
	if c != 0 {
		return false, "source version is not NOS's"
	}
	if rec.Fix.State == vulnfinding.FixFixed {
		affected, err := vulnver.Affected(scheme, installed, rec.Fix.Version)
		if err != nil {
			return false, "fixed version does not parse"
		}
		if !affected {
			return false, "installed version is not below the fixed version"
		}
	}
	return true, ""
}

type completeResultJSON struct {
	RunID      string                `json:"run_id"`
	Repeat     bool                  `json:"repeat"`
	Completion *vulnstore.Completion `json:"completion"`
}

func (h *VulnHandler) completeRun(ctx context.Context, w http.ResponseWriter, r *http.Request, t *token, runID string) {
	h.batchMu.Lock()
	defer h.batchMu.Unlock()
	body, err := readBody(r, maxCompleteBytes)
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, "complete takes an empty body or {}")
		return
	}
	if len(body) > 0 {
		var empty struct{}
		if err := decodeStrict(body, &empty); err != nil {
			writeError(w, http.StatusBadRequest, "complete takes an empty body or {}: "+reasonOf(err))
			return
		}
	}
	h.mu.Lock()
	st := h.runs[runID]
	h.mu.Unlock()
	if st == nil || st.token != t.name {
		h.log.Warn("audit", "kind", "vuln_complete_refused", "token", t.name, "run", runID, "reason", "run state not held")
		writeError(w, http.StatusConflict, "run state not held by this server; start a new run")
		return
	}
	if st.completion != nil {
		writeJSON(w, http.StatusOK, completeResultJSON{RunID: runID, Repeat: true, Completion: st.completion})
		return
	}
	// D3: a run that names a subject without all its parts is rejected.
	h.mu.Lock()
	var incomplete []vulnfinding.SubjectRef
	count := 0
	for key, n := range st.next {
		if n < st.snap.parts[key] {
			count++
			if len(incomplete) < maxListedSubjects {
				incomplete = append(incomplete, st.snap.subjects[st.snap.byKey[key]].head.SubjectRef)
			}
		}
	}
	h.mu.Unlock()
	if count > 0 {
		h.log.Warn("audit", "kind", "vuln_complete_refused", "token", t.name, "run", runID, "reason", "incomplete subjects", "count", count)
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": "subjects named without all their parts",
			"incomplete_subjects": incomplete, "incomplete_count": count})
		return
	}
	comp, err := h.store.Complete(ctx, runID)
	if err != nil {
		code, msg := storeError(err)
		h.log.Warn("audit", "kind", "vuln_complete_refused", "token", t.name, "run", runID, "reason", msg)
		writeError(w, code, msg)
		return
	}
	h.mu.Lock()
	st.completion, st.snap = &comp, nil
	h.mu.Unlock()
	h.log.Info("audit", "kind", "vuln_run_completed", "token", t.name, "run", runID, "closed_evidenced", comp.ClosedEvidenced,
		"closed_unconfirmed", comp.ClosedUnconfirmed, "held", comp.Held, "not_requested", comp.NotRequested,
		"blocked_rejected", comp.BlockedRejected, "superseded", comp.Superseded, "batch_rejected", comp.BatchRejected,
		"run_guard", comp.RunGuard, "window_guard", comp.WindowGuard)
	writeJSON(w, http.StatusOK, completeResultJSON{RunID: runID, Completion: &comp})
}

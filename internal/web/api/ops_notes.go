// SPDX-License-Identifier: AGPL-3.0-or-later

package api

// POST /api/v1/ops/notes and POST /api/v1/ops/status (ADR 0016 D7, D14).
// The body is read with a limit before it is parsed, decoded strictly, then
// checked by opsnotes.Validate against a resolver the server builds from
// its own facts for this request. The server attaches its own snapshot of
// the facts; the model's text never provides it.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/opsconfig"
	"github.com/nebula-operation-station/nebula-operation-station/internal/opsfacts"
	"github.com/nebula-operation-station/nebula-operation-station/internal/opsnotes"
)

// opsResolver answers the store's questions from the facts of one request.
// It holds no inventory or catalog of its own.
type opsResolver struct {
	day      string
	external bool
	fleet    string
	groups   map[string]opsfacts.Group
	hosts    map[string]bool
	chunk    func(string) bool
}

var _ opsnotes.Resolver = (*opsResolver)(nil)

// CurrentDigest: a fix ref is a group key; a summary ref is today's day.
func (r *opsResolver) CurrentDigest(kind opsnotes.Kind, ref string) (string, bool) {
	switch kind {
	case opsnotes.KindFix:
		g, ok := r.groups[ref]
		return g.Digest, ok
	case opsnotes.KindSummary:
		return r.fleet, ref == r.day
	}
	return "", false
}

// External reports the stored data class.
func (r *opsResolver) External(string) bool { return r.external }

// Candidates returns the steps the server offered for ref at digest.
func (r *opsResolver) Candidates(ref, digest string) []opsnotes.Candidate {
	g, ok := r.groups[ref]
	if !ok || g.Digest != digest {
		return nil
	}
	out := make([]opsnotes.Candidate, 0, len(g.Projection.Candidates))
	for _, c := range g.Projection.Candidates {
		out = append(out, opsnotes.Candidate{ActionID: c.Action, HostID: c.HostID})
	}
	return out
}

// GroupHost returns the host of a group.
func (r *opsResolver) GroupHost(ref string) (string, bool) {
	g, ok := r.groups[ref]
	return g.Projection.Host.ID, ok
}

// HostExists reports whether the managed host exists.
func (r *opsResolver) HostExists(hostID string) bool { return r.hosts[hostID] }

// ActionFamily returns the family of an allowlisted action.
func (r *opsResolver) ActionFamily(actionID string) (string, bool) {
	return opsfacts.Families(actionID)
}

// DocChunkExists reports whether the chunk is in the documentation index.
func (r *opsResolver) DocChunkExists(chunkID string) bool {
	return r.chunk != nil && r.chunk(chunkID)
}

// buildResolver reads the facts for one request and returns the resolver
// and the snapshot the server stores with a note of the given kind and ref.
func (h *OpsHandler) buildResolver(ctx context.Context, class string) (*opsResolver, map[string]opsfacts.Group, opsfacts.Counts, error) {
	fleet, err := h.opts.Facts.External(ctx)
	if err != nil {
		return nil, nil, opsfacts.Counts{}, err
	}
	hostIDs, err := h.opts.Facts.Hosts(ctx)
	if err != nil {
		return nil, nil, opsfacts.Counts{}, err
	}
	r := &opsResolver{
		day:      h.now().UTC().Format(time.DateOnly),
		external: class != opsconfig.DataClassLab,
		fleet:    fleetDigest(fleet.Fleet),
		groups:   map[string]opsfacts.Group{},
		hosts:    make(map[string]bool, len(hostIDs)),
		chunk:    h.opts.DocChunk,
	}
	for _, id := range hostIDs {
		r.hosts[id] = true
	}
	if r.external {
		return r, r.groups, fleet.Fleet, nil
	}
	groups, err := h.opts.Facts.EligibleGroups(ctx)
	if err != nil {
		return nil, nil, opsfacts.Counts{}, err
	}
	for _, g := range groups {
		r.groups[g.Key] = g
	}
	return r, r.groups, fleet.Fleet, nil
}

// postNote serves POST OpsNotesPath.
func (h *OpsHandler) postNote(ctx context.Context, w http.ResponseWriter, r *http.Request, t *token) {
	body, err := readBody(r, opsnotes.MaxNoteBytes)
	sum := sha256.Sum256(body)
	digest := hex.EncodeToString(sum[:])
	if errors.Is(err, errBodyTooLarge) {
		h.refuseNote(w, t, http.StatusRequestEntityTooLarge, len(body), digest, nil)
		return
	}
	if err != nil {
		h.refuseNote(w, t, http.StatusBadRequest, len(body), digest, nil)
		return
	}
	d, err := opsnotes.Decode(body)
	if err != nil {
		h.refuseNote(w, t, http.StatusBadRequest, len(body), digest, nil)
		return
	}
	row, err := h.opts.Settings.Get(ctx)
	if err != nil {
		h.log.Error("ops api: read settings", "error", err)
		writeError(w, http.StatusBadGateway, "ops agent settings unavailable")
		return
	}
	// While the agent is off (the default, ADR 0016 D12) no note is stored:
	// a stored note would feed the suggestion index. The setting is read on
	// every request, so switching it off takes effect at once.
	if !row.Enabled {
		h.refuseNote(w, t, http.StatusForbidden, len(body), digest, &d)
		return
	}
	// A fix note in class external is refused before any facts are read.
	if row.DataClass != opsconfig.DataClassLab && d.Kind == opsnotes.KindFix {
		h.refuseNote(w, t, http.StatusForbidden, len(body), digest, &d)
		return
	}
	res, groups, fleet, err := h.buildResolver(ctx, row.DataClass)
	if err != nil {
		h.log.Error("ops api: build resolver", "error", err)
		writeError(w, http.StatusBadGateway, "ops facts unavailable")
		return
	}
	snapshot := "{}"
	switch {
	case d.Kind == opsnotes.KindFix:
		if g, ok := groups[d.Ref]; ok {
			if b, err := json.Marshal(g.Projection); err == nil {
				snapshot = string(b)
			}
		}
	case d.Kind == opsnotes.KindSummary:
		if b, err := json.Marshal(fleet); err == nil {
			snapshot = string(b)
		}
	}
	n, created, err := h.opts.Notes.Put(ctx, res, d, snapshot)
	if err != nil {
		status := opsNoteStatus(err)
		if status == http.StatusInternalServerError {
			h.log.Error("ops api: store note", "error", err)
		}
		h.refuseNote(w, t, status, len(body), digest, &d)
		return
	}
	h.log.Info("audit", "kind", "ops_note", "token", t.name, "note_kind", string(d.Kind), "ref", d.Ref,
		"digest", d.Digest, "length", len(body), "sha256", digest, "created", created)
	if created && h.opts.OnNoteAccepted != nil {
		h.opts.OnNoteAccepted(n)
	}
	code := http.StatusOK
	if created {
		code = http.StatusCreated
	}
	writeJSON(w, code, map[string]any{"id": n.ID, "created": created})
}

// refuseNote answers a refused note with status and audits it (ADR 0016
// D14). d is the decoded note, nil when the body did not decode; its kind,
// ref and digest are audited whenever it is set. The text is never logged:
// only the length and the digest of the bytes.
func (h *OpsHandler) refuseNote(w http.ResponseWriter, t *token, status, length int, digest string, d *opsnotes.Draft) {
	attrs := []any{"kind", "ops_note_refused", "token", t.name, "status", status, "length", length, "sha256", digest}
	if d != nil {
		attrs = append(attrs, "note_kind", string(d.Kind), "ref", d.Ref, "digest", d.Digest)
	}
	h.log.Warn("audit", attrs...)
	switch status {
	case http.StatusRequestEntityTooLarge:
		writeError(w, status, "the note is larger than the limit")
	case http.StatusBadRequest:
		writeError(w, status, "the note is malformed")
	case http.StatusForbidden:
		writeError(w, status, "the note is not accepted: the ops agent is off or the data class takes no fix notes")
	case http.StatusConflict:
		writeError(w, status, "a different note exists for this digest")
	case http.StatusTooManyRequests:
		writeError(w, status, "the daily note limit is reached")
	case http.StatusUnprocessableEntity:
		writeError(w, status, "the note does not match the current facts")
	default:
		writeError(w, http.StatusInternalServerError, "the note could not be stored")
	}
}

// opsNoteStatus maps a store or validation error to its answer.
func opsNoteStatus(err error) int {
	switch {
	case errors.Is(err, opsnotes.ErrConflict):
		return http.StatusConflict
	case errors.Is(err, opsnotes.ErrDailyLimit):
		return http.StatusTooManyRequests
	case errors.Is(err, opsnotes.ErrExternalData):
		return http.StatusForbidden
	case errors.Is(err, opsnotes.ErrDecode), errors.Is(err, opsnotes.ErrInvalidText),
		errors.Is(err, opsnotes.ErrURL), errors.Is(err, opsnotes.ErrInvalidField),
		errors.Is(err, opsnotes.ErrMissing), errors.Is(err, opsnotes.ErrFieldNotAllowed),
		errors.Is(err, opsnotes.ErrInvalidKind):
		return http.StatusBadRequest
	case errors.Is(err, opsnotes.ErrLimit), errors.Is(err, opsnotes.ErrUnknownRef),
		errors.Is(err, opsnotes.ErrStaleDigest), errors.Is(err, opsnotes.ErrUnknownAction),
		errors.Is(err, opsnotes.ErrUnknownHost), errors.Is(err, opsnotes.ErrNotAllowlisted),
		errors.Is(err, opsnotes.ErrNotGroupHost), errors.Is(err, opsnotes.ErrNotCandidate),
		errors.Is(err, opsnotes.ErrDuplicateStep), errors.Is(err, opsnotes.ErrUnknownCitation),
		errors.Is(err, opsnotes.ErrInvalidSnapshot):
		return http.StatusUnprocessableEntity
	}
	return http.StatusInternalServerError
}

// opsStatusBody is the agent's last-run report. Refusal reasons come from a
// fixed list; any other text is refused.
type opsStatusBody struct {
	RunAt        string   `json:"run_at"`
	ItemsSeen    int      `json:"items_seen"`
	LLMCalls     int      `json:"llm_calls"`
	Discarded    int      `json:"discarded"`
	NotesWritten int      `json:"notes_written"`
	Refusals     []string `json:"refusals"`
}

// postStatus serves POST OpsStatusPath and keeps the last status in memory
// and in the audit log.
func (h *OpsHandler) postStatus(w http.ResponseWriter, r *http.Request, t *token) {
	body, err := readBody(r, MaxOpsStatusBytes)
	if errors.Is(err, errBodyTooLarge) {
		writeError(w, http.StatusRequestEntityTooLarge, "the status is larger than the limit")
		return
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, "the status is malformed")
		return
	}
	var in opsStatusBody
	if err := decodeStrict(body, &in); err != nil {
		writeError(w, http.StatusBadRequest, "the status is malformed")
		return
	}
	runAt, err := time.Parse(time.RFC3339, in.RunAt)
	if err != nil || !validRunCounts(in) || len(in.Refusals) > MaxOpsRefusals {
		writeError(w, http.StatusBadRequest, "the status is malformed")
		return
	}
	for _, reason := range in.Refusals {
		if !opsRefusalReasons[reason] {
			writeError(w, http.StatusBadRequest, "unknown refusal reason")
			return
		}
	}
	st := &OpsRunStatus{RunAt: runAt.UTC(), ReceivedAt: h.now().UTC(), ItemsSeen: in.ItemsSeen, LLMCalls: in.LLMCalls,
		Discarded: in.Discarded, NotesWritten: in.NotesWritten, Refusals: slices.Clone(in.Refusals)}
	h.mu.Lock()
	h.last = st
	h.mu.Unlock()
	h.log.Info("audit", "kind", "ops_status", "token", t.name, "items_seen", st.ItemsSeen, "llm_calls", st.LLMCalls,
		"discarded", st.Discarded, "notes_written", st.NotesWritten, "refusals", slices.Clone(st.Refusals))
	w.WriteHeader(http.StatusNoContent)
}

// validRunCounts checks every counter against MaxOpsRunCount.
func validRunCounts(in opsStatusBody) bool {
	for _, n := range []int{in.ItemsSeen, in.LLMCalls, in.Discarded, in.NotesWritten} {
		if n < 0 || n > MaxOpsRunCount {
			return false
		}
	}
	return true
}

// LastOpsStatus returns the last status the agent reported, if any.
func (h *OpsHandler) LastOpsStatus() (OpsRunStatus, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.last == nil {
		return OpsRunStatus{}, false
	}
	st := *h.last
	st.Refusals = slices.Clone(h.last.Refusals)
	return st, true
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package ui

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
	"sync"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/opsconfig"
)

// The "Ops-Agent" section of the settings page (ADR 0016 D12) shows and
// changes the ops agent settings with the flow of the vulnerability agent:
// begin returns a challenge bound to the change digest (opsconfig.ChangeDigest),
// commit takes the fresh user-verified assertion and stores the change. The
// row never holds the LLM credential, and the form has no field for one.
// A recovery login pending (or a recovery status that cannot be read)
// refuses every change.

// opsAgentPendingTTL is how long a begun change waits for its assertion.
const opsAgentPendingTTL = 5 * time.Minute

// maxOpsAgentPending bounds the open ops agent challenges kept in memory.
const maxOpsAgentPending = 16

// ErrOpsAgentAssertionRefused: the backend's check of the assertion failed
// (wrong key, wrong user, or an assertion bound to another change digest).
var ErrOpsAgentAssertionRefused = errors.New("security key assertion refused")

// ErrOpsAgentNotMaintainer: the backend's re-check found that the request's
// user is not the maintainer (admin).
var ErrOpsAgentNotMaintainer = errors.New("only the maintainer can change the ops agent settings")

// errOpsRecoveryUnknown: no recovery status source is configured, so the
// recovery state cannot be ruled out and changes are refused.
var errOpsRecoveryUnknown = errors.New("recovery status unavailable")

// OpsAgentChange is a validated change of the ops agent settings. The
// challenge is bound to its Digest.
type OpsAgentChange struct {
	// Settings are the complete new values (opsconfig.Settings.Validate passed).
	Settings opsconfig.Settings
	// BaseVersion is the stored version the admin edited.
	BaseVersion int64
	// URLChanged reports that the base URL differs from the stored one; the
	// admin confirmed it as a security-relevant change.
	URLChanged bool
}

// Digest is the change digest the challenge is bound to: opsconfig.ChangeDigest
// over the complete new settings and the base version.
func (c OpsAgentChange) Digest() ([sha256.Size]byte, error) {
	return opsconfig.ChangeDigest(c.Settings, c.BaseVersion)
}

// OpsAgentSettings is the backend of the "Ops-Agent" section. The server
// implements it over opsconfig.Store, its audit log, the executor's
// BeginLogin/FinishLogin (challenge bound to the user and the digest) and
// the notifier. Commit stores the change through Store.Save (which checks the
// base version and audits in one transaction) and, after a successful
// commit, sends the opsagent.settings_changed event
// (notify.Notifier.NotifyOpsAgentSettingsChanged). The backend re-checks the
// maintainer role and every input rule.
type OpsAgentSettings interface {
	// OpsAgentConfig reads the stored settings row.
	OpsAgentConfig(ctx context.Context) (opsconfig.Row, error)
	// OpsAgentCorePrompt returns the agent's fixed core prompt, shown
	// read-only as text; empty when this build has none.
	OpsAgentCorePrompt() string
	// OpsAgentMaintainer reports whether user is the maintainer (admin).
	OpsAgentMaintainer(ctx context.Context, user string) (bool, error)
	// BeginOpsAgentChange returns a fresh challenge bound to the user and to
	// the change digest.
	BeginOpsAgentChange(ctx context.Context, user string, c OpsAgentChange) (VulnChallenge, error)
	// CommitOpsAgentChange verifies the assertion against the challenge, the
	// user and the change digest, stores the change and audits it.
	// ErrOpsAgentAssertionRefused when the assertion does not verify,
	// opsconfig.ErrStale when the base version is no longer current.
	CommitOpsAgentChange(ctx context.Context, user, challengeID string, c OpsAgentChange, assertion []byte) error
}

// opsAgentView is the "Ops-Agent" section.
type opsAgentView struct {
	// Error is a plain line shown instead of the form when the settings
	// could not be read.
	Error string
	// Maintainer is true for the admin; others see the values read-only.
	Maintainer bool
	// Locked says why changes are refused (recovery pending or unknown);
	// empty when changes are open.
	Locked string
	// Config is the stored settings row.
	Config opsconfig.Row
	// Updated is the <time> element of the last save; empty before.
	Updated template.HTML
	// CorePrompt is the agent's fixed core prompt, rendered as text.
	CorePrompt string
	// MaxBaseURL, MaxModel and MaxInstructions are the field limits.
	MaxBaseURL, MaxModel, MaxInstructions int
	// CanCopy is true when the vulnerability agent's settings could be read;
	// the copy button then carries its URL and model. Copying saves nothing.
	CanCopy            bool
	CopyURL, CopyModel string
}

// opsAgentRecoveryState reports whether a recovery login is pending. An
// error (or a missing status source) means the state is unknown.
func (h *Handler) opsAgentRecoveryState(ctx context.Context) (bool, error) {
	if h.totpStatus == nil {
		return false, errOpsRecoveryUnknown
	}
	st, err := h.totpStatus(ctx)
	if err != nil {
		return false, err
	}
	return st.GetRecoveryPending(), nil
}

// opsAgentChangesOpen answers the refusal when changes are not allowed; it
// reports whether the request may go on.
func (h *Handler) opsAgentChangesOpen(ctx context.Context, w http.ResponseWriter) bool {
	pending, err := h.opsAgentRecoveryState(ctx)
	if err != nil {
		h.log.Error("settings: ops agent recovery status", "error", err)
		writeJSONError(w, http.StatusServiceUnavailable, "the recovery status could not be read; ops agent changes are refused")
		return false
	}
	if pending {
		writeJSONError(w, http.StatusForbidden, "a recovery login is pending: register a security key first; ops agent changes are refused meanwhile")
		return false
	}
	return true
}

// opsAgentSection builds the section; nil without a backend.
func (h *Handler) opsAgentSection(r *http.Request) *opsAgentView {
	if h.opsAgent == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(r.Context(), vulnCallTimeout)
	defer cancel()
	v := &opsAgentView{CorePrompt: h.opsAgent.OpsAgentCorePrompt(), MaxBaseURL: opsconfig.MaxBaseURL,
		MaxModel: opsconfig.MaxModel, MaxInstructions: opsconfig.MaxInstructions}
	row, err := h.opsAgent.OpsAgentConfig(ctx)
	if err != nil {
		h.log.Error("settings: read ops agent settings", "error", err)
		v.Error = "Ops agent settings could not be loaded."
		return v
	}
	v.Config = row
	if !row.UpdatedAt.IsZero() {
		v.Updated = timeTag(row.UpdatedAt)
	}
	if ok, err := h.opsAgent.OpsAgentMaintainer(ctx, webUser(r)); err != nil {
		h.log.Error("settings: ops agent maintainer check", "error", err)
	} else {
		v.Maintainer = ok
	}
	switch pending, err := h.opsAgentRecoveryState(ctx); {
	case err != nil:
		v.Locked = "The recovery status could not be read: ops agent changes are refused."
	case pending:
		v.Locked = "A recovery login is pending: ops agent changes are refused until a new security key is registered."
	}
	if h.vulnAgent != nil {
		if vc, err := h.vulnAgent.VulnAgentConfig(ctx); err == nil {
			v.CanCopy = true
			v.CopyURL = vc.LLMBaseURL
			v.CopyModel = vc.LLMModel
		}
	}
	return v
}

// opsAgentInput is the begin request body. Pointers make a missing field
// an error instead of a silent zero.
type opsAgentInput struct {
	Enabled              *bool   `json:"enabled"`
	BaseURL              *string `json:"base_url"`
	Model                *string `json:"model"`
	AllowPlainHTTP       *bool   `json:"allow_plain_http"`
	DataClass            *string `json:"data_class"`
	OperatorInstructions *string `json:"operator_instructions"`
	Language             *string `json:"language"`
	BaseVersion          *int64  `json:"base_version"`
	ConfirmURLChange     bool    `json:"confirm_url_change"`
}

// validateOpsAgentInput turns the begin input into a change, given the
// stored row, or a rejection. Validation messages from opsconfig never
// quote the values.
func validateOpsAgentInput(in opsAgentInput, cur opsconfig.Row) (OpsAgentChange, error) {
	if in.Enabled == nil || in.BaseURL == nil || in.Model == nil || in.AllowPlainHTTP == nil ||
		in.DataClass == nil || in.OperatorInstructions == nil || in.Language == nil ||
		in.BaseVersion == nil || *in.BaseVersion < 0 {
		return OpsAgentChange{}, vulnInputError("every setting and the loaded version are required")
	}
	c := OpsAgentChange{
		Settings: opsconfig.Settings{Enabled: *in.Enabled, BaseURL: *in.BaseURL, Model: *in.Model,
			AllowPlainHTTP: *in.AllowPlainHTTP, DataClass: *in.DataClass,
			Instructions: *in.OperatorInstructions, Language: *in.Language},
		BaseVersion: *in.BaseVersion,
	}
	if err := c.Settings.Validate(); err != nil {
		return c, vulnInputError("the ops agent settings are invalid (" + err.Error() + ")")
	}
	c.URLChanged = c.Settings.BaseURL != cur.BaseURL
	if c.URLChanged && !in.ConfirmURLChange {
		return c, vulnInputError("changing the base URL is security-relevant (the ops agent sends its prompt to it): confirm the change")
	}
	return c, nil
}

// opsAgentPending is a begun change awaiting its assertion.
type opsAgentPending struct {
	user    string
	change  OpsAgentChange
	expires time.Time
}

// opsAgentPendingTable keeps begun changes by challenge ID.
type opsAgentPendingTable struct {
	mu sync.Mutex
	m  map[string]opsAgentPending
}

func newOpsAgentPendingTable() *opsAgentPendingTable {
	return &opsAgentPendingTable{m: map[string]opsAgentPending{}}
}

// put stores a pending change; false when the table is full of live
// entries. Expired entries are dropped first.
func (t *opsAgentPendingTable) put(id string, p opsAgentPending, now time.Time) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	for k, v := range t.m {
		if !now.Before(v.expires) {
			delete(t.m, k)
		}
	}
	if len(t.m) >= maxOpsAgentPending {
		return false
	}
	t.m[id] = p
	return true
}

// take removes and returns the pending change of user under id. A change
// begun by another user is not returned and stays in place.
func (t *opsAgentPendingTable) take(id, user string, now time.Time) (OpsAgentChange, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	p, ok := t.m[id]
	if !ok || p.user != user {
		return OpsAgentChange{}, false
	}
	delete(t.m, id)
	if !now.Before(p.expires) {
		return OpsAgentChange{}, false
	}
	return p.change, true
}

// opsAgentReady answers 404 without a backend and 403 for anyone but the
// maintainer.
func (h *Handler) opsAgentReady(ctx context.Context, w http.ResponseWriter, r *http.Request) bool {
	if h.opsAgent == nil {
		http.NotFound(w, r)
		return false
	}
	ok, err := h.opsAgent.OpsAgentMaintainer(ctx, webUser(r))
	if err != nil {
		h.log.Error("settings: ops agent maintainer check", "error", err)
		ok = false
	}
	if !ok {
		writeJSONError(w, http.StatusForbidden, "only the maintainer can change the ops agent settings")
		return false
	}
	return true
}

// handleOpsAgentBegin serves POST /settings/ops-agent/begin.
func (h *Handler) handleOpsAgentBegin(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), vulnCallTimeout)
	defer cancel()
	if !h.opsAgentReady(ctx, w, r) {
		return
	}
	var in opsAgentInput
	if !readVulnJSON(w, r, &in) {
		return
	}
	if !h.opsAgentChangesOpen(ctx, w) {
		return
	}
	cur, err := h.opsAgent.OpsAgentConfig(ctx)
	if err != nil {
		h.log.Error("settings: read ops agent settings", "error", err)
		writeJSONError(w, http.StatusBadGateway, "the current settings could not be read")
		return
	}
	c, err := validateOpsAgentInput(in, cur)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	if c.BaseVersion != cur.Version {
		writeJSONError(w, http.StatusConflict, "the settings were changed meanwhile; reload the page")
		return
	}
	user := webUser(r)
	ch, err := h.opsAgent.BeginOpsAgentChange(ctx, user, c)
	if err != nil {
		h.opsAgentError(w, "begin", err)
		return
	}
	if !vulnChallengeIDRe.MatchString(ch.ID) || !json.Valid(ch.Options) {
		h.log.Error("settings: begin ops agent change", "error", "backend returned a malformed challenge")
		writeJSONError(w, http.StatusBadGateway, "security key challenge unavailable")
		return
	}
	now := h.clockNow()
	if !h.opsAgentPending.put(ch.ID, opsAgentPending{user: user, change: c, expires: now.Add(opsAgentPendingTTL)}, now) {
		writeJSONError(w, http.StatusTooManyRequests, "too many changes in progress; try again in a few minutes")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": ch.ID, "options": json.RawMessage(ch.Options)})
}

// handleOpsAgentCommit serves POST /settings/ops-agent/commit.
func (h *Handler) handleOpsAgentCommit(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), vulnCallTimeout)
	defer cancel()
	if !h.opsAgentReady(ctx, w, r) {
		return
	}
	var in struct {
		ID        string          `json:"id"`
		Assertion json.RawMessage `json:"assertion"`
	}
	if !readVulnJSON(w, r, &in) {
		return
	}
	if len(in.Assertion) == 0 || string(in.Assertion) == "null" {
		writeJSONError(w, http.StatusForbidden, "a fresh security key assertion is required")
		return
	}
	user := webUser(r)
	if !vulnChallengeIDRe.MatchString(in.ID) {
		writeJSONError(w, http.StatusNotFound, "change not found or expired; start again")
		return
	}
	c, ok := h.opsAgentPending.take(in.ID, user, h.clockNow())
	if !ok {
		writeJSONError(w, http.StatusNotFound, "change not found or expired; start again")
		return
	}
	if !h.opsAgentChangesOpen(ctx, w) {
		return
	}
	if err := h.opsAgent.CommitOpsAgentChange(ctx, user, in.ID, c, in.Assertion); err != nil {
		h.opsAgentError(w, "commit", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"done": true})
}

// opsAgentError maps a backend error to a fixed message.
func (h *Handler) opsAgentError(w http.ResponseWriter, op string, err error) {
	switch {
	case errors.Is(err, ErrOpsAgentAssertionRefused):
		writeJSONError(w, http.StatusForbidden, "the security key assertion was refused")
	case errors.Is(err, ErrOpsAgentNotMaintainer):
		writeJSONError(w, http.StatusForbidden, "only the maintainer can change the ops agent settings")
	case errors.Is(err, opsconfig.ErrStale):
		writeJSONError(w, http.StatusConflict, "the settings were changed meanwhile; reload the page")
	case errors.Is(err, opsconfig.ErrInvalidInput):
		writeJSONError(w, http.StatusBadRequest, "the change was rejected: an input is out of bounds")
	default:
		h.log.Error("settings: "+op+" ops agent change", "error", err)
		writeJSONError(w, http.StatusBadGateway, "the change could not be applied")
	}
}

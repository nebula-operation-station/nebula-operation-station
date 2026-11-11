// SPDX-License-Identifier: AGPL-3.0-or-later

// Settings page and theme handling for the web UI.
//
// The theme is a per-browser preference stored in the nebula_theme cookie.
// The value is validated strictly: anything other than "system", "light" or
// "dark" is treated as "system". The cookie is set only by a POST to
// /settings/appearance (a state-changing request, so the security middleware
// checks its Origin like every other POST).
//
// The "Vulnerability agent – LLM" section (ADR 0011 amendment 1, "LLM
// settings") shows and changes the agent's LLM settings with the two-step
// flow of the vulnerability decisions (vuln_decide.go): only the
// maintainer (admin) may change them, and every change needs a fresh
// WebAuthn assertion that the backend verifies before it stores and
// audits the change (vuln.agent_llm_changed). A changed LLM URL must be
// confirmed explicitly: the agent sends finding context to it.
//
// The "Sign-in and security keys" section lists the WebAuthn credentials
// registered with the executor (read-only RPC) and offers the existing
// /setup registration flow for a further key. Removing a key and TOTP setup
// and removal stay CLI-only; the page only shows the exact commands.
package ui

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
	"strings"
	"sync"
	"time"

	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/version"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnstore"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/auth"
)

// themeCookieName is the cookie that stores the UI theme preference.
const themeCookieName = "nebula_theme"

// themeCookieMaxAge is one year, so the preference persists across sessions.
const themeCookieMaxAge = 365 * 24 * 3600

// themeSystem is the default theme: follow the OS colour scheme.
const themeSystem = "system"

// validTheme reports whether t is an accepted theme value.
func validTheme(t string) bool {
	return t == themeSystem || t == "light" || t == "dark"
}

// themeFromRequest reads the theme from the nebula_theme cookie, defaulting
// to "system" when the cookie is absent or holds an invalid value.
func themeFromRequest(r *http.Request) string {
	c, err := r.Cookie(themeCookieName)
	if err != nil {
		return themeSystem
	}
	if validTheme(c.Value) {
		return c.Value
	}
	return themeSystem
}

// themeSecure reports whether the theme cookie must carry the Secure flag:
// the request is HTTPS, or the configured public origin is https.
func (h *Handler) themeSecure(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	return strings.HasPrefix(h.publicOrigin, "https://")
}

// themeCookie builds the nebula_theme cookie with the deployment's security
// attributes: Path=/, SameSite=Strict, HttpOnly, Secure when the request is
// HTTPS or the public origin is https, and a one-year Max-Age.
func (h *Handler) themeCookie(value string, r *http.Request) *http.Cookie {
	return &http.Cookie{
		Name:     themeCookieName,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   h.themeSecure(r),
		SameSite: http.SameSiteStrictMode,
		MaxAge:   themeCookieMaxAge,
	}
}

// keyView is one row of the security keys table on the settings page.
type keyView struct {
	// Label is the key's label, rendered as text; an em dash when the
	// credential has none.
	Label string
	// AAGUID is the short hex of the authenticator's AAGUID, empty when
	// the authenticator reported none.
	AAGUID string
	// Registered is the <time> element of the registration date.
	Registered template.HTML
	// ShortID is the short credential ID shown in the table.
	ShortID string
	// RemoveCmd is the exact CLI command that removes the key; the UI
	// only shows it, removal stays CLI-only.
	RemoveCmd string
	// Current is true for the key this session used to log in.
	Current bool
}

// totpView is the recovery status of the settings page.
type totpView struct {
	// Configured reports whether a TOTP secret is set up on the executor.
	Configured bool
	// Activated reports whether a code has been confirmed.
	Activated bool
	// RecoveryPending reports whether a recovery login is waiting for a
	// newly registered security key.
	RecoveryPending bool
}

// settingsData is the data of the settings page.
type settingsData struct {
	// Theme is the current theme (system/light/dark); the matching radio
	// is preselected.
	Theme string
	// Version is the build version and commit, shown in the About section.
	Version string
	// KeysError is a plain line shown in the security section when the
	// executor could not be read.
	KeysError string
	// Keys is the table of registered security keys.
	Keys []keyView
	// TOTPError is a plain line shown in the recovery section when the
	// executor could not be read.
	TOTPError string
	// TOTP is the recovery status; nil when TOTPError is set.
	TOTP *totpView
	// Agent is the "Vulnerability agent – LLM" section; nil hides it (no
	// backend configured).
	Agent *vulnAgentView
}

// handleSettingsPage renders the settings page (GET /settings).
func (h *Handler) handleSettingsPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	data := &settingsData{
		Theme:   themeFromRequest(r),
		Version: version.String(),
	}
	if h.securityKeys != nil {
		creds, err := h.securityKeys(r.Context())
		if err != nil {
			h.log.Error("list webauthn credentials", "error", err)
			data.KeysError = "Security keys could not be loaded."
		} else {
			data.Keys = keyViews(creds, currentCredentialID(r))
		}
	}
	if h.totpStatus != nil {
		st, err := h.totpStatus(r.Context())
		if err != nil {
			h.log.Error("get totp status", "error", err)
			data.TOTPError = "Recovery status could not be loaded."
		} else {
			data.TOTP = &totpView{
				Configured:      st.GetConfigured(),
				Activated:       st.GetActivated(),
				RecoveryPending: st.GetRecoveryPending(),
			}
		}
	}
	data.Agent = h.vulnAgentSection(r)
	h.render(w, r, pageData{
		Title:    "Settings",
		Active:   "settings",
		Content:  "settings",
		Scripts:  []string{"webauthn.js", "settings.js"},
		Settings: data,
	})
}

// keyViews converts the executor's credentials into table rows. currentID
// is the credential ID of the request's web session ("" without one); the
// matching row is marked as the current key.
func keyViews(creds []*pb.WebAuthnCredential, currentID string) []keyView {
	views := make([]keyView, 0, len(creds))
	for _, c := range creds {
		label := c.GetLabel()
		if label == "" {
			label = "—"
		}
		var registered template.HTML
		if c.GetCreatedAtUnix() > 0 {
			registered = timeTag(time.Unix(c.GetCreatedAtUnix(), 0))
		}
		views = append(views, keyView{
			Label:      label,
			AAGUID:     aaguidShort(c.GetAaguid()),
			Registered: registered,
			ShortID:    shortCredentialID(c.GetCredentialId()),
			RemoveCmd:  "nebula webauthn remove " + c.GetCredentialId(),
			Current:    currentID != "" && c.GetCredentialId() == currentID,
		})
	}
	return views
}

// aaguidShort returns the first 8 hex characters of an AAGUID (the
// authenticator model), empty when none was reported.
func aaguidShort(aaguid string) string {
	aaguid = strings.ToLower(strings.TrimSpace(aaguid))
	if len(aaguid) < 8 {
		return aaguid
	}
	return aaguid[:8]
}

// shortCredentialID shortens a credential ID for the table: up to 12
// characters are shown in full, longer ones keep the first 8 and the last 4
// characters. The full ID stays in the remove command.
func shortCredentialID(id string) string {
	if len(id) <= 12 {
		return id
	}
	return id[:8] + "…" + id[len(id)-4:]
}

// currentCredentialID returns the credential ID of the request's web
// session, or "" without a session.
func currentCredentialID(r *http.Request) string {
	if s, ok := auth.SessionFrom(r.Context()); ok {
		return s.CredentialID
	}
	return ""
}

// handleSettingsAppearance sets the theme cookie and redirects back to the
// settings page (POST /settings/appearance). The body is JSON with a "theme"
// field (the UI posts it through nebulaWebAuthn.post, like every other
// state-changing request, so the security middleware's Origin check holds).
// An invalid theme value answers 400 without changing the cookie.
func (h *Handler) handleSettingsAppearance(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var in struct {
		Theme string `json:"theme"`
	}
	if !readOpsJSON(w, r, &in) {
		return
	}
	if !validTheme(in.Theme) {
		writeJSONError(w, http.StatusBadRequest, "invalid theme")
		return
	}
	http.SetCookie(w, h.themeCookie(in.Theme, r))
	http.Redirect(w, r, "/settings", http.StatusSeeOther)
}

// VulnAgentChange is a validated change of the vulnerability agent's LLM
// settings. The challenge is bound to its Digest.
type VulnAgentChange struct {
	// Settings are the new values (vulnstore.AgentSettings.Validate
	// passed).
	Settings vulnstore.AgentSettings
	// BaseVersion is the stored version the admin edited.
	BaseVersion int64
	// URLChanged reports that the LLM base URL differs from the stored
	// one; the admin confirmed it as a security-relevant change.
	URLChanged bool
}

// Digest is the SHA-256 the challenge is bound to: every field in a fixed
// JSON encoding.
func (c VulnAgentChange) Digest() string {
	b, _ := json.Marshal(struct {
		Enabled     bool   `json:"llm_enabled"`
		URL         string `json:"llm_base_url"`
		Model       string `json:"llm_model"`
		Operator    string `json:"operator_instructions"`
		Language    string `json:"language"`
		BaseVersion int64  `json:"base_version"`
		URLChanged  bool   `json:"url_changed"`
	}{c.Settings.LLMEnabled, c.Settings.LLMBaseURL, c.Settings.LLMModel, c.Settings.OperatorInstructions,
		c.Settings.Language, c.BaseVersion, c.URLChanged})
	sum := sha256.Sum256(append([]byte("nos-vuln-agent-settings-v1\x00"), b...))
	return hex.EncodeToString(sum[:])
}

// ErrVulnAgentNotMaintainer: the backend's re-check found that the
// request's user is not the maintainer.
var ErrVulnAgentNotMaintainer = errors.New("only the maintainer can change the vulnerability agent settings")

// VulnAgentSettings is the backend of the "Vulnerability agent – LLM"
// section. The server implements it over vulnstore.AgentConfigStore, its
// audit log and the executor's WebAuthn verification; it re-checks the
// maintainer and every input rule.
type VulnAgentSettings interface {
	// VulnAgentConfig reads the stored settings.
	VulnAgentConfig(ctx context.Context) (vulnstore.AgentConfig, error)
	// VulnAgentCorePrompt returns the agent's fixed core prompt, shown
	// read-only as text; empty when this build has none.
	VulnAgentCorePrompt() string
	// VulnMaintainer reports whether user is the maintainer (admin).
	VulnMaintainer(ctx context.Context, user string) (bool, error)
	// BeginVulnAgentChange returns a fresh WebAuthn challenge bound to the
	// change's digest and user.
	BeginVulnAgentChange(ctx context.Context, user string, c VulnAgentChange) (VulnChallenge, error)
	// CommitVulnAgentChange verifies the assertion against the challenge,
	// the user and the change digest, stores the change and audits it
	// (vulnstore.AgentConfigStore.Change). ErrVulnAssertionRefused when
	// the assertion does not verify, vulnstore.ErrAgentConfigConflict when
	// the settings changed meanwhile.
	CommitVulnAgentChange(ctx context.Context, user, challengeID string, c VulnAgentChange, assertion []byte) error
}

// vulnAgentView is the "Vulnerability agent – LLM" section.
type vulnAgentView struct {
	// Error is a plain line shown instead of the form when the settings
	// could not be read.
	Error string
	// Maintainer enables the form; others see the values read-only.
	Maintainer bool
	// Config is the stored settings.
	Config vulnstore.AgentConfig
	// Updated is the <time> element of the last save; empty before.
	Updated template.HTML
	// URLPlaceholder and ModelPlaceholder are shown in the empty fields.
	URLPlaceholder   string
	ModelPlaceholder string
	// CorePrompt is the agent's fixed core prompt, rendered as text.
	CorePrompt string
	// MaxURL, MaxModel and MaxOperator are the field limits.
	MaxURL, MaxModel, MaxOperator int
}

// vulnAgentSection builds the section; nil without a backend.
func (h *Handler) vulnAgentSection(r *http.Request) *vulnAgentView {
	if h.vulnAgent == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(r.Context(), vulnCallTimeout)
	defer cancel()
	v := &vulnAgentView{URLPlaceholder: vulnstore.AgentLLMURLPlaceholder, ModelPlaceholder: vulnstore.DefaultAgentLLMModel,
		CorePrompt: h.vulnAgent.VulnAgentCorePrompt(), MaxURL: vulnstore.MaxAgentLLMURL, MaxModel: vulnstore.MaxAgentLLMModel,
		MaxOperator: vulnstore.MaxAgentOperatorText}
	c, err := h.vulnAgent.VulnAgentConfig(ctx)
	if err != nil {
		h.log.Error("settings: read vulnerability agent settings", "error", err)
		v.Error = "Vulnerability agent settings could not be loaded."
		return v
	}
	v.Config = c
	if !c.UpdatedAt.IsZero() {
		v.Updated = timeTag(c.UpdatedAt)
	}
	v.Maintainer = h.vulnAgentMaintainer(ctx, r)
	return v
}

// vulnAgentMaintainer reports whether the request's user is the
// maintainer; an error counts as no.
func (h *Handler) vulnAgentMaintainer(ctx context.Context, r *http.Request) bool {
	ok, err := h.vulnAgent.VulnMaintainer(ctx, webUser(r))
	if err != nil {
		h.log.Error("settings: maintainer check", "error", err)
		return false
	}
	return ok
}

// vulnAgentInput is the begin request body. Pointers make a missing field
// an error instead of a silent zero.
type vulnAgentInput struct {
	LLMEnabled           *bool   `json:"llm_enabled"`
	LLMBaseURL           *string `json:"llm_base_url"`
	LLMModel             *string `json:"llm_model"`
	OperatorInstructions *string `json:"operator_instructions"`
	Language             *string `json:"language"`
	BaseVersion          *int64  `json:"base_version"`
	ConfirmURLChange     bool    `json:"confirm_url_change"`
}

// vulnAgentInputMessage maps a validation error to a fixed message that
// never quotes the input.
func vulnAgentInputMessage(in vulnstore.AgentSettings) string {
	switch {
	case vulnstore.ValidateAgentLLMURL(in.LLMBaseURL) != nil:
		return "the LLM URL must be an http or https URL with a host, without user name, password, query or fragment, at most 512 bytes"
	case (vulnstore.AgentSettings{LLMModel: in.LLMModel, Language: vulnstore.AgentLanguageDE}).Validate() != nil:
		return "the model must be at most 128 printable ASCII characters without spaces"
	case (vulnstore.AgentSettings{OperatorInstructions: in.OperatorInstructions, Language: vulnstore.AgentLanguageDE}).Validate() != nil:
		return "the operator instructions must be at most 4 KiB of printable UTF-8 (newline and tab allowed)"
	default:
		return "the language must be de or en"
	}
}

// validateVulnAgentInput turns the begin input into a change, given the
// stored settings, or a rejection message.
func validateVulnAgentInput(in vulnAgentInput, cur vulnstore.AgentConfig) (VulnAgentChange, error) {
	if in.LLMEnabled == nil || in.LLMBaseURL == nil || in.LLMModel == nil || in.OperatorInstructions == nil ||
		in.Language == nil || in.BaseVersion == nil || *in.BaseVersion < 0 {
		return VulnAgentChange{}, vulnInputError("every setting and the loaded version are required")
	}
	c := VulnAgentChange{Settings: vulnstore.AgentSettings{LLMEnabled: *in.LLMEnabled, LLMBaseURL: *in.LLMBaseURL,
		LLMModel: *in.LLMModel, OperatorInstructions: *in.OperatorInstructions, Language: *in.Language}, BaseVersion: *in.BaseVersion}
	if err := c.Settings.Validate(); err != nil {
		return c, vulnInputError(vulnAgentInputMessage(c.Settings))
	}
	c.URLChanged = c.Settings.LLMBaseURL != cur.LLMBaseURL
	if c.URLChanged && !in.ConfirmURLChange {
		return c, vulnInputError("changing the LLM URL is security-relevant (the agent sends finding context to it): confirm the change")
	}
	return c, nil
}

// vulnAgentPending is a begun change awaiting its assertion.
type vulnAgentPending struct {
	user    string
	change  VulnAgentChange
	expires time.Time
}

// vulnAgentPendingTable keeps begun changes by challenge ID.
type vulnAgentPendingTable struct {
	mu sync.Mutex
	m  map[string]vulnAgentPending
}

func newVulnAgentPendingTable() *vulnAgentPendingTable {
	return &vulnAgentPendingTable{m: map[string]vulnAgentPending{}}
}

// put stores a pending change; false when the table is full of live
// entries.
func (t *vulnAgentPendingTable) put(id string, p vulnAgentPending, now time.Time) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	for k, v := range t.m {
		if !now.Before(v.expires) {
			delete(t.m, k)
		}
	}
	if len(t.m) >= maxVulnPending {
		return false
	}
	t.m[id] = p
	return true
}

// take removes and returns the pending change of user under id.
func (t *vulnAgentPendingTable) take(id, user string, now time.Time) (VulnAgentChange, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	p, ok := t.m[id]
	if !ok || p.user != user {
		return VulnAgentChange{}, false
	}
	delete(t.m, id)
	if !now.Before(p.expires) {
		return VulnAgentChange{}, false
	}
	return p.change, true
}

// vulnAgentReady answers 404 without a backend and 403 for anyone but the
// maintainer.
func (h *Handler) vulnAgentReady(ctx context.Context, w http.ResponseWriter, r *http.Request) bool {
	if h.vulnAgent == nil {
		http.NotFound(w, r)
		return false
	}
	if !h.vulnAgentMaintainer(ctx, r) {
		writeJSONError(w, http.StatusForbidden, "only the maintainer can change the vulnerability agent settings")
		return false
	}
	return true
}

// handleVulnAgentBegin serves POST /settings/vuln-agent/begin.
func (h *Handler) handleVulnAgentBegin(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), vulnCallTimeout)
	defer cancel()
	if !h.vulnAgentReady(ctx, w, r) {
		return
	}
	var in vulnAgentInput
	if !readVulnJSON(w, r, &in) {
		return
	}
	cur, err := h.vulnAgent.VulnAgentConfig(ctx)
	if err != nil {
		h.log.Error("settings: read vulnerability agent settings", "error", err)
		writeJSONError(w, http.StatusBadGateway, "the current settings could not be read")
		return
	}
	c, err := validateVulnAgentInput(in, cur)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	if c.BaseVersion != cur.Version {
		writeJSONError(w, http.StatusConflict, "the settings were changed meanwhile; reload the page")
		return
	}
	user := webUser(r)
	ch, err := h.vulnAgent.BeginVulnAgentChange(ctx, user, c)
	if err != nil {
		h.vulnAgentError(w, "begin", err)
		return
	}
	if !vulnChallengeIDRe.MatchString(ch.ID) || !json.Valid(ch.Options) {
		h.log.Error("settings: begin vulnerability agent change", "error", "backend returned a malformed challenge")
		writeJSONError(w, http.StatusBadGateway, "security key challenge unavailable")
		return
	}
	now := h.clockNow()
	if !h.vulnAgentPending.put(ch.ID, vulnAgentPending{user: user, change: c, expires: now.Add(vulnPendingTTL)}, now) {
		writeJSONError(w, http.StatusTooManyRequests, "too many changes in progress; try again in a few minutes")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": ch.ID, "options": json.RawMessage(ch.Options)})
}

// handleVulnAgentCommit serves POST /settings/vuln-agent/commit.
func (h *Handler) handleVulnAgentCommit(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), vulnCallTimeout)
	defer cancel()
	if !h.vulnAgentReady(ctx, w, r) {
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
	c, ok := h.vulnAgentPending.take(in.ID, user, h.clockNow())
	if !ok {
		writeJSONError(w, http.StatusNotFound, "change not found or expired; start again")
		return
	}
	if err := h.vulnAgent.CommitVulnAgentChange(ctx, user, in.ID, c, in.Assertion); err != nil {
		h.vulnAgentError(w, "commit", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"done": true})
}

// vulnAgentError maps a backend error to a fixed message.
func (h *Handler) vulnAgentError(w http.ResponseWriter, op string, err error) {
	switch {
	case errors.Is(err, ErrVulnAssertionRefused):
		writeJSONError(w, http.StatusForbidden, "the security key assertion was refused")
	case errors.Is(err, ErrVulnAgentNotMaintainer):
		writeJSONError(w, http.StatusForbidden, "only the maintainer can change the vulnerability agent settings")
	case errors.Is(err, vulnstore.ErrAgentConfigConflict):
		writeJSONError(w, http.StatusConflict, "the settings were changed meanwhile; reload the page")
	case errors.Is(err, vulnstore.ErrInvalidInput):
		writeJSONError(w, http.StatusBadRequest, "the change was rejected: an input is out of bounds")
	default:
		h.log.Error("settings: "+op+" vulnerability agent change", "error", err)
		writeJSONError(w, http.StatusBadGateway, "the change could not be applied")
	}
}

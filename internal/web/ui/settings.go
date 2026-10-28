// SPDX-License-Identifier: AGPL-3.0-or-later

// Settings page and theme handling for the web UI.
//
// The theme is a per-browser preference stored in the nebula_theme cookie.
// The value is validated strictly: anything other than "system", "light" or
// "dark" is treated as "system". The cookie is set only by a POST to
// /settings/appearance (a state-changing request, so the security middleware
// checks its Origin like every other POST).
//
// The "Sign-in and security keys" section lists the WebAuthn credentials
// registered with the executor (read-only RPC) and offers the existing
// /setup registration flow for a further key. Removing a key and TOTP setup
// and removal stay CLI-only; the page only shows the exact commands.
package ui

import (
	"html/template"
	"net/http"
	"strings"
	"time"

	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/version"
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

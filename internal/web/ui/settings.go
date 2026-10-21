// SPDX-License-Identifier: AGPL-3.0-or-later

// Settings page and theme handling for the web UI.
//
// The theme is a per-browser preference stored in the nebula_theme cookie.
// The value is validated strictly: anything other than "system", "light" or
// "dark" is treated as "system". The cookie is set only by a POST to
// /settings/appearance (a state-changing request, so the security middleware
// checks its Origin like every other POST).
package ui

import (
	"net/http"
	"strings"

	"github.com/nebula-operation-station/nebula-operation-station/internal/version"
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

// settingsData is the data of the settings page.
type settingsData struct {
	// Theme is the current theme (system/light/dark); the matching radio
	// is preselected.
	Theme string
	// Version is the build version and commit, shown in the About section.
	Version string
}

// handleSettingsPage renders the settings page (GET /settings).
func (h *Handler) handleSettingsPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	h.render(w, r, pageData{
		Title:   "Settings",
		Active:  "settings",
		Content: "settings",
		Scripts: []string{"webauthn.js", "settings.js"},
		Settings: &settingsData{
			Theme:   themeFromRequest(r),
			Version: version.String(),
		},
	})
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

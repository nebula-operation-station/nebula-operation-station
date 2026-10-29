// SPDX-License-Identifier: AGPL-3.0-or-later

// Nav state (sidebar collapse) for the web UI.
//
// The collapse state is a per-browser setting stored in the nebula_nav
// cookie, following the nebula_theme cookie (settings.go): the value is
// validated strictly and anything else is treated as "expanded". The
// cookie is only set through POST /ui/nav — a state-changing request, so
// the security middleware checks its Origin like every other POST.
//
// The server renders the state (see render in ui.go), so the first paint
// is already collapsed or expanded: no client-side flicker.
package ui

import (
	"net/http"
)

const (
	navCookieName = "nebula_nav"
	navCollapsed  = "collapsed"
	navExpanded   = "expanded"
)

func validNavState(s string) bool {
	return s == navCollapsed || s == navExpanded
}

// navStateFromRequest reads the sidebar state from the nebula_nav cookie,
// defaulting to "expanded" when the cookie is absent or invalid.
func navStateFromRequest(r *http.Request) string {
	c, err := r.Cookie(navCookieName)
	if err != nil {
		return navExpanded
	}
	if validNavState(c.Value) {
		return c.Value
	}
	return navExpanded
}

// navCookie builds the nebula_nav cookie with the deployment's security
// attributes (same as the theme cookie).
func (h *Handler) navCookie(value string, r *http.Request) *http.Cookie {
	return &http.Cookie{
		Name:     navCookieName,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   h.themeSecure(r),
		SameSite: http.SameSiteStrictMode,
		MaxAge:   themeCookieMaxAge,
	}
}

// handleNav sets the sidebar state cookie and answers with JSON
// (POST /ui/nav). The body is a JSON object with a "collapsed" boolean
// field; any other shape is rejected.
func (h *Handler) handleNav(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var in struct {
		Collapsed bool `json:"collapsed"`
	}
	if !readOpsJSON(w, r, &in) {
		return
	}
	state := navExpanded
	if in.Collapsed {
		state = navCollapsed
	}
	http.SetCookie(w, h.navCookie(state, r))
	writeJSON(w, http.StatusOK, map[string]string{"state": state})
}

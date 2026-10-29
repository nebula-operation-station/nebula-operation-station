// SPDX-License-Identifier: AGPL-3.0-or-later

// Tests for the sidebar navigation: the Lucide sprite markup, the
// aria-current marking of the active page, the server-rendered collapse
// state from the nebula_nav cookie, and the POST /ui/nav handler.
package ui_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
)

// TestSidebarRendersLucideNavigation checks that every page carries the
// sidebar navigation built from the vendored Lucide sprite: the nav
// landmark, one sprite reference per item, and the collapse control.
func TestSidebarRendersLucideNavigation(t *testing.T) {
	h := newTestHandler(t, ui.Options{PublicOrigin: "https://nebula.example.org"})
	body := getBody(t, h.Handler(), "/dashboard")
	for _, want := range []string{
		`<nav class="sidebar__nav" id="sidebar-nav" aria-label="Main navigation">`,
		`<use href="/static/icons.svg#i-layout-dashboard">`,
		`<use href="/static/icons.svg#i-server">`,
		`<use href="/static/icons.svg#i-globe">`,
		`<use href="/static/icons.svg#i-play">`,
		`<use href="/static/icons.svg#i-book-open">`,
		`<use href="/static/icons.svg#i-history">`,
		`<use href="/static/icons.svg#i-settings">`,
		`<use href="/static/icons.svg#i-orbit">`,
		`id="nav-collapse"`,
		`<use href="/static/icons.svg#i-panel-left-close">`,
		`id="nav-menu"`,
		`id="nav-backdrop"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("GET /dashboard: sidebar missing %s", want)
		}
	}
}

// TestSidebarMarksActivePage checks that the active page carries
// aria-current="page" and the other items do not.
func TestSidebarMarksActivePage(t *testing.T) {
	h := newTestHandler(t, ui.Options{PublicOrigin: "https://nebula.example.org"})
	for _, tc := range []struct {
		path   string
		active string
	}{
		{path: "/dashboard", active: "/dashboard"},
		{path: "/inventory", active: "/inventory"},
		{path: "/settings", active: "/settings"},
	} {
		t.Run(tc.path, func(t *testing.T) {
			body := getBody(t, h.Handler(), tc.path)
			for _, item := range navItems {
				want := item.path == tc.active
				tag := navItemTag(t, body, item.path)
				if has := strings.Contains(tag, `aria-current="page"`); has != want {
					t.Errorf("GET %s: item %s aria-current present=%v, want %v", tc.path, item.path, has, want)
				}
			}
		})
	}
}

// navItemTag returns the attributes of the sidebar item linking to path
// (from href= up to the icon), skipping other links to the same target
// such as the brand link.
func navItemTag(t *testing.T, body, path string) string {
	t.Helper()
	needle := `href="` + path + `"`
	from := 0
	for {
		start := strings.Index(body[from:], needle)
		if start < 0 {
			t.Fatalf("nav item %s not found", path)
		}
		start += from
		lo := start - 80
		if lo < 0 {
			lo = 0
		}
		if strings.Contains(body[lo:start], "sidebar__item") {
			tagEnd := strings.Index(body[start:], "<svg")
			if tagEnd < 0 {
				t.Fatalf("nav item %s has no icon", path)
			}
			return body[start : start+tagEnd]
		}
		from = start + len(needle)
	}
}

// TestSidebarCollapsedFromCookie checks the server-rendered collapse
// state: no or invalid cookie -> expanded, "collapsed" -> the collapsed
// class, the expanded=false toggle state and the title tooltips.
func TestSidebarCollapsedFromCookie(t *testing.T) {
	h := newTestHandler(t, ui.Options{PublicOrigin: "https://nebula.example.org"})
	for _, tc := range []struct {
		name      string
		cookie    string
		collapsed bool
	}{
		{name: "no cookie", cookie: ""},
		{name: "expanded cookie", cookie: "nebula_nav=expanded"},
		{name: "collapsed cookie", cookie: "nebula_nav=collapsed", collapsed: true},
		{name: "invalid cookie", cookie: "nebula_nav=bogus"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := getWithCookie(t, h.Handler(), "/dashboard", tc.cookie)
			hasClass := strings.Contains(body, `class="app app--nav-collapsed"`)
			if hasClass != tc.collapsed {
				t.Errorf("app--nav-collapsed present=%v, want %v", hasClass, tc.collapsed)
			}
			wantExpanded := "false"
			if !tc.collapsed {
				wantExpanded = "true"
			}
			if !strings.Contains(body, `aria-expanded="`+wantExpanded+`" aria-controls="sidebar-nav"`) {
				t.Errorf("nav-collapse aria-expanded, want %q", wantExpanded)
			}
			if tc.collapsed {
				for _, want := range []string{
					`title="Dashboard"`,
					`title="Inventory"`,
					`title="Runbooks / Modules"`,
					`<use href="/static/icons.svg#i-panel-left-open">`,
				} {
					if !strings.Contains(body, want) {
						t.Errorf("collapsed sidebar missing %s", want)
					}
				}
			} else if strings.Contains(body, `title="Dashboard"`) {
				t.Error("expanded sidebar must not carry title tooltips")
			}
		})
	}
}

// TestNavPostSetsStateCookie checks POST /ui/nav: a valid body sets the
// nebula_nav cookie with the deployment's security attributes and
// answers with the new state.
func TestNavPostSetsStateCookie(t *testing.T) {
	h := newTestHandler(t, ui.Options{PublicOrigin: "https://nebula.example.org"})
	for _, tc := range []struct {
		name string
		body string
		want string
	}{
		{name: "collapse", body: `{"collapsed":true}`, want: "collapsed"},
		{name: "expand", body: `{"collapsed":false}`, want: "expanded"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/ui/nav", strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			h.Handler().ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("POST /ui/nav: status %d, want 200", rec.Code)
			}
			var nav *http.Cookie
			for _, c := range rec.Result().Cookies() {
				if c.Name == "nebula_nav" {
					nav = c
				}
			}
			if nav == nil {
				t.Fatal("nebula_nav cookie not set")
			}
			if nav.Value != tc.want {
				t.Errorf("cookie value %q, want %q", nav.Value, tc.want)
			}
			if !nav.HttpOnly || !nav.Secure || nav.SameSite != http.SameSiteStrictMode {
				t.Errorf("cookie attributes: HttpOnly=%v Secure=%v SameSite=%v", nav.HttpOnly, nav.Secure, nav.SameSite)
			}
			if !strings.Contains(rec.Body.String(), fmt.Sprintf(`"state":%q`, tc.want)) {
				t.Errorf("response %q missing state %q", rec.Body.String(), tc.want)
			}
		})
	}
}

// TestNavPostRejectsInvalidBody checks that malformed or wrong-shaped
// bodies are rejected with 400 and do not set the cookie.
func TestNavPostRejectsInvalidBody(t *testing.T) {
	h := newTestHandler(t, ui.Options{PublicOrigin: "https://nebula.example.org"})
	for _, body := range []string{`{`, `{"collapsed":"yes"}`, `{"other":true}`, ``} {
		t.Run(fmt.Sprintf("%q", body), func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/ui/nav", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			h.Handler().ServeHTTP(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("body %q: status %d, want 400", body, rec.Code)
			}
			for _, c := range rec.Result().Cookies() {
				if c.Name == "nebula_nav" {
					t.Errorf("body %q: cookie was set, want none", body)
				}
			}
		})
	}
}

// TestNavPostRejectsOtherMethods checks that GET /ui/nav is refused:
// the route is registered as POST /ui/nav, so other methods do not
// match the pattern (404), the codebase convention for method-scoped
// routes.
func TestNavPostRejectsOtherMethods(t *testing.T) {
	h := newTestHandler(t, ui.Options{PublicOrigin: "https://nebula.example.org"})
	rec := httptest.NewRecorder()
	h.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ui/nav", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("GET /ui/nav: status %d, want 404", rec.Code)
	}
}

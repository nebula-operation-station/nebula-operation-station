// SPDX-License-Identifier: AGPL-3.0-or-later

package ui_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
)

// TestSettingsAppearanceSetsThemeCookie posts a valid theme and checks the
// nebula_theme cookie is set with the deployment's security attributes
// (Path=/, SameSite=Strict, HttpOnly, Secure for an https origin, one-year
// Max-Age) and that the handler redirects back to /settings.
func TestSettingsAppearanceSetsThemeCookie(t *testing.T) {
	h := newTestHandler(t, ui.Options{PublicOrigin: "https://nebula.example.org"})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/settings/appearance", strings.NewReader(`{"theme":"dark"}`))
	req.Header.Set("Content-Type", "application/json")
	h.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("POST /settings/appearance: status %d, want 303", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/settings" {
		t.Errorf("Location %q, want /settings", loc)
	}
	var theme *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == "nebula_theme" {
			theme = c
		}
	}
	if theme == nil {
		t.Fatal("nebula_theme cookie not set")
	}
	if theme.Value != "dark" {
		t.Errorf("cookie value %q, want dark", theme.Value)
	}
	if theme.Path != "/" {
		t.Errorf("cookie Path %q, want /", theme.Path)
	}
	if !theme.HttpOnly {
		t.Error("cookie is not HttpOnly")
	}
	if theme.SameSite != http.SameSiteStrictMode {
		t.Errorf("cookie SameSite %v, want Strict", theme.SameSite)
	}
	if !theme.Secure {
		t.Error("cookie is not Secure although the public origin is https")
	}
	if theme.MaxAge != 365*24*3600 {
		t.Errorf("cookie MaxAge %d, want one year (%d)", theme.MaxAge, 365*24*3600)
	}
}

// TestSettingsAppearanceRejectsInvalidTheme posts unknown theme values and
// checks each answers 400 without setting the cookie.
func TestSettingsAppearanceRejectsInvalidTheme(t *testing.T) {
	h := newTestHandler(t, ui.Options{PublicOrigin: "https://nebula.example.org"})
	for _, theme := range []string{"hacker", "DARK", "dark<script>", "dark light", ""} {
		t.Run(fmt.Sprintf("%q", theme), func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/settings/appearance", strings.NewReader(fmt.Sprintf(`{"theme":%q}`, theme)))
			req.Header.Set("Content-Type", "application/json")
			h.Handler().ServeHTTP(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("theme %q: status %d, want 400", theme, rec.Code)
			}
			for _, c := range rec.Result().Cookies() {
				if c.Name == "nebula_theme" {
					t.Errorf("theme %q: cookie was set, want none", theme)
				}
			}
		})
	}
}

// TestSettingsPageRendersThemeAttribute checks the <html> data-theme attribute
// follows the cookie: absent or invalid -> system, valid -> the value.
func TestSettingsPageRendersThemeAttribute(t *testing.T) {
	h := newTestHandler(t, ui.Options{PublicOrigin: "https://nebula.example.org"})
	for _, tc := range []struct {
		name   string
		cookie string
		want   string
	}{
		{name: "no cookie", cookie: "", want: `data-theme="system"`},
		{name: "dark cookie", cookie: "dark", want: `data-theme="dark"`},
		{name: "light cookie", cookie: "light", want: `data-theme="light"`},
		{name: "invalid cookie", cookie: "bogus", want: `data-theme="system"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/settings", nil)
			if tc.cookie != "" {
				req.AddCookie(&http.Cookie{Name: "nebula_theme", Value: tc.cookie})
			}
			rec := httptest.NewRecorder()
			h.Handler().ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("GET /settings: status %d, want 200", rec.Code)
			}
			if !strings.Contains(rec.Body.String(), tc.want) {
				t.Errorf("missing %s", tc.want)
			}
		})
	}
}

// TestSettingsPageShowsAboutAndTools checks the settings page carries the
// About version and the inventory-tool links.
func TestSettingsPageShowsAboutAndTools(t *testing.T) {
	h := newTestHandler(t, ui.Options{PublicOrigin: "https://nebula.example.org"})
	body := getBody(t, h.Handler(), "/settings")
	for _, want := range []string{"Appearance", "Inventory tools", "About", "/inventory/import", "/inventory/enroll", "/schedules"} {
		if !strings.Contains(body, want) {
			t.Errorf("settings page missing %q", want)
		}
	}
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package ui_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
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

// TestSettingsPageListsSecurityKeys checks the "Sign-in and security keys"
// section lists every registered key (label, short AAGUID hex, the exact
// remove command with the full credential ID) and the recovery section shows
// the TOTP status and the CLI commands.
func TestSettingsPageListsSecurityKeys(t *testing.T) {
	creds := []*pb.WebAuthnCredential{
		{CredentialId: "abc123", Label: "YubiKey 5C NFC", Aaguid: "051d0464864e8f06b775a07a915b3b2c", CreatedAtUnix: 1750000000},
		{CredentialId: "def456", Label: "MacBook Touch ID", CreatedAtUnix: 1750100000},
	}
	h := newTestHandler(t, ui.Options{
		PublicOrigin: "https://nebula.example.org",
		SecurityKeys: func(ctx context.Context) ([]*pb.WebAuthnCredential, error) { return creds, nil },
		TOTPStatus: func(ctx context.Context) (*pb.GetTOTPStatusResponse, error) {
			return &pb.GetTOTPStatusResponse{Configured: true, Activated: true}, nil
		},
	})
	body := getBody(t, h.Handler(), "/settings")
	for _, want := range []string{
		"Sign-in and security keys",
		"YubiKey 5C NFC",
		"MacBook Touch ID",
		"051d0464",
		"nebula webauthn remove abc123",
		"nebula webauthn remove def456",
		"Add a security key",
		"nebula webauthn code",
		"Recovery",
		"TOTP recovery is enabled",
		"nebula totp setup",
		"nebula totp status",
		"nebula totp remove",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("settings page misses %q", want)
		}
	}
}

// TestSettingsPageRendersHostileKeyLabelAsText checks a label containing HTML
// and control characters is rendered as text, never as markup.
func TestSettingsPageRendersHostileKeyLabelAsText(t *testing.T) {
	label := "<img src=x onerror=alert(1)>\a<script>alert(2)</script>"
	h := newTestHandler(t, ui.Options{
		PublicOrigin: "https://nebula.example.org",
		SecurityKeys: func(ctx context.Context) ([]*pb.WebAuthnCredential, error) {
			return []*pb.WebAuthnCredential{{CredentialId: "abc123", Label: label}}, nil
		},
	})
	body := getBody(t, h.Handler(), "/settings")
	if strings.Contains(body, "<img src=x") || strings.Contains(body, "<script>") {
		t.Error("label rendered as HTML")
	}
	if !strings.Contains(body, "&lt;img src=x") {
		t.Error("label not escaped as text")
	}
}

// TestSettingsPageShowsErrorLineWhenExecutorUnreachable checks that an
// executor failure renders the section with a plain error line: status 200,
// no internal details.
func TestSettingsPageShowsErrorLineWhenExecutorUnreachable(t *testing.T) {
	h := newTestHandler(t, ui.Options{
		PublicOrigin: "https://nebula.example.org",
		SecurityKeys: func(ctx context.Context) ([]*pb.WebAuthnCredential, error) {
			return nil, errors.New("dial tcp 10.0.0.5:9443: connection refused")
		},
		TOTPStatus: func(ctx context.Context) (*pb.GetTOTPStatusResponse, error) {
			return nil, errors.New("dial tcp 10.0.0.5:9443: connection refused")
		},
	})
	body := getBody(t, h.Handler(), "/settings")
	for _, want := range []string{"Security keys could not be loaded", "Recovery status could not be loaded"} {
		if !strings.Contains(body, want) {
			t.Errorf("settings page misses %q", want)
		}
	}
	if strings.Contains(body, "10.0.0.5") || strings.Contains(body, "connection refused") {
		t.Error("internal error detail leaked into the page")
	}
}

// TestSettingsPageShowsTOTPStatus checks the recovery section reflects the
// executor's TOTP status.
func TestSettingsPageShowsTOTPStatus(t *testing.T) {
	for _, tc := range []struct {
		name string
		st   *pb.GetTOTPStatusResponse
		want string
	}{
		{name: "enabled", st: &pb.GetTOTPStatusResponse{Configured: true, Activated: true}, want: "TOTP recovery is enabled"},
		{name: "not activated", st: &pb.GetTOTPStatusResponse{Configured: true}, want: "TOTP is set up but not activated"},
		{name: "not set up", st: &pb.GetTOTPStatusResponse{}, want: "TOTP recovery is not set up"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newTestHandler(t, ui.Options{
				PublicOrigin: "https://nebula.example.org",
				TOTPStatus: func(ctx context.Context) (*pb.GetTOTPStatusResponse, error) {
					return tc.st, nil
				},
			})
			body := getBody(t, h.Handler(), "/settings")
			if !strings.Contains(body, tc.want) {
				t.Errorf("recovery section misses %q", tc.want)
			}
		})
	}
}

// TestSettingsPageAddKeyPanelReusesSetupEndpoints checks the "Add a security
// key" panel is present with a code input and that the page loads the shared
// WebAuthn script; the panel posts to the existing /setup endpoints, whose
// CSRF/Origin rules are covered by the auth package tests.
func TestSettingsPageAddKeyPanelReusesSetupEndpoints(t *testing.T) {
	h := newTestHandler(t, ui.Options{PublicOrigin: "https://nebula.example.org"})
	body := getBody(t, h.Handler(), "/settings")
	for _, want := range []string{`id="key-form"`, `id="key-code"`, `id="key-label"`, "/static/webauthn.js", "/static/settings.js"} {
		if !strings.Contains(body, want) {
			t.Errorf("settings page misses %q", want)
		}
	}
}

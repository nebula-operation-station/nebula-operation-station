// SPDX-License-Identifier: AGPL-3.0-or-later

package ui_test

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/deployprofile"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pveinventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
)

func statusOf(t *testing.T, h http.Handler, path string) int {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec.Code
}

func statusOfRequest(t *testing.T, h http.Handler, req *http.Request) int {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code
}

func deployProfileHandler(t *testing.T) (http.Handler, *deployprofile.Store) {
	t.Helper()
	db, err := serverdb.Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	s := deployprofile.New(db)
	return newTestHandler(t, ui.Options{
		PublicOrigin:   "https://nebula.example.org",
		DeployProfiles: s,
		PVE:            pveinventory.New(db),
	}).Handler(), s
}

const validProfile = `{"slug":"web_m","title":"Web server, M","description":"A small web server.",
 "image":"debian-13","storage_class":"local-lvm","size":{"preset":"M"},
 "network":{"bridge":"vmbr0","vlan":0,"dhcp":false,"ipam_pool":"lan"},
 "dns":{"nameservers":["1.1.1.1","9.9.9.9"],"search_domain":"lab.example.org"},
 "bootstrap":[{"name":"user","params":{"username":"web"}},{"name":"ssh-hardening"}],
 "runbooks":[{"slug":"web_restart","version":3}],
 "vault_refs":[{"slot":"ssh_key","vault_id":"host-web-ssh"}]}`

func TestDeployProfilePages(t *testing.T) {
	h, _ := deployProfileHandler(t)
	if page := getBody(t, h, "/deploy"); !strings.Contains(page, "No deploy profiles yet.") {
		t.Fatal(page)
	}
	if code, body := postJSON(t, h, "/deploy/save", validProfile); code != http.StatusOK || !strings.Contains(body, `"version":1`) {
		t.Fatalf("%d %s", code, body)
	}
	list := getBody(t, h, "/deploy")
	if !strings.Contains(list, `<a href="/deploy/web_m">web_m</a>`) || !strings.Contains(list, "Web server, M") {
		t.Fatalf("list missing profile: %s", list)
	}
	detail := getBody(t, h, "/deploy/web_m")
	for _, want := range []string{
		"Web server, M", "debian-13", "local-lvm", "M",
		"vmbr0", "lan", "1.1.1.1, 9.9.9.9", "search lab.example.org",
		"user, ssh-hardening", "web_restart v3", "vault:host-web-ssh",
		`<a href="/deploy/web_m?version=1">1</a>`,
	} {
		if !strings.Contains(detail, want) {
			t.Errorf("detail missing %q", want)
		}
	}
	// The detail page renders the document digest, not the raw document.
	if !strings.Contains(detail, "Document SHA-256") {
		t.Error("detail missing document digest")
	}
	// Editing saves a new version; the old one stays as it was.
	edited := strings.Replace(validProfile, "Web server, M", "Web server, M (v2)", 1)
	if code, body := postJSON(t, h, "/deploy/save", edited); code != http.StatusOK || !strings.Contains(body, `"version":2`) {
		t.Fatalf("save 2: %d %s", code, body)
	}
	if detail := getBody(t, h, "/deploy/web_m"); !strings.Contains(detail, "Web server, M (v2)") {
		t.Fatalf("latest must be v2: %s", detail)
	}
	if detail := getBody(t, h, "/deploy/web_m?version=1"); !strings.Contains(detail, "Web server, M") || strings.Contains(detail, "Web server, M (v2)") {
		t.Fatalf("v1 changed: %s", detail)
	}
	// The edit form carries the draft.
	edit := getBody(t, h, "/deploy/web_m/edit")
	if !strings.Contains(edit, `id="deploy-profile-form"`) || !strings.Contains(edit, "web_m") {
		t.Fatalf("edit form missing draft: %s", edit)
	}
	if fresh := getBody(t, h, "/deploy/new"); !strings.Contains(fresh, `id="deploy-profile-form"`) {
		t.Fatalf("new form missing: %s", fresh)
	}
	if code := statusOf(t, h, "/deploy/nope"); code != http.StatusNotFound {
		t.Fatalf("GET /deploy/nope: %d, want 404", code)
	}
	if code := statusOf(t, h, "/deploy/web_m?version=9"); code != http.StatusNotFound {
		t.Fatalf("GET missing version: %d, want 404", code)
	}
}

func TestDeployProfileSaveValidation(t *testing.T) {
	h, _ := deployProfileHandler(t)
	cases := []struct {
		name string
		body string
		want int
	}{
		{"secret parameter rejected", strings.Replace(validProfile, `"username":"web"`, `"password":"hunter2"`, 1), http.StatusBadRequest},
		{"uppercase slot rejected", strings.Replace(validProfile, `"slot":"ssh_key"`, `"slot":"SSH_KEY"`, 1), http.StatusBadRequest},
		{"unknown field rejected", `{"slug":"x","bogus":true}`, http.StatusBadRequest},
		{"oversized size rejected", strings.Replace(validProfile, `"preset":"M"`, `"vcpu":2,"ram_gib":2,"disk_gib":100000`, 1), http.StatusBadRequest},
		{"preset with custom rejected", strings.Replace(validProfile, `"preset":"M"`, `"preset":"M","vcpu":8`, 1), http.StatusBadRequest},
		{"missing image rejected", `{"slug":"x","title":"t","size":{"preset":"S"},"network":{"bridge":"vmbr0"}}`, http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if code, body := postJSON(t, h, "/deploy/save", tc.body); code != tc.want {
				t.Fatalf("%d %s, want %d", code, body, tc.want)
			}
		})
	}
	// A wrong content type is refused before the body is read.
	if code, _ := postJSON(t, h, "/deploy/save", validProfile); code != http.StatusOK {
		t.Fatalf("control save: %d", code)
	}
	req := httptest.NewRequest(http.MethodPost, "/deploy/save", strings.NewReader(validProfile))
	req.Header.Set("Content-Type", "text/plain")
	if code := statusOfRequest(t, h, req); code != http.StatusUnsupportedMediaType {
		t.Fatalf("text/plain: %d, want 415", code)
	}
}

func TestDeployProfileSaveTooLarge(t *testing.T) {
	h, _ := deployProfileHandler(t)
	// Grow the description past the 64 KiB request bound.
	big := strings.Replace(validProfile, `"description":"A small web server."`,
		`"description":"`+strings.Repeat("a", 70<<10)+`"`, 1)
	if code, _ := postJSON(t, h, "/deploy/save", big); code != http.StatusRequestEntityTooLarge {
		t.Fatalf("want 413, got %d", code)
	}
}

func TestDeployProfileNavWithPVE(t *testing.T) {
	h, _ := deployProfileHandler(t)
	body := getBody(t, h, "/deploy")
	for _, want := range []string{
		`<use href="/static/icons.svg#i-rocket">`,
		`href="/deploy"`,
		"Deploy profiles",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("nav missing %s", want)
		}
	}
}

func TestDeployProfilePagesWithoutStore(t *testing.T) {
	h := newTestHandler(t, ui.Options{PublicOrigin: "https://nebula.example.org"}).Handler()
	if page := getBody(t, h, "/deploy"); !strings.Contains(page, "Deploy Profiles") {
		t.Fatalf("list page must render empty: %s", page)
	}
	if code := statusOf(t, h, "/deploy/web_m"); code != http.StatusNotFound {
		t.Fatalf("detail without store: %d, want 404", code)
	}
}

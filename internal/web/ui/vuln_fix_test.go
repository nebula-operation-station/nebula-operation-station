// SPDX-License-Identifier: AGPL-3.0-or-later

package ui_test

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnstore"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
)

// listUpdatesResult builds a package.list_updates result as the script
// prints it, with the optional candidates section.
func listUpdatesResult(t *testing.T, sim, candidates string) executions.LastResultRow {
	t.Helper()
	enc := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	b, err := json.Marshal(map[string]any{
		"format": "apt-simulate-v1", "mode": "upgrade", "simulate": enc(sim), "reboot_required": false,
		"reboot_pkgs": "", "lists_mtime": vulnNow.Add(-time.Hour).Unix(), "proxmox": false, "candidates": enc(candidates),
	})
	if err != nil {
		t.Fatal(err)
	}
	return executions.LastResultRow{Result: b, FinishedAt: vulnNow.Add(-time.Hour)}
}

// TestVulnPagesRenderFixWithLinks renders "fix with" from real
// list_updates results: web1's candidate reaches the fixed source version
// (prefilled install_security link), web2's binNMU candidate's source
// version stays below it ("no fix available yet", no update link). GET
// pages never create, approve or propose anything.
func TestVulnPagesRenderFixWithLinks(t *testing.T) {
	web1, web2 := hostSubject("web1"), hostSubject("web2")
	fixed := vulnRow(1, web1, "CVE-2024-0001", vulnstore.StateOpen, vulnstore.TierHigh, "debian-tracker")
	fixed.Finding.Record.Component.Binaries = []vulnfinding.Binary{{Name: "openssl", Version: "3.0.11-1"}}
	notYet := vulnRow(2, web2, "CVE-2024-0002", vulnstore.StateOpen, vulnstore.TierHigh, "debian-tracker")
	notYet.Finding.Record.Component.SourcePackage = "foo"
	notYet.Finding.Record.Component.Binaries = []vulnfinding.Binary{{Name: "libfoo1", Version: "1.2-2"}}
	notYet.Finding.Record.Fix.Version = "1.2-4"

	ops := &chartOps{fakeOps: &fakeOps{}, extra: map[string]map[string]executions.LastResultRow{
		"package.list_updates": {
			"web1": listUpdatesResult(t,
				"Inst openssl [3.0.11-1] (3.0.13-1 Debian-Security:12/stable-security [amd64])",
				"Package: openssl\nVersion: 3.0.13-1\n\n"),
			"web2": listUpdatesResult(t,
				"Inst libfoo1 [1.2-2] (1.2-3+b1 Debian:12/stable [amd64])",
				"Package: libfoo1\nVersion: 1.2-3+b1\nSource: foo (1.2-3)\n\n"),
		},
	}}
	f := &fakeVuln{
		page: ui.VulnPage{
			Rows:     []ui.VulnRow{fixed, notYet},
			Subjects: []ui.VulnSubjectStatus{freshSubject(web1), freshSubject(web2)},
			Feeds:    []ui.VulnFeedStatus{okFeed("debian-tracker")}, LastComplete: vulnNow,
		},
		detail: ui.VulnFindingDetail{Row: fixed, Subject: freshSubject(web1), Feeds: []ui.VulnFeedStatus{okFeed("debian-tracker")}, LastComplete: vulnNow},
	}
	h := newTestHandler(t, ui.Options{PublicOrigin: leaseOrigin, Vuln: f, Operations: ops, Now: func() time.Time { return vulnNow }}).Handler()

	const link1 = `href="/operations/new?action=package.install_security&amp;host=web1"`
	for _, p := range []string{"/vulnerabilities/cve/CVE-2024-0001", "/vulnerabilities/subject/host/web1", "/vulnerabilities/f/" + vulnKey(1).String()} {
		code, body := vulnGet(t, h, p)
		if code != http.StatusOK {
			t.Fatalf("GET %s = %d", p, code)
		}
		if !strings.Contains(body, link1) || !strings.Contains(body, "Fix available: the update brings the fixed source version") {
			t.Errorf("GET %s lacks the verified fix link", p)
		}
		if strings.Contains(body, `action="/operations`) {
			t.Errorf("GET %s renders a form submitting to operations", p)
		}
	}
	_, body := vulnGet(t, h, "/vulnerabilities/subject/host/web2")
	if !strings.Contains(body, "No fix available yet") || strings.Contains(body, "action=package.install") {
		t.Errorf("binNMU candidate below the fixed source version shown as a fix:\n%s", body)
	}
	_, body = vulnGet(t, h, "/vulnerabilities/f/"+vulnKey(1).String())
	if !strings.Contains(body, "<dt>Fix with</dt>") {
		t.Error("finding page lacks the Fix with entry")
	}
	if len(ops.created) != 0 || len(ops.createdCalls) != 0 || ops.approved != "" || len(f.begun) != 0 || len(f.committed) != 0 {
		t.Fatalf("a GET proposed or decided something: %v %v %q %v %v", ops.created, ops.createdCalls, ops.approved, f.begun, f.committed)
	}
}

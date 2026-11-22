// SPDX-License-Identifier: AGPL-3.0-or-later

package ui_test

import (
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnstore"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
)

// inventoryHost returns a host subject with a fresh complete run, so the
// only thing that can keep it from green is its package inventory.
func inventoryHost(id string, inv *ui.VulnInventoryStatus) ui.VulnSubjectStatus {
	return ui.VulnSubjectStatus{Subject: hostSubject(id), LastComplete: vulnNow.Add(-time.Hour), Inventory: inv}
}

// inventoryPage renders the Vulnerabilities tab of host id.
func inventoryPage(t *testing.T, st ui.VulnSubjectStatus) string {
	t.Helper()
	f := &fakeVuln{page: ui.VulnPage{Subjects: []ui.VulnSubjectStatus{st}, LastComplete: vulnNow.Add(-time.Hour)}}
	_, body := vulnGet(t, vulnHandler(t, f), "/vulnerabilities/subject/host/"+st.Subject.ID)
	return body
}

// vulnStatusText returns the rendered overall status badge of the subject
// page.
func vulnStatusText(t *testing.T, body string) string {
	t.Helper()
	const open = `<span class="badge `
	i := strings.Index(body, `vuln-status">`)
	if i < 0 {
		t.Fatalf("no status badge in page")
	}
	start := strings.LastIndex(body[:i], open)
	return body[start : i+len(`vuln-status">`)]
}

func TestVulnInventoryLineShowsEachState(t *testing.T) {
	stamp := vulnNow.Add(-2 * time.Hour).UTC().Format("2006-01-02 15:04 UTC")
	tests := []struct {
		name string
		inv  *ui.VulnInventoryStatus
		want []string
	}{
		{
			name: "complete read, mapped kernel",
			inv: &ui.VulnInventoryStatus{ReadAt: vulnNow.Add(-2 * time.Hour), Complete: true, Sources: 3, Binaries: 7,
				KernelRelease: "6.8.0-45-generic", KernelMapped: true},
			want: []string{"Package inventory", "read " + stamp + ", 3 source packages (7 binaries), complete", "Running kernel 6.8.0-45-generic: mapped"},
		},
		{
			name: "partial read, kernel not mappable",
			inv: &ui.VulnInventoryStatus{ReadAt: vulnNow.Add(-2 * time.Hour), Complete: false, Reason: "package list incomplete",
				Sources: 2, Binaries: 4, KernelRelease: "6.8.0-45-generic"},
			want: []string{"partial: package list incomplete", "Running kernel 6.8.0-45-generic: kernel coverage unknown"},
		},
		{
			name: "no read stored",
			inv:  nil,
			want: []string{"none stored: no successful package.list_installed run for this host yet", "Running kernel: kernel coverage unknown"},
		},
		{
			name: "read failed in the backend",
			inv:  &ui.VulnInventoryStatus{Unavailable: true},
			want: []string{"inventory status unavailable", "Running kernel: kernel coverage unknown"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			body := inventoryPage(t, inventoryHost("web01", tc.inv))
			if !strings.Contains(body, "Package inventory") {
				t.Fatal("page lacks the Package inventory line")
			}
			for _, w := range tc.want {
				if !strings.Contains(body, w) {
					t.Errorf("page lacks %q", w)
				}
			}
			if tc.inv == nil || !tc.inv.Complete || tc.inv.Unavailable {
				if status := vulnStatusText(t, body); strings.Contains(status, "badge--ok") {
					t.Errorf("status of a host without a complete inventory is green: %q", status)
				}
			}
		})
	}
}

func TestVulnInventoryKernelReleaseIsEscapedAndCapped(t *testing.T) {
	hostile := "<script>alert(1)</script>\x07‮" + strings.Repeat("q", 200)
	inv := &ui.VulnInventoryStatus{ReadAt: vulnNow.Add(-time.Hour), Complete: true, KernelRelease: hostile, KernelMapped: true}
	body := inventoryPage(t, inventoryHost("web01", inv))
	if strings.Contains(body, "<script>alert(1)") {
		t.Fatal("kernel release rendered as HTML")
	}
	if !strings.Contains(body, "&lt;script&gt;") {
		t.Error("kernel release text not escaped")
	}
	if strings.ContainsRune(body, '\x07') || strings.ContainsRune(body, '‮') {
		t.Error("control or bidi characters of the kernel release were not replaced")
	}
	if strings.Contains(body, strings.Repeat("q", 127)) {
		t.Error("kernel release not capped at 128 characters")
	}
	if !strings.Contains(body, strings.Repeat("q", 100)) {
		t.Error("kernel release cut too early")
	}
}

func TestVulnHostWithoutInventoryNeverZeroOrGreen(t *testing.T) {
	for _, inv := range []*ui.VulnInventoryStatus{nil, {Unavailable: true}, {ReadAt: vulnNow, Complete: false, Reason: "package list incomplete"}} {
		body := inventoryPage(t, inventoryHost("web01", inv))
		status := vulnStatusText(t, body)
		if strings.Contains(body, "no open findings") || strings.Contains(body, "0 findings") || strings.Contains(status, "badge--ok") {
			t.Errorf("host with inventory %+v shown as clean: status %q", inv, status)
		}
		if !strings.Contains(status, "unknown") {
			t.Errorf("host with inventory %+v: status %q, want the unknown label", inv, status)
		}
	}
}

func TestVulnHostWithCompleteInventoryStaysGreenWhenClean(t *testing.T) {
	inv := &ui.VulnInventoryStatus{ReadAt: vulnNow.Add(-time.Hour), Complete: true, Sources: 1, Binaries: 1, KernelRelease: "6.8.0", KernelMapped: true}
	body := inventoryPage(t, inventoryHost("web01", inv))
	if status := vulnStatusText(t, body); !strings.Contains(status, "badge--ok") || !strings.Contains(body, "no open findings") {
		t.Errorf("clean host with complete inventory status = %q, want green", status)
	}
}

func TestVulnInventoryLineOnlyForHosts(t *testing.T) {
	inv := &ui.VulnInventoryStatus{ReadAt: vulnNow.Add(-time.Hour), Complete: true, KernelMapped: true}
	digest := "sha256:" + strings.Repeat("0123456789abcdef", 4)
	image := ui.VulnSubjectStatus{Subject: vulnstore.Subject{Kind: "image", ID: "box", ImageDigest: digest}, LastComplete: vulnNow.Add(-time.Hour), Inventory: inv}
	device := ui.VulnSubjectStatus{Subject: vulnstore.Subject{Kind: "device", ID: "dev01"}, LastComplete: vulnNow.Add(-time.Hour), Inventory: inv}
	f := &fakeVuln{page: ui.VulnPage{Subjects: []ui.VulnSubjectStatus{image, device}, LastComplete: vulnNow.Add(-time.Hour)}}
	h := vulnHandler(t, f)
	for _, path := range []string{
		"/vulnerabilities/subject/image/box?digest=sha256%3A" + strings.Repeat("0123456789abcdef", 4),
		"/vulnerabilities/subject/device/dev01",
	} {
		_, body := vulnGet(t, h, path)
		if strings.Contains(body, "Package inventory") || strings.Contains(body, "Running kernel") {
			t.Errorf("%s shows a package inventory line", path)
		}
	}
}

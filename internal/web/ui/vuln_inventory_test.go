// SPDX-License-Identifier: AGPL-3.0-or-later

package ui_test

import (
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnstore"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
)

// bidiOverride is U+202E, a bidi control character a host may send in its
// kernel release.
var bidiOverride = string(rune(0x202e))

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

// vulnStatusText returns the first rendered status badge of the page (the
// subject page's overall status, or the first row of the subject list):
// its opening tag with the class and its text.
func vulnStatusText(t *testing.T, body string) string {
	t.Helper()
	const open = `<span class="badge `
	i := strings.Index(body, `vuln-status">`)
	if i < 0 {
		t.Fatalf("no status badge in page")
	}
	start := strings.LastIndex(body[:i], open)
	end := strings.Index(body[i:], "</span>")
	if start < 0 || end < 0 {
		t.Fatalf("malformed status badge in page")
	}
	return body[start : i+end]
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
	hostile := "<script>alert(1)</script>\x07" + bidiOverride + strings.Repeat("q", 200)
	inv := &ui.VulnInventoryStatus{ReadAt: vulnNow.Add(-time.Hour), Complete: true, KernelRelease: hostile, KernelMapped: true}
	body := inventoryPage(t, inventoryHost("web01", inv))
	if strings.Contains(body, "<script>alert(1)") {
		t.Fatal("kernel release rendered as HTML")
	}
	if !strings.Contains(body, "&lt;script&gt;") {
		t.Error("kernel release text not escaped")
	}
	if strings.ContainsRune(body, '\x07') || strings.Contains(body, bidiOverride) {
		t.Error("control or bidi characters of the kernel release were not replaced")
	}
	// The hostile prefix is 27 characters (the two replaced ones count), so
	// the cap of 128 leaves exactly 101 "q" before the "…" marker.
	if !strings.Contains(body, "Running kernel &lt;script&gt;") || !strings.Contains(body, strings.Repeat("q", 101)+"…: mapped") {
		t.Error("kernel release not cut at exactly 128 characters with the … marker")
	}
	if strings.Contains(body, strings.Repeat("q", 102)) {
		t.Error("kernel release longer than 128 characters")
	}
}

func TestVulnInventoryKernelReleaseCapCountsCharactersNotBytes(t *testing.T) {
	tests := []struct {
		name    string
		release string
		want    string
		absent  string
	}{
		{
			name:    "multi-byte characters past the cap",
			release: strings.Repeat("é", 200),
			want:    "Running kernel " + strings.Repeat("é", 128) + "…: mapped",
			absent:  strings.Repeat("é", 129),
		},
		{
			name:    "exactly at the cap is not marked",
			release: strings.Repeat("é", 128),
			want:    "Running kernel " + strings.Repeat("é", 128) + ": mapped",
			absent:  "é…",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			inv := &ui.VulnInventoryStatus{ReadAt: vulnNow.Add(-time.Hour), Complete: true, KernelRelease: tc.release, KernelMapped: true}
			body := inventoryPage(t, inventoryHost("web01", inv))
			if !strings.Contains(body, tc.want) {
				t.Errorf("page lacks %q", tc.want)
			}
			if strings.Contains(body, tc.absent) {
				t.Errorf("page contains %q", tc.absent)
			}
		})
	}
}

func TestVulnHostWithoutInventoryNeverZeroOrGreen(t *testing.T) {
	for _, inv := range []*ui.VulnInventoryStatus{
		nil,
		{Unavailable: true},
		{ReadAt: vulnNow, Complete: false, Reason: "package list incomplete"},
		// A complete package read with an unmapped running kernel: kernel
		// coverage is unknown, never clean (D4).
		{ReadAt: vulnNow, Complete: true, Sources: 3, Binaries: 5, KernelRelease: "6.8.0-45-generic", KernelMapped: false},
	} {
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

// unknownInventories are the inventories that leave a host's coverage
// unknown: none stored, unavailable, partial, and complete with an unmapped
// running kernel.
func unknownInventories() map[string]*ui.VulnInventoryStatus {
	return map[string]*ui.VulnInventoryStatus{
		"none stored":     nil,
		"unavailable":     {Unavailable: true},
		"partial":         {ReadAt: vulnNow.Add(-time.Hour), Complete: false, Reason: "package list incomplete", KernelMapped: true},
		"unmapped kernel": {ReadAt: vulnNow.Add(-time.Hour), Complete: true, Sources: 1, Binaries: 1, KernelRelease: "6.8.0", KernelMapped: false},
	}
}

func TestVulnUnknownInventoryNeverGreenInSubjectListOrChart(t *testing.T) {
	for name, inv := range unknownInventories() {
		t.Run(name, func(t *testing.T) {
			page := ui.VulnPage{Subjects: []ui.VulnSubjectStatus{inventoryHost("box", inv)}, Feeds: []ui.VulnFeedStatus{okFeed("debian-tracker")}, LastComplete: vulnNow.Add(-time.Hour)}
			_, list := vulnGet(t, vulnHandler(t, &fakeVuln{page: page}), "/vulnerabilities?view=subject")
			status := vulnStatusText(t, list)
			if strings.Contains(list, "no open findings") || strings.Contains(list, "0 findings") || strings.Contains(status, "badge--ok") {
				t.Errorf("subject list shows a host with unknown coverage as clean: %q", status)
			}
			if !strings.Contains(status, "unknown") {
				t.Errorf("subject list status %q, want the unknown label", status)
			}

			chartHost := inventoryHost("box", inv)
			chartHost.LastComplete = chartTime(time.Hour)
			chartPage := ui.VulnPage{Subjects: []ui.VulnSubjectStatus{chartHost}, Feeds: []ui.VulnFeedStatus{okFeed("debian-tracker")}, LastComplete: chartTime(time.Hour)}
			chart := chartVulnBody(t, &fakeVuln{page: chartPage}, nil)
			if got := vulnLineState(chart); got != "unknown" {
				t.Errorf("chart line state = %q, want unknown", got)
			}
			if strings.Contains(chart, "no open findings") {
				t.Error("chart line shows a host with unknown coverage as clean")
			}
		})
	}
}

func TestVulnSubjectListShowsFullyCoveredCleanHostGreen(t *testing.T) {
	inv := &ui.VulnInventoryStatus{ReadAt: vulnNow.Add(-time.Hour), Complete: true, KernelMapped: true}
	page := ui.VulnPage{Subjects: []ui.VulnSubjectStatus{inventoryHost("box", inv)}, Feeds: []ui.VulnFeedStatus{okFeed("debian-tracker")}, LastComplete: vulnNow.Add(-time.Hour)}
	_, list := vulnGet(t, vulnHandler(t, &fakeVuln{page: page}), "/vulnerabilities?view=subject")
	if status := vulnStatusText(t, list); !strings.Contains(status, "badge--ok") || !strings.Contains(status, "no open findings") {
		t.Errorf("subject list status %q, want a fully covered clean host green", status)
	}
}

func TestVulnOpenCountIsLowerBoundWithoutFullInventory(t *testing.T) {
	host := hostSubject("web01")
	row := vulnRow(1, host, "CVE-2024-0001", vulnstore.StateOpen, vulnstore.TierMedium, "debian-tracker")
	render := func(inv *ui.VulnInventoryStatus) string {
		f := &fakeVuln{page: ui.VulnPage{Rows: []ui.VulnRow{row}, Subjects: []ui.VulnSubjectStatus{inventoryHost("web01", inv)},
			Feeds: []ui.VulnFeedStatus{okFeed("debian-tracker")}, LastComplete: vulnNow.Add(-time.Hour)}}
		_, body := vulnGet(t, vulnHandler(t, f), "/vulnerabilities/subject/host/web01")
		return vulnStatusText(t, body)
	}
	for name, inv := range unknownInventories() {
		if status := render(inv); !strings.Contains(status, "at least 1 open") {
			t.Errorf("%s: status %q, want %q", name, status, "at least 1 open")
		}
	}
	full := &ui.VulnInventoryStatus{ReadAt: vulnNow.Add(-time.Hour), Complete: true, KernelMapped: true}
	if status := render(full); !strings.Contains(status, "1 open") || strings.Contains(status, "at least") {
		t.Errorf("fully covered host: status %q, want the exact %q", status, "1 open")
	}
}

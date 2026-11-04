// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

// get serves one GET request on h and returns the status and body.
func get(t *testing.T, h http.Handler, path string) (int, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec.Code, rec.Body.String()
}

// TestPreviewPagesServeSeededProxmoxBatchesLeasesAndDeployments checks that
// the preview mode (the README screenshot source) serves the Proxmox,
// batch, read lease and deployment pages with the seeded demo data instead
// of a 404 or an empty shell.
func TestPreviewPagesServeSeededProxmoxBatchesLeasesAndDeployments(t *testing.T) {
	h := newHarness(true, "8080", t.TempDir())

	pages := []struct {
		path string
		want []string
	}{
		{"/pve", []string{"Lab cluster", "Edge node", "pve-a", "pve-b", "pve-c"}},
		{"/pve/" + previewClusterID, []string{"pve-a", "pve-b", "gitea", "pihole", "win11-test", "app-01"}},
		{"/pve/" + previewEdgeID, []string{"pve-c", "wireguard"}},
		{"/pve/guests/snapshots?remote=" + previewClusterID + "&vmid=101", []string{"gitea", "before-upgrade"}},
		{"/batches", []string{"partially failed"}},
		{"/leases", []string{"active", "expired"}},
		{"/deploy", []string{"Debian app server"}},
		{"/deployments", []string{"app-01"}},
		{"/inventory/chart", []string{"pve-a", "pve-c", "gitea", "nas-backup", "local-zfs"}},
	}
	for _, p := range pages {
		code, body := get(t, h, p.path)
		if code != http.StatusOK {
			t.Errorf("GET %s = %d, want 200", p.path, code)
			continue
		}
		for _, w := range p.want {
			if !strings.Contains(body, w) {
				t.Errorf("GET %s lacks %q", p.path, w)
			}
		}
	}

	// The detail pages linked from the lists answer 200 too.
	for _, list := range []struct{ path, link string }{
		{"/batches", `href="(/batches/[0-9a-f-]{36})"`},
		{"/deployments", `href="(/deployments/[0-9a-f]{32})"`},
		{"/leases", `href="(/leases/[0-9a-f-]{36})"`},
	} {
		_, body := get(t, h, list.path)
		m := regexp.MustCompile(list.link).FindStringSubmatch(body)
		if m == nil {
			t.Errorf("GET %s links no detail page", list.path)
			continue
		}
		if code, _ := get(t, h, m[1]); code != http.StatusOK {
			t.Errorf("GET %s = %d, want 200", m[1], code)
		}
	}

	// Both read grants decode (none is shown as invalid): one active, one
	// expired.
	_, leases := get(t, h, "/leases")
	states := regexp.MustCompile(`<span class="badge [^"]*">([a-z]+)</span>`).FindAllStringSubmatch(leases, -1)
	var got []string
	for _, s := range states {
		got = append(got, s[1])
	}
	if strings.Join(got, ",") != "active,expired" && strings.Join(got, ",") != "expired,active" {
		t.Errorf("lease states = %v, want one active and one expired", got)
	}

	// The finished deployment shows as done.
	_, body := get(t, h, "/deployments")
	if m := regexp.MustCompile(`href="(/deployments/[0-9a-f]{32})"`).FindStringSubmatch(body); m != nil {
		if _, run := get(t, h, m[1]); !strings.Contains(run, `id="deploy-state">done<`) {
			t.Errorf("the seeded deployment is not done")
		}
	}

	// The batch shows member outcomes of more than one kind.
	_, body = get(t, h, "/batches")
	if m := regexp.MustCompile(`href="(/batches/[0-9a-f-]{36})"`).FindStringSubmatch(body); m != nil {
		_, b := get(t, h, m[1])
		for _, w := range []string{"Security updates", "canary", "success", "failed", "skipped"} {
			if !strings.Contains(b, w) {
				t.Errorf("batch page lacks outcome %q", w)
			}
		}
	}
}

// TestPreviewChartShowsHostMetrics checks that the org chart shows CPU, RAM
// and disk numbers for the seeded hosts instead of "unknown".
func TestPreviewChartShowsHostMetrics(t *testing.T) {
	h := newHarness(true, "8080", t.TempDir())
	code, body := get(t, h, "/inventory/chart")
	if code != http.StatusOK {
		t.Fatalf("GET /inventory/chart = %d", code)
	}
	if n := len(regexp.MustCompile(`\d+ %`).FindAllString(body, -1)); n < 10 {
		t.Errorf("chart shows %d percentages, want the seeded CPU/RAM/disk values", n)
	}
}

// TestPreviewDemoDataIsInvented checks that the seeded Proxmox addresses
// stay in the invented demo range.
func TestPreviewDemoDataIsInvented(t *testing.T) {
	for _, r := range previewRemotes() {
		for _, ep := range r.Endpoints {
			if !strings.HasPrefix(ep.Host, "10.20.0.") {
				t.Errorf("remote %s endpoint %s is outside 10.20.0.0/24", r.RemoteID, ep.Host)
			}
		}
	}
}

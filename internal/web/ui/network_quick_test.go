// SPDX-License-Identifier: AGPL-3.0-or-later

package ui_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/discovery"
	"github.com/nebula-operation-station/nebula-operation-station/internal/discoveryjob"
	"github.com/nebula-operation-station/nebula-operation-station/internal/ipam"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
)

// quickHandler builds a handler with an IPAM store and a discovery store.
// installed controls whether the discovery spool exists (so scans can run);
// serverIP overrides the server address used for the scan prefill (nil keeps
// the default, which reads the machine's own interfaces).
func quickHandler(t *testing.T, installed bool, serverIP func() netip.Addr) (http.Handler, *ipam.Store, *discovery.Store, discoveryjob.Spool) {
	t.Helper()
	db, err := serverdb.Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	sp := discoveryjob.Spool{Dir: t.TempDir()}
	if installed {
		for _, d := range []string{sp.JobsDir(), sp.ResultsDir()} {
			if err := os.MkdirAll(d, 0o750); err != nil {
				t.Fatal(err)
			}
		}
	}
	ip := ipam.New(db, nil)
	ds := discovery.New(db, sp, ip, nil, nil)
	o := ui.Options{PublicOrigin: "https://nebula.example.org", Network: ip, Discovery: ds}
	if serverIP != nil {
		o.ServerIP = serverIP
	}
	return newTestHandler(t, o).Handler(), ip, ds, sp
}

func getWithCookie(t *testing.T, h http.Handler, path, cookie string) string {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s: status %d, want 200", path, rec.Code)
	}
	return rec.Body.String()
}

var scanCIDRRe = regexp.MustCompile(`id="scan-cidr" value="([^"]*)"`)

// The Quick/Expert switch is link-based: the ?mode= parameter wins, then the
// cookie, then quick. Invalid values fall back to quick.
func TestNetworkModeCookieAndParam(t *testing.T) {
	h, _, _, _ := quickHandler(t, true, func() netip.Addr { return netip.MustParseAddr("10.1.2.3") })
	const quickOn = `seg-item--active" href="/network?mode=quick"`
	const expertOn = `seg-item--active" href="/network?mode=expert"`
	for _, c := range []struct {
		name, path, cookie, want string
	}{
		{"default is quick", "/network", "", quickOn},
		{"param expert", "/network?mode=expert", "", expertOn},
		{"param quick", "/network?mode=quick", "", quickOn},
		{"invalid param falls back", "/network?mode=bogus", "", quickOn},
		{"cookie expert", "/network", "nebula_network_mode=expert", expertOn},
		{"invalid cookie falls back", "/network", "nebula_network_mode=bogus", quickOn},
		{"param overrides cookie", "/network?mode=quick", "nebula_network_mode=expert", quickOn},
	} {
		t.Run(c.name, func(t *testing.T) {
			var page string
			if c.cookie == "" {
				page = getBody(t, h, c.path)
			} else {
				page = getWithCookie(t, h, c.path, c.cookie)
			}
			if !strings.Contains(page, c.want) {
				t.Fatalf("active segment not %q", c.want)
			}
		})
	}
}

// The scan input is prefilled server side: the first configured network's
// prefix, else the /24 of the server's private IPv4, else a fixed default. It
// never uses host data.
func TestNetworkQuickScanPrefill(t *testing.T) {
	t.Run("server ip /24", func(t *testing.T) {
		h, _, _, _ := quickHandler(t, true, func() netip.Addr { return netip.MustParseAddr("10.1.2.3") })
		if got := scanCIDRRe.FindStringSubmatch(getBody(t, h, "/network"))[1]; got != "10.1.2.0/24" {
			t.Fatalf("prefill = %q, want 10.1.2.0/24", got)
		}
	})
	t.Run("configured network wins", func(t *testing.T) {
		h, ip, _, _ := quickHandler(t, true, func() netip.Addr { return netip.MustParseAddr("10.1.2.3") })
		if err := ip.SaveNetwork(context.Background(), ipam.Network{ID: "lan", Name: "LAN", Prefix: netip.MustParsePrefix("172.16.5.0/24")}); err != nil {
			t.Fatal(err)
		}
		if got := scanCIDRRe.FindStringSubmatch(getBody(t, h, "/network"))[1]; got != "172.16.5.0/24" {
			t.Fatalf("prefill = %q, want 172.16.5.0/24", got)
		}
	})
	t.Run("no network no server ip uses default", func(t *testing.T) {
		h, _, _, _ := quickHandler(t, true, func() netip.Addr { return netip.Addr{} })
		if got := scanCIDRRe.FindStringSubmatch(getBody(t, h, "/network"))[1]; got != "192.168.1.0/24" {
			t.Fatalf("prefill = %q, want the fixed default 192.168.1.0/24", got)
		}
	})
}

// The "Scan" button creates the network when it is missing and queues a scan
// through the existing discovery path, so its limits apply unchanged: a target
// the discovery path rejects (too large) is rejected here too.
func TestNetworkQuickScanUsesDiscoveryValidation(t *testing.T) {
	t.Run("valid prefix creates network and job", func(t *testing.T) {
		h, ip, _, _ := quickHandler(t, true, nil)
		code, body := postJSON(t, h, "/network/scan", `{"cidr":"192.168.50.0/24"}`)
		if code != http.StatusOK {
			t.Fatalf("status %d, body %s", code, body)
		}
		if strings.Contains(body, `"job":""`) {
			t.Fatalf("no job queued: %s", body)
		}
		nets, err := ip.Networks(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if len(nets) != 1 || nets[0].Name != "192.168.50.0/24" {
			t.Fatalf("network not created: %+v", nets)
		}
	})
	t.Run("too large target is rejected like the discovery page", func(t *testing.T) {
		h, _, _, _ := quickHandler(t, true, nil)
		code, body := postJSON(t, h, "/network/scan", `{"cidr":"10.0.0.0/8"}`)
		if code != http.StatusBadRequest {
			t.Fatalf("status %d, body %s", code, body)
		}
		if !strings.Contains(body, "error") {
			t.Fatalf("no error: %s", body)
		}
	})
	t.Run("invalid and empty cidr rejected", func(t *testing.T) {
		h, _, _, _ := quickHandler(t, true, nil)
		for _, cidr := range []string{"nope", "", "192.168.10.5"} {
			if code, body := postJSON(t, h, "/network/scan", `{"cidr":"`+cidr+`"}`); code != http.StatusBadRequest {
				t.Fatalf("cidr %q: status %d, body %s", cidr, code, body)
			}
		}
	})
	t.Run("discovery disabled creates network but no job", func(t *testing.T) {
		h, ip, _, _ := quickHandler(t, false, nil)
		code, body := postJSON(t, h, "/network/scan", `{"cidr":"192.168.60.0/24"}`)
		if code != http.StatusOK {
			t.Fatalf("status %d, body %s", code, body)
		}
		if !strings.Contains(body, `"job":""`) {
			t.Fatalf("a job should not be queued without discovery: %s", body)
		}
		if nets, err := ip.Networks(context.Background()); err != nil || len(nets) != 1 {
			t.Fatalf("network not created: %+v %v", nets, err)
		}
	})
}

// seedDiscoveryResult queues a scan for the given network, writes a result with
// one host, and polls so the job is finished and its rows are staged.
func seedDiscoveryResult(t *testing.T, ds *discovery.Store, sp discoveryjob.Spool, network, addr, hostname, mac string) {
	t.Helper()
	ctx := context.Background()
	j, err := ds.Submit(ctx, "unknown", discovery.Request{Mode: discoveryjob.ModePorts, Targets: []string{network}, Ports: "22"})
	if err != nil {
		t.Fatal(err)
	}
	res := discoveryjob.Result{Format: discoveryjob.ResultFormat, Job: j.ID, StartedAt: 1, FinishedAt: 2, OK: true,
		Hosts: []discoveryjob.Host{{Address: addr, Hostname: hostname, MAC: mac,
			Ports: []discoveryjob.Port{{Port: 22, Protocol: "tcp", State: "open"}}}}}
	if err := sp.WriteResult(res); err != nil {
		t.Fatal(err)
	}
	if err := ds.Poll(ctx); err != nil {
		t.Fatal(err)
	}
}

// The Devices card merges saved assets with the latest discovery results.
// Untrusted scan data (hostname, vendor) renders as text only.
func TestNetworkQuickDevicesMerge(t *testing.T) {
	h, ip, ds, sp := quickHandler(t, true, nil)
	if err := ip.SaveNetwork(context.Background(), ipam.Network{ID: "lan", Name: "LAN", Prefix: netip.MustParsePrefix("192.168.10.0/24")}); err != nil {
		t.Fatal(err)
	}
	// A saved asset with an address shows up as a device, with "Add as managed host".
	if code, body := postJSON(t, h, "/network/a/save",
		`{"id":"nas","name":"NAS","kind":"nas","hostname":"nas.lan","mac":"AA:BB:CC:DD:EE:FF","notes":"","addresses":["192.168.10.21"]}`); code != http.StatusOK {
		t.Fatal(code, body)
	}
	page := getBody(t, h, "/network")
	for _, want := range []string{"192.168.10.21", "NAS", `href="/inventory?asset=nas"`, "aa:bb:cc:dd:ee:ff"} {
		if !strings.Contains(page, want) {
			t.Errorf("devices card lacks %q", want)
		}
	}
	// A discovery sighting that is not an asset yet shows "Save as device".
	seedDiscoveryResult(t, ds, sp, "192.168.10.0/24", "192.168.10.77", `<script>alert(1)</script>`, "AA:BB:CC:00:00:01")
	page = getBody(t, h, "/network")
	if !strings.Contains(page, "192.168.10.77") || !strings.Contains(page, "Save as device") {
		t.Fatal("discovery sighting not listed")
	}
	if strings.Contains(page, "<script>alert") {
		t.Fatal("scan hostname rendered as markup")
	}
}

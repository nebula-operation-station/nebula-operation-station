// SPDX-License-Identifier: AGPL-3.0-or-later

package ui_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/discovery"
	"github.com/nebula-operation-station/nebula-operation-station/internal/discoveryjob"
	"github.com/nebula-operation-station/nebula-operation-station/internal/ipam"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
)

func discoveryHandler(t *testing.T, installed bool) (http.Handler, *discovery.Store, discoveryjob.Spool) {
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
	if err := ip.SaveNetwork(context.Background(), ipam.Network{ID: "lan", Name: "LAN", Prefix: netip.MustParsePrefix("192.168.10.0/24")}); err != nil {
		t.Fatal(err)
	}
	ds := discovery.New(db, sp, ip, nil, nil)
	h := newTestHandler(t, ui.Options{PublicOrigin: "https://nebula.example.org", Network: ip, Discovery: ds}).Handler()
	return h, ds, sp
}

func TestDiscoveryFlow(t *testing.T) {
	h, ds, sp := discoveryHandler(t, true)
	page := getBody(t, h, "/network/discovery")
	if !strings.Contains(page, "No scans yet.") || strings.Contains(page, "not installed") || !strings.Contains(page, "<code>192.168.10.0/24</code> (LAN)") {
		t.Fatal(page)
	}
	for _, c := range []struct {
		body string
		want int
	}{
		{`{"mode":"ping","targets":["10.0.0.0/24"],"ports":"","custom":null,"schedule":{"kind":"now","name":"","at":0,"hours":0}}`, http.StatusBadRequest},
		{`{"mode":"ping","targets":["192.168.10.0/24"],"ports":"","custom":null,"schedule":{"kind":"interval","name":"x","at":0,"hours":0}}`, http.StatusBadRequest},
		{`{"mode":"ping","targets":["192.168.10.0/24"],"ports":"","custom":null,"schedule":{"kind":"cron","name":"x","at":0,"hours":1}}`, http.StatusBadRequest},
		{`{"mode":"ping","targets":["192.168.10.0/24"],"args":"-sC","schedule":{"kind":"now"}}`, http.StatusBadRequest},
		{`{"mode":"ping","targets":["192.168.10.0/24"],"ports":"","custom":null,"schedule":{"kind":"interval","name":"nightly","at":0,"hours":24}}`, http.StatusOK},
	} {
		if code, body := postJSON(t, h, "/network/discovery/submit", c.body); code != c.want {
			t.Errorf("%s: %d %s", c.body, code, body)
		}
	}
	code, body := postJSON(t, h, "/network/discovery/submit", `{"mode":"ports","targets":["192.168.10.0/24"],"ports":"80,22","custom":null,"schedule":{"kind":"now"}}`)
	if code != http.StatusOK {
		t.Fatal(code, body)
	}
	var out struct{ ID string }
	_ = json.Unmarshal([]byte(body), &out)
	if !strings.Contains(getBody(t, h, "/network/discovery/"+out.ID), "Waiting for nebula-discovery") {
		t.Fatal("queued job page")
	}
	// Hostile network data in the result renders as text.
	if err := sp.WriteResult(discoveryjob.Result{Format: discoveryjob.ResultFormat, Job: out.ID, StartedAt: 1, FinishedAt: 2, OK: true,
		Hosts: []discoveryjob.Host{{Address: "192.168.10.40", Vendor: "<script>alert(1)</script>", OS: "<img src=x onerror=alert(2)>",
			Ports: []discoveryjob.Port{{Port: 80, Protocol: "tcp", State: "open", Service: "http", Product: "<b>x</b>"}}}}}); err != nil {
		t.Fatal(err)
	}
	if err := ds.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	page = getBody(t, h, "/network/discovery/"+out.ID)
	if strings.Contains(page, "<script>alert") || strings.Contains(page, "<img src=x") || strings.Contains(page, "<b>x</b>") {
		t.Fatal("markup rendered")
	}
	if !strings.Contains(page, `class="stage-pick" value="192.168.10.40"`) || !strings.Contains(page, "1 NEW") {
		t.Fatal(page)
	}
	if code, body := postJSON(t, h, "/network/discovery/import", `{"id":"`+out.ID+`","addresses":["192.168.10.40"],"all":false}`); code != http.StatusOK ||
		!strings.Contains(body, `"created":["ip-192-168-10-40"]`) {
		t.Fatal(code, body)
	}
	if !strings.Contains(getBody(t, h, "/network/discovery/"+out.ID), `imported as <a href="/network/a/ip-192-168-10-40">`) {
		t.Fatal("import not shown")
	}
	page = getBody(t, h, "/network/discovery")
	if !strings.Contains(page, "nightly") || !strings.Contains(page, "every 24 h") {
		t.Fatal(page)
	}
}

func TestDiscoveryNotInstalled(t *testing.T) {
	h, _, _ := discoveryHandler(t, false)
	if !strings.Contains(getBody(t, h, "/network/discovery"), "nebula-discovery is not installed") {
		t.Fatal("no notice")
	}
	if code, _ := postJSON(t, h, "/network/discovery/submit", `{"mode":"ping","targets":["192.168.10.0/24"],"schedule":{"kind":"now"}}`); code != http.StatusConflict {
		t.Fatal(code)
	}
	plain := newTestHandler(t, ui.Options{PublicOrigin: "https://nebula.example.org"}).Handler()
	for _, p := range []string{"/network/discovery/submit", "/network/discovery/import", "/network/discovery/cancel"} {
		if code, _ := postJSON(t, plain, p, `{}`); code != http.StatusNotFound {
			t.Errorf("%s: %d", p, code)
		}
	}
}

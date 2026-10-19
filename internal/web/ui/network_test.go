// SPDX-License-Identifier: AGPL-3.0-or-later

package ui_test

import (
	"context"
	"html"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/ipam"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
)

func networkHandler(t *testing.T, inv *fakeInventory) http.Handler {
	t.Helper()
	db, err := serverdb.Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	list := func(context.Context) ([]inventory.Host, error) {
		var out []inventory.Host
		for _, h := range inv.hosts {
			out = append(out, h)
		}
		return out, nil
	}
	return newTestHandler(t, ui.Options{PublicOrigin: "https://nebula.example.org", Inventory: inv, Hosts: list,
		Network: ipam.New(db, ipam.FromInventory(list))}).Handler()
}

func TestNetworkPagesAndStatus(t *testing.T) {
	inv := newFakeInventory()
	inv.hosts["web1"] = inventory.Host{ID: "web1", Endpoints: []inventory.Endpoint{{Address: "192.168.10.20", Port: 22}}}
	h := networkHandler(t, inv)
	if page := getBody(t, h, "/network"); !strings.Contains(page, "No networks yet.") || !strings.Contains(page, "No assets yet.") {
		t.Fatal(page)
	}
	for _, c := range []struct {
		path, body string
		want       int
	}{
		{"/network/save", `{"id":"lan","name":"LAN","prefix":"192.168.10.0/24","vlan":10,"gateway":"192.168.10.1","notes":"",
			"pools":[{"name":"servers","first":"192.168.10.10","last":"192.168.10.19"}]}`, http.StatusOK},
		{"/network/save", `{"id":"bad","name":"B","prefix":"nope","vlan":0,"gateway":"","notes":"","pools":[]}`, http.StatusBadRequest},
		{"/network/save", `{"id":"x","name":"X","prefix":"10.0.0.0/24","extra":1}`, http.StatusBadRequest},
		{"/network/a/save", `{"id":"printer","name":"Printer","kind":"printer","hostname":"","mac":"","notes":"","addresses":["192.168.10.20"]}`, http.StatusOK},
		{"/network/a/save", `{"id":"cam","name":"Cam","kind":"iot","hostname":"","mac":"","notes":"","addresses":["192.168.10.30"]}`, http.StatusOK},
		{"/network/a/save", `{"id":"cam","name":"Cam","kind":"toaster","hostname":"","mac":"","notes":"","addresses":[]}`, http.StatusBadRequest},
		{"/network/entry", `{"address":"192.168.10.40","kind":"reserved","note":"switch"}`, http.StatusOK},
		{"/network/entry", `{"address":"192.168.10.41","kind":"excluded","note":""}`, http.StatusOK},
		{"/network/entry", `{"address":"192.168.10.41","kind":"","note":""}`, http.StatusOK},
		{"/network/entry", `{"address":"192.168.10.41","kind":"","note":""}`, http.StatusNotFound},
		{"/network/entry", `{"address":"nope","kind":"reserved","note":""}`, http.StatusBadRequest},
		{"/network/a/link", `{"asset":"cam","host":"ghost"}`, http.StatusNotFound},
	} {
		if code, body := postJSON(t, h, c.path, c.body); code != c.want {
			t.Errorf("%s %s: %d %s", c.path, c.body, code, body)
		}
	}
	page := getBody(t, h, "/network/n/lan")
	for _, m := range regexp.MustCompile(`<script src="(/static/[^"]+)"`).FindAllStringSubmatch(page, -1) {
		getBody(t, h, m[1])
	}
	for _, want := range []string{
		`title="192.168.10.20 CONFLICT: claimed by several assets or hosts"`,
		`title="192.168.10.30 ASSIGNED"`,
		`title="192.168.10.40 RESERVED: switch"`,
		`title="192.168.10.0 EXCLUDED: network or broadcast address"`,
		`<code>192.168.10.2</code>`,
	} {
		if !strings.Contains(page, want) {
			t.Errorf("network page lacks %q", want)
		}
	}
	if !strings.Contains(getBody(t, h, "/network/n/lan?pool=servers"), "<code>192.168.10.10</code>") {
		t.Error("no pool suggestion")
	}
	if !strings.Contains(getBody(t, h, "/network"), "2 assigned, 1 reserved, 1 conflict, 250 free") {
		t.Error("no counts on the list: " + regexp.MustCompile(`<td>[0-9][^<]*free[^<]*</td>`).FindString(getBody(t, h, "/network")))
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/network/n/nope", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatal(rec.Code)
	}
}

func TestAddAssetToManagedHosts(t *testing.T) {
	inv := newFakeInventory()
	h := networkHandler(t, inv)
	if code, body := postJSON(t, h, "/network/a/save",
		`{"id":"nas","name":"NAS","kind":"nas","hostname":"nas.lan","mac":"AA:BB:CC:DD:EE:FF","notes":"","addresses":["192.168.10.21","fd00::21"]}`); code != http.StatusOK {
		t.Fatal(code, body)
	}
	page := getBody(t, h, "/network/a/nas")
	if !strings.Contains(page, `href="/inventory?asset=nas"`) || !strings.Contains(page, "aa:bb:cc:dd:ee:ff") {
		t.Fatal(page)
	}
	prefill := regexp.MustCompile(`data-prefill="([^"]+)"`).FindStringSubmatch(getBody(t, h, "/inventory?asset=nas"))
	if prefill == nil {
		t.Fatal("no prefill")
	}
	if got := html.UnescapeString(prefill[1]); got != `{"asset":"nas","display_name":"NAS","endpoints":["192.168.10.21","[fd00::21]:22"],"id":"nas"}` {
		t.Fatal(got)
	}
	if strings.Contains(getBody(t, h, "/inventory?asset=ghost"), "data-prefill") {
		t.Fatal("prefill for an unknown asset")
	}
	inv.hosts["nas"] = inventory.Host{ID: "nas"}
	if code, body := postJSON(t, h, "/network/a/link", `{"asset":"nas","host":"nas"}`); code != http.StatusOK {
		t.Fatal(code, body)
	}
	page = getBody(t, h, "/network/a/nas")
	if !strings.Contains(page, `<a href="/hosts/nas">nas</a>`) || strings.Contains(page, "/inventory?asset=nas") {
		t.Fatal(page)
	}
	if strings.Contains(getBody(t, h, "/inventory?asset=nas"), "data-prefill") {
		t.Fatal("prefill for a linked asset")
	}
}

// Asset and network texts are user input: they render as text only.
func TestNetworkTextsRenderInert(t *testing.T) {
	h := networkHandler(t, newFakeInventory())
	hostile := `<script>alert(1)</script>`
	if code, body := postJSON(t, h, "/network/a/save", `{"id":"evil","name":"`+strings.ReplaceAll(hostile, `"`, `\"`)+`","kind":"unknown",
		"hostname":"","mac":"","notes":"<img src=x onerror=alert(2)>","addresses":[]}`); code != http.StatusOK {
		t.Fatal(code, body)
	}
	for _, path := range []string{"/network", "/network/a/evil"} {
		page := getBody(t, h, path)
		if strings.Contains(page, "<script>alert") || strings.Contains(page, "<img src=x") {
			t.Fatalf("%s renders markup", path)
		}
	}
	if code, _ := postJSON(t, h, "/network/a/save", `{"id":"bidi","name":"a\u202eb","kind":"unknown","hostname":"","mac":"","notes":"","addresses":[]}`); code != http.StatusBadRequest {
		t.Fatal("bidi control accepted")
	}
}

func TestNetworkWithoutStore(t *testing.T) {
	h := newTestHandler(t, ui.Options{PublicOrigin: "https://nebula.example.org"}).Handler()
	if page := getBody(t, h, "/network"); !strings.Contains(page, "Network") {
		t.Fatal(page)
	}
	for _, p := range []string{"/network/save", "/network/a/save", "/network/entry", "/network/a/link"} {
		if code, _ := postJSON(t, h, p, `{}`); code != http.StatusNotFound {
			t.Errorf("%s: %d", p, code)
		}
	}
}

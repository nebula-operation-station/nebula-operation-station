// SPDX-License-Identifier: AGPL-3.0-or-later

package ui_test

import (
	"context"
	"net/netip"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"

	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/ipam"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
)

func searchHandler(t *testing.T) *ui.Handler {
	t.Helper()
	db, err := serverdb.Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	hosts := func(context.Context) ([]inventory.Host, error) {
		return []inventory.Host{{ID: "web", DisplayName: "<b>Web</b>", Endpoints: []inventory.Endpoint{{Address: "192.168.10.20", Port: 22}},
			Tags: map[string]string{"role": "frontend"}}, {ID: "db1", Endpoints: []inventory.Endpoint{{Address: "db1.lan", Port: 22}}}}, nil
	}
	ip := ipam.New(db, ipam.FromInventory(hosts))
	ctx := context.Background()
	if err := ip.SaveNetwork(ctx, ipam.Network{ID: "lan", Name: "LAN", VLAN: 10, Prefix: netip.MustParsePrefix("192.168.10.0/24")}); err != nil {
		t.Fatal(err)
	}
	if err := ip.SaveAsset(ctx, ipam.Asset{ID: "nas", Name: "Synology", Kind: ipam.KindNAS, MAC: "aa:bb:cc:dd:ee:ff",
		Addresses: []netip.Addr{netip.MustParseAddr("192.168.10.21")}}); err != nil {
		t.Fatal(err)
	}
	return newTestHandler(t, ui.Options{PublicOrigin: "https://nebula.example.org", Hosts: hosts, Network: ip, Operations: &fakeOps{},
		Inventory: newFakeInventory(),
		HostKeys: func(context.Context) ([]*pb.HostKeyPin, error) {
			return []*pb.HostKeyPin{{HostId: "web", Fingerprint: "SHA256:x"}}, nil
		}})
}

func search(t *testing.T, h *ui.Handler, q string) string {
	t.Helper()
	return getBody(t, h.Handler(), "/search?q="+url.QueryEscape(q))
}

func TestSearch(t *testing.T) {
	h := searchHandler(t)
	for q, want := range map[string][]string{
		"192.168.10.20":   {`<a href="/hosts/web">&lt;b&gt;Web&lt;/b&gt; (web)</a>`, "Address", "ASSIGNED in 192.168.10.0/24", `href="/operations/new?host=web"`},
		"192.168.10.21":   {`<a href="/network/a/nas">Synology (nas)</a>`, "ASSIGNED in 192.168.10.0/24"},
		"192.168.10.0/25": {"Synology (nas)", "LAN (lan)", "(web)"},
		"SYNO":            {"Synology (nas)", `href="/inventory?asset=nas"`},
		"aa:bb:cc":        {"Synology (nas)"},
		"role=front":      {"(web)"},
		"db1.lan":         {"(db1)"},
		"vlan 10":         {"LAN (lan)"},
		"0b9c2f7e":        {`href="/operations/0b9c2f7e-4a51-4c8e-9a51-6f0d3c2b1a00"`},
		"core.facts":      {"Execution"},
	} {
		page := search(t, h, q)
		for _, w := range want {
			if !strings.Contains(page, w) {
				t.Errorf("%q: missing %q", q, w)
			}
		}
	}
	page := search(t, h, `"><script>alert(1)</script>`)
	if strings.Contains(page, "<script>alert") || !strings.Contains(page, "Nothing found") {
		t.Fatal("query reflected as markup")
	}
	if !strings.Contains(search(t, h, strings.Repeat("a", 101)), "too long") {
		t.Fatal("long query")
	}
	if strings.Contains(search(t, h, ""), "Results") {
		t.Fatal("empty query searched")
	}
	// The quick action preselects the host in the planner.
	if page := getBody(t, h.Handler(), "/operations/new?host=web&host=new"); !strings.Contains(page, `value="web" checked`) || strings.Contains(page, `value="new" disabled checked`) {
		t.Fatal("host not preselected")
	}
}

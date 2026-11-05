// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"log/slog"
	"net/http"
	"net/netip"

	"github.com/nebula-operation-station/nebula-operation-station/internal/flowagg"
	tmapi "github.com/nebula-operation-station/nebula-operation-station/internal/web/api/trafficmap"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/auth"
	tmui "github.com/nebula-operation-station/nebula-operation-station/internal/web/ui/trafficmap"
)

// Hostile names of the browser test's traffic map (test/browser/
// trafficmap.spec.js, ADR 0009 TM21). Each would run script if any layer
// turned it into markup; the spec checks that window.__pwned stays unset
// and that the labels arrive as literal text.
const (
	trafficHostLabel  = `<img src=x onerror="window.__pwned='img'">E2E host`
	trafficTwoLabel   = `</script><script>window.__pwned='script'</script>`
	trafficAssetLabel = "printer.local‮<svg onload=\"window.__pwned='svg'\">"
	trafficZoneName   = `<iframe srcdoc="<script>parent.__pwned='zone'</script>">`
)

// trafficMapAPIPath is where the page fetches the model (as in
// cmd/nebula-server).
const trafficMapAPIPath = "/api/v1/" + tmapi.Path

// noTrafficFlows is a traffic store without flows: the browser test is
// about drawing nodes, isolation, focus and navigation.
type noTrafficFlows struct{}

func (noTrafficFlows) TopN(context.Context, netip.Addr, flowagg.Window, int) ([]flowagg.FlowTotal, error) {
	return nil, nil
}

func (noTrafficFlows) OverviewUnion(context.Context, []netip.Addr, flowagg.Window, int) ([]flowagg.FlowTotal, error) {
	return nil, nil
}

// trafficInventory is the map's fixed inventory: the harness hosts e2e-host
// and e2e-two (so a node opens a real host page) and one IPAM asset, all
// with hostile labels, in one zone with a hostile name.
func trafficInventory(context.Context) (tmapi.Inventory, error) {
	return tmapi.Inventory{
		Zones: []tmapi.ZoneInput{{ID: "lan", Name: trafficZoneName, VLAN: 10}},
		Nodes: []tmapi.NodeInput{
			{ID: "e2e-host", Label: trafficHostLabel, Kind: tmapi.KindHost, Zone: "lan", VLAN: 10,
				Addrs: []netip.Addr{netip.MustParseAddr("192.168.10.11")}},
			{ID: "e2e-two", Label: trafficTwoLabel, Kind: tmapi.KindHost, Zone: "lan", VLAN: 10,
				Addrs: []netip.Addr{netip.MustParseAddr("192.168.10.12")}},
			{ID: "asset:prn", Label: trafficAssetLabel, Kind: tmapi.KindAsset, Zone: "lan", VLAN: 10,
				Addrs: []netip.Addr{netip.MustParseAddr("192.168.10.21")}},
		},
	}, nil
}

// mountTrafficMap adds the traffic map page, the renderer document, the
// renderer modules and the model API to pages, like cmd/nebula-server
// does. Without preview the model needs a session (the session wrapper in
// front checks it as well); in preview there is no session at all.
func mountTrafficMap(pages *http.ServeMux, preview bool, origin string, log *slog.Logger) {
	builder, err := tmapi.NewBuilder(trafficInventory, noTrafficFlows{}, nil, tmapi.Limits{})
	must(err)
	model, err := tmapi.New(tmapi.Options{
		Inventory: trafficInventory,
		Flows:     noTrafficFlows{},
		Authorize: func(r *http.Request) bool {
			_, ok := auth.SessionFrom(r.Context())
			return ok || preview
		},
		Log: log,
	})
	must(err)
	page, err := tmui.New(tmui.Options{PublicOrigin: origin, Windows: builder.Windows, Log: log})
	must(err)
	page.RegisterPages(pages)
	page.RegisterModules(pages)
	pages.Handle(trafficMapAPIPath, model)
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/attackpath"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/auth"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui/paths"
)

// Hostile texts of the browser test's attack paths (test/browser/
// attackpath.spec.js, ADR 0011 D10, VU-26). Each would run script if any
// layer turned it into markup; the spec checks that window.__pwned stays
// unset and that the texts arrive as literal text. The node labels differ
// from the traffic map's on purpose: the list shows the attack-path
// labels, the map draws the traffic model's.
const (
	pathsEntryLabel  = `<img src=x onerror="window.__pwned='paths-host'">AP host`
	pathsTargetLabel = `</td></tr><script>window.__pwned='paths-target'</script>AP jewel`
	pathsVulnID      = `CVE-2026-<svg onload="window.__pwned='paths-vuln'">`
	pathsPackage     = `nginx"><iframe srcdoc="<script>parent.__pwned='paths-pkg'</script>">`
)

// pathsAdmin is the harness's admin rule for the attack-path pages: a
// signed-in session while the flag is set. The test hook /__paths/admin
// clears and sets it, so one browser session can be admin and non-admin.
var pathsAdmin atomic.Bool

func init() { pathsAdmin.Store(true) }

// pathsAdminHook serves /__paths/admin?on=0|1.
func pathsAdminHook(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Query().Get("on") {
	case "0":
		pathsAdmin.Store(false)
	case "1":
		pathsAdmin.Store(true)
	default:
		http.Error(w, "on=0 or on=1", http.StatusBadRequest)
		return
	}
	fmt.Fprint(w, pathsAdmin.Load())
}

// harnessPaths is the fixed attack-path source: the real builder and ap-v1
// over internet -(tcp/443, KEV finding)-> host:e2e-host -(credential)->
// host:e2e-two, the harness hosts that are also on the traffic map, so
// the overlay draws a beam between two drawn nodes.
type harnessPaths struct{ snap paths.Snapshot }

func (p harnessPaths) Snapshot(context.Context) (paths.Snapshot, error) { return p.snap, nil }

func newHarnessPaths() (harnessPaths, error) {
	b := attackpath.NewBuilder()
	for _, n := range []attackpath.Node{
		{ID: "host:e2e-host", Kind: attackpath.NodeHost, Label: pathsEntryLabel},
		{ID: "host:e2e-two", Kind: attackpath.NodeHost, Label: pathsTargetLabel},
	} {
		if err := b.AddNode(n); err != nil {
			return harnessPaths{}, fmt.Errorf("attack-path node %s: %w", n.ID, err)
		}
	}
	for _, e := range []attackpath.Edge{
		{From: attackpath.InternetID, To: "host:e2e-host", Kind: attackpath.EdgeNetworkPolicy, Proto: attackpath.ProtoTCP, Port: 443},
		{From: "host:e2e-host", To: "host:e2e-two", Kind: attackpath.EdgeCredential},
	} {
		if err := b.AddEdge(e); err != nil {
			return harnessPaths{}, fmt.Errorf("attack-path edge %s -> %s: %w", e.From, e.To, err)
		}
	}
	g := b.Build()
	at := time.Date(2026, 11, 10, 9, 0, 0, 0, time.UTC)
	res, err := attackpath.Compute(g, []attackpath.Finding{{Node: "host:e2e-host", Key: "fk-web",
		Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", KEV: true, State: attackpath.FindingOpen,
		Ports: []attackpath.Port{{Proto: attackpath.ProtoTCP, Number: 443}}}},
		[]attackpath.Target{{Node: "host:e2e-two", Impact: 10}}, attackpath.Options{Now: func() time.Time { return at }})
	if err != nil {
		return harnessPaths{}, fmt.Errorf("attack paths: %w", err)
	}
	labels := map[string]string{}
	for _, n := range g.Nodes() {
		labels[n.ID] = n.Label
	}
	return harnessPaths{snap: paths.Snapshot{Result: res, ComputedAt: at, Labels: labels,
		Findings: map[paths.FindingRef]paths.FindingInfo{{Node: "host:e2e-host", Key: "fk-web"}: {
			VulnID: pathsVulnID, Package: pathsPackage,
			Fix: paths.FixLink{Href: "javascript:window.__pwned='paths-fix'", Text: "Update " + pathsPackage}}},
	}}, nil
}

// mountAttackPaths adds the attack-path pages like cmd/nebula-server's
// mountAttackPaths, with the harness admin rule (preview has no session
// and shows them).
func mountAttackPaths(pages *http.ServeMux, preview bool, origin string, log *slog.Logger) {
	src, err := newHarnessPaths()
	must(err)
	h, err := paths.New(paths.Options{
		Source: src,
		Authorize: func(r *http.Request) bool {
			_, ok := auth.SessionFrom(r.Context())
			return preview || (ok && pathsAdmin.Load())
		},
		PublicOrigin: origin,
		MapNode: func(id string) (string, bool) {
			h, ok := strings.CutPrefix(id, "host:")
			return h, ok && h != "" && !strings.Contains(h, ":")
		},
		Log: log,
	})
	must(err)
	h.Register(pages)
}

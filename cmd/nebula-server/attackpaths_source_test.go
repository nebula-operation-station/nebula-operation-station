// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"net/netip"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/attackpath/jewels"
	"github.com/nebula-operation-station/nebula-operation-station/internal/attackpath/sources"
	"github.com/nebula-operation-station/nebula-operation-station/internal/flowagg"
	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pveinventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/trafficstore"
)

// apTestRetention is the traffic retention of the attack-path tests.
const apTestRetention = 21 * 24 * time.Hour

var (
	apWebAddr    = netip.MustParseAddr("10.20.0.11")
	apAppAddr    = netip.MustParseAddr("10.20.0.12")
	apPublicAddr = netip.MustParseAddr("203.0.113.9")
)

// apSourceEnv is a server database with two managed hosts, web01 (a crown
// jewel) and app02 (an open finding, reached from the internet, with a
// stored flow to web01), the findings store of the server and the source
// over them.
type apSourceEnv struct {
	db   *sql.DB
	vt   *vtEnv
	inv  *inventory.Store
	src  *attackPathSource
	jewl *jewels.Store
}

// newAPSourceEnv builds the environment; the crown jewel and the finding
// are added by the caller (markWebJewel, submitAppFinding).
func newAPSourceEnv(t *testing.T) *apSourceEnv {
	t.Helper()
	vt := newVTEnv(t)
	db := vt.db
	ctx := context.Background()
	inv := inventory.New(db)
	for _, h := range []struct {
		id, name string
		addr     netip.Addr
	}{{"web01", "web01.lab", apWebAddr}, {"app02", "app02.lab", apAppAddr}} {
		if _, err := inv.Create(ctx, inventory.Host{ID: h.id, DisplayName: h.name, Environment: inventory.EnvProd,
			Criticality: inventory.CriticalityMedium,
			Endpoints:   []inventory.Endpoint{{Address: h.addr.String(), Port: 22}}, CredentialRef: h.id},
			inventory.CreateOptions{}); err != nil {
			t.Fatalf("create host %s: %v", h.id, err)
		}
	}
	ts, err := trafficstore.NewWithRetention(db, apTestRetention)
	if err != nil {
		t.Fatal(err)
	}
	// app02 serves 8080 to the internet and calls web01 on 443.
	hour := time.Now().Add(-time.Hour).Truncate(time.Hour)
	// Keys are in address order; Server names the side that listens. The
	// inbound flow is reported by its server (ServerReported), the outbound
	// one by its client: a host speaks only for its own end.
	for _, f := range []struct {
		key      flowagg.FlowKey
		serverRp bool
	}{
		{flowagg.FlowKey{A: apAppAddr, B: apPublicAddr, Proto: flowagg.TCP, ServerPort: 8080, Server: flowagg.SideA, Tier: flowagg.TierSocket}, true},
		{flowagg.FlowKey{A: apWebAddr, B: apAppAddr, Proto: flowagg.TCP, ServerPort: 443, Server: flowagg.SideA, Tier: flowagg.TierSocket}, false},
	} {
		b := trafficstore.Bucket{Hour: hour, Key: f.key, Reporter: "app02", BytesAB: 100, BytesBA: 100, Connections: 1, ServerReported: f.serverRp}
		if err := ts.UpsertBucket(ctx, b, []netip.Addr{apAppAddr}); err != nil {
			t.Fatal(err)
		}
	}
	jw, err := jewels.New(db, slog.New(slog.DiscardHandler), nil)
	if err != nil {
		t.Fatal(err)
	}
	pve := pveinventory.New(db)
	src := newAttackPathSource(serverDeps{db: db, vuln: vt.svc, retention: apTestRetention,
		log: slog.New(slog.DiscardHandler), pveStore: pve, inventory: inv})
	src.now = func() time.Time { return time.Now() }
	return &apSourceEnv{db: db, vt: vt, inv: inv, src: src, jewl: jw}
}

// markWebJewel makes web01 a crown jewel of impact 9.
func (e *apSourceEnv) markWebJewel(t *testing.T) {
	t.Helper()
	if _, err := e.jewl.Mark(context.Background(), jewels.Mark{Node: "host:web01", Role: jewels.RoleOther,
		Impact: 9, Admin: "admin", Reason: "payroll"}); err != nil {
		t.Fatal(err)
	}
}

// submitAppFinding stores a KEV-listed, network-reachable finding on app02.
func (e *apSourceEnv) submitAppFinding(t *testing.T) {
	t.Helper()
	r := vtRecord("CVE-2026-7001", true)
	r["subject_ref"] = map[string]any{"id": "app02"}
	r["scores"] = map[string]any{
		"kev": map[string]any{"date_added": "2026-11-01"},
		"cvss": map[string]any{"version": "3.1", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			"base_score": 9.8, "source": "nvd"},
	}
	e.vt.startAndSubmit(t, r)
}

// failingPlacements is a placement reader whose store cannot be read.
type failingPlacements struct{}

var errAPStoreDown = errors.New("store down")

func (failingPlacements) ListRemotes(context.Context, int) ([]pveinventory.Remote, error) {
	return nil, errAPStoreDown
}

func (failingPlacements) ListNodes(context.Context, string, int) ([]pveinventory.Node, error) {
	return nil, errAPStoreDown
}

func (failingPlacements) ListGuests(context.Context, string, pveinventory.GuestFilter, int) ([]pveinventory.Guest, error) {
	return nil, errAPStoreDown
}

func (failingPlacements) ListLinks(context.Context, string, int) ([]pveinventory.Link, error) {
	return nil, errAPStoreDown
}

func TestAttackPathSourceWithoutCrownJewelIsNotComputed(t *testing.T) {
	e := newAPSourceEnv(t)
	e.submitAppFinding(t)
	if err := e.src.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh without crown jewels: %v", err)
	}
	snap, err := e.src.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if snap.Result != nil || snap.Report != nil || !snap.ComputedAt.IsZero() {
		t.Fatalf("no crown jewel: snapshot = %+v, want not computed", snap)
	}
}

func TestAttackPathSourceComputesPathWithCoverage(t *testing.T) {
	e := newAPSourceEnv(t)
	e.markWebJewel(t)
	e.submitAppFinding(t)
	ctx := context.Background()
	if err := e.src.Refresh(ctx); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	snap, err := e.src.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if snap.Result == nil || snap.Report == nil || snap.ComputedAt.IsZero() {
		t.Fatalf("snapshot after a run = %+v, want a result, a report and a time", snap)
	}
	if snap.Labels["host:web01"] != "web01.lab" {
		t.Errorf("label of web01 = %q, want web01.lab", snap.Labels["host:web01"])
	}
	// Docker, firewall and VLAN are not read: the report names them missing
	// and the run is never complete.
	missing := map[string]bool{}
	for _, m := range snap.Report.Missing {
		missing[m] = true
	}
	for _, src := range []string{sources.SourceDocker, sources.SourceFirewall, sources.SourceVLAN} {
		if !missing[src] {
			t.Errorf("report does not name %s as missing: %v", src, snap.Report.Missing)
		}
	}
	if snap.Report.Complete() {
		t.Error("report reads complete with sources missing")
	}
}

func TestAttackPathSourceFailedReadKeepsLastSnapshot(t *testing.T) {
	e := newAPSourceEnv(t)
	e.markWebJewel(t)
	e.submitAppFinding(t)
	ctx := context.Background()
	if err := e.src.Refresh(ctx); err != nil {
		t.Fatalf("first Refresh: %v", err)
	}
	before, _ := e.src.Snapshot(ctx)
	if before.Result == nil {
		t.Fatal("first run has no result")
	}

	later := before.ComputedAt.Add(time.Hour)
	e.src.now = func() time.Time { return later }
	e.src.placements = failingPlacements{}
	if err := e.src.Refresh(ctx); err == nil || !errors.Is(err, errAPStoreDown) {
		t.Fatalf("Refresh with unreadable placements = %v, want the store error", err)
	}
	after, _ := e.src.Snapshot(ctx)
	if after.Result != before.Result || !after.ComputedAt.Equal(before.ComputedAt) {
		t.Fatalf("failed run replaced the snapshot: computed %v, want %v", after.ComputedAt, before.ComputedAt)
	}
}

func TestAttackPathSourceFindingsOfHostsOnly(t *testing.T) {
	e := newAPSourceEnv(t)
	e.markWebJewel(t)
	e.submitAppFinding(t)
	ctx := context.Background()
	if err := e.src.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	snap, _ := e.src.Snapshot(ctx)
	if snap.Result == nil {
		t.Fatal("no result")
	}
	for ref, fi := range snap.Findings {
		if ref.Node != "host:app02" || fi.VulnID != "CVE-2026-7001" {
			t.Errorf("finding %v = %+v, want CVE-2026-7001 on host:app02", ref, fi)
		}
	}
	if snap.Result.UnattachedFindings != 0 {
		t.Errorf("unattached findings = %d, want 0", snap.Result.UnattachedFindings)
	}
}

// TestAttackPathSourceRunsUntilCancelled: the loop computes at once and
// returns when its context ends (no ticker wait in the test).
func TestAttackPathSourceRunsUntilCancelled(t *testing.T) {
	e := newAPSourceEnv(t)
	e.markWebJewel(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { e.src.run(ctx); close(done) }()
	cancel()
	<-done
}

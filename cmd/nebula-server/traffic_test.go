// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/flowagg"
	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/ipam"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/trafficingest"
	"github.com/nebula-operation-station/nebula-operation-station/internal/trafficstore"
)

// The recorded net.facts outputs of internal/trafficingest: host-a is
// 192.168.10.37 / 52:54:00:00:10:37, host-b 192.168.10.20 /
// 52:54:00:00:10:20.
const trafficFixtures = "../../internal/trafficingest/testdata"

const (
	tfMACA = "52:54:00:00:10:37"
	tfMACB = "52:54:00:00:10:20"
)

var (
	tfT0    = time.Date(2026, 11, 5, 10, 0, 0, 0, time.UTC)
	tfAddrA = netip.MustParseAddr("192.168.10.37")
	tfAddrB = netip.MustParseAddr("192.168.10.20")
)

// netFactsResult assembles a net-facts-v1 result document from the
// recorded command outputs of host dir and its socket table ss.
func netFactsResult(t *testing.T, dir, ss string) []byte {
	t.Helper()
	read := func(name string) map[string]any {
		b, err := os.ReadFile(filepath.Join(trafficFixtures, dir, name))
		if err != nil {
			t.Fatalf("read fixture: %v", err)
		}
		return map[string]any{"status": "ok", "truncated": false, "data": base64.StdEncoding.EncodeToString(b)}
	}
	status := func(s string) map[string]any { return map[string]any{"status": s, "truncated": false, "data": ""} }
	b, err := json.Marshal(map[string]any{
		"format": "net-facts-v1", "phase": "done",
		"addr": read("addr.json"), "link": read("link.json"), "route": read("route.json"), "neigh": read("neigh.json"),
		"sockets": read(ss), "route6": status("unavailable"), "neigh6": status("unavailable"),
		"bridge_vlan": status("absent"), "lldp": status("absent"), "conntrack": status("absent"),
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// countingSyncer counts the Syncs the loop runs and keeps the last
// result, so a test can assert what a Sync did.
type countingSyncer struct {
	trafficSyncer
	n    int
	last trafficingest.SyncResult
}

func (c *countingSyncer) Sync(ctx context.Context) (trafficingest.SyncResult, error) {
	c.n++
	res, err := c.trafficSyncer.Sync(ctx)
	if err == nil {
		c.last = res
	}
	return res, err
}

// trafficEnv is a server database with inventory, IPAM, execution
// records and the wired traffic loop on a controllable clock.
type trafficEnv struct {
	t     *testing.T
	db    *sql.DB
	inv   *inventory.Store
	ipam  *ipam.Store
	store *trafficstore.Store
	loop  *trafficLoop
	sync  *countingSyncer
	now   time.Time
	n     int
}

func newTrafficEnv(t *testing.T) *trafficEnv {
	return newTrafficEnvWithRetention(t, trafficstore.DefaultRetention)
}

// newTrafficEnvWithRetention is newTrafficEnv with a configured traffic
// retention passed to the wired ingest loop.
func newTrafficEnvWithRetention(t *testing.T, retention time.Duration) *trafficEnv {
	t.Helper()
	db, err := serverdb.Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	e := &trafficEnv{t: t, db: db, inv: inventory.New(db), now: tfT0}
	e.ipam = ipam.New(db, ipam.FromInventory(e.inv.List))
	clock := func() time.Time { return e.now }
	e.store = trafficstore.NewWithNow(db, clock)
	e.loop, err = newTrafficIngest(db, e.inv.List, e.ipam.Assets, slog.New(slog.DiscardHandler), clock, retention)
	if err != nil {
		t.Fatal(err)
	}
	e.sync = &countingSyncer{trafficSyncer: e.loop.ing}
	e.loop.ing = e.sync
	return e
}

func (e *trafficEnv) host(id string, addrs ...string) {
	e.t.Helper()
	h := inventory.Host{ID: id, Environment: "DEV", Criticality: "LOW", CredentialRef: "lab"}
	for _, a := range addrs {
		h.Endpoints = append(h.Endpoints, inventory.Endpoint{Address: a})
	}
	if _, err := e.inv.Create(context.Background(), h, inventory.CreateOptions{}); err != nil {
		e.t.Fatalf("create host %s: %v", id, err)
	}
}

// nic records an IPAM asset with mac, linked to host when host != "".
func (e *trafficEnv) nic(id, mac, host string, addrs ...netip.Addr) {
	e.t.Helper()
	ctx := context.Background()
	if err := e.ipam.SaveAsset(ctx, ipam.Asset{ID: id, Name: id, Kind: ipam.KindServer, MAC: mac, Addresses: addrs}); err != nil {
		e.t.Fatalf("save asset %s: %v", id, err)
	}
	if err := e.ipam.LinkHost(ctx, id, host); err != nil {
		e.t.Fatalf("link asset %s: %v", id, err)
	}
}

// runAction records a finished, successful run of host for action, as
// the executions service stores it. result may be nil.
func (e *trafficEnv) runAction(action, host string, finished time.Time, result []byte) {
	e.t.Helper()
	e.n++
	id := fmt.Sprintf("%08d-0000-4000-8000-%012d", e.n, e.n)
	if _, err := e.db.Exec(`INSERT INTO executions (id, action_id, module_version, artifact_sha256, risk, state,
		durable, timeout_s, created_by, created_at, finished_at) VALUES (?, ?, '1.0.0', ?, 'read', 'finished', 0, 60, 'test', ?, ?)`,
		id, action, strings.Repeat("a", 64), finished.Unix()-1, finished.Unix()); err != nil {
		e.t.Fatal(err)
	}
	if _, err := e.db.Exec(`INSERT INTO execution_hosts (execution_id, host_id, fingerprint, credential_ref, endpoints,
		state, class, exit_code, result, started_at, finished_at) VALUES (?, ?, 'fp', 'cred', '[]', 'finished', 'success', 0, ?, ?, ?)`,
		id, host, result, finished.Unix()-1, finished.Unix()); err != nil {
		e.t.Fatal(err)
	}
}

// run records a finished, successful net.facts run of host, as the
// executions service stores it.
func (e *trafficEnv) run(host string, finished time.Time, result []byte) {
	e.runAction(trafficingest.ActionID, host, finished, result)
}

// expiredBucket inserts a flow bucket row directly, bypassing the
// store's retention validation, so the hourly prune has something
// expired to remove.
func (e *trafficEnv) expiredBucket(hour int64) {
	e.t.Helper()
	if _, err := e.db.Exec(`INSERT INTO flow_buckets (hour, a, b, proto, server_port, server_side, tier, server_reported, reporter)
		VALUES (?, '10.99.0.1', '10.99.0.2', 6, 22, 0, 'socket', 1, 'host-x')`, hour); err != nil {
		e.t.Fatal(err)
	}
}

func (e *trafficEnv) count(table string) int {
	e.t.Helper()
	var n int
	if err := e.db.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&n); err != nil {
		e.t.Fatal(err)
	}
	return n
}

func (e *trafficEnv) owner(mac string) string {
	e.t.Helper()
	ep, ok, err := e.store.LookupEndpoint(context.Background(), mac, netip.Addr{})
	if err != nil || !ok {
		e.t.Fatalf("lookup endpoint %s: %v %v", mac, ok, err)
	}
	return ep.Owner
}

// lab records host-a and host-b with their NICs and two net.facts
// rounds of each, checked by the loop after each round.
func (e *trafficEnv) lab() {
	e.t.Helper()
	e.host("host-a", tfAddrA.String(), "host-a.lan")
	e.host("host-b", tfAddrB.String())
	e.nic("nic-a", tfMACA, "host-a", tfAddrA)
	e.nic("nic-b", tfMACB, "host-b")
	ctx := context.Background()
	e.run("host-a", tfT0, netFactsResult(e.t, "host-a", "ss-t0.txt"))
	e.run("host-b", tfT0, netFactsResult(e.t, "host-b", "ss-t0.txt"))
	e.now = tfT0.Add(time.Minute)
	if !e.loop.check(ctx) {
		e.t.Fatal("first results not synced")
	}
	t1 := tfT0.Add(5 * time.Minute)
	e.run("host-a", t1, netFactsResult(e.t, "host-a", "ss-t1.txt"))
	e.run("host-b", t1, netFactsResult(e.t, "host-b", "ss-t1.txt"))
	e.now = t1.Add(time.Minute)
	if !e.loop.check(ctx) {
		e.t.Fatal("second results not synced")
	}
}

func TestTrafficIngestFlowsFromNetFactsResults(t *testing.T) {
	e := newTrafficEnv(t)
	assets := e.count("assets")
	e.lab()
	w := flowagg.Window{From: tfT0.Add(-time.Hour), To: e.now.Add(time.Hour)}
	ts, err := e.store.TopN(context.Background(), tfAddrA, w, 20)
	if err != nil {
		t.Fatal(err)
	}
	var ssh *flowagg.FlowTotal
	for i, f := range ts {
		if f.Key.A == tfAddrB && f.Key.B == tfAddrA && f.Key.ServerPort == 22 {
			ssh = &ts[i]
		}
	}
	// host-a served SSH to host-b: 720 bytes in, 3600 out between the
	// two recorded snapshots.
	if ssh == nil || ssh.BytesAB != 720 || ssh.BytesBA != 3600 || !ssh.ServerReported {
		t.Fatalf("ssh flow missing or wrong: %+v", ts)
	}
	// The NICs on record make each host the owner of its own endpoint.
	if o := e.owner(tfMACA); o != "host-a" {
		t.Fatalf("owner of host-a's NIC = %q", o)
	}
	if o := e.owner(tfMACB); o != "host-b" {
		t.Fatalf("owner of host-b's NIC = %q", o)
	}
	// Endpoints are facts: no hosts or assets appear.
	if h := e.count("hosts"); h != 2 {
		t.Fatalf("hosts = %d, want 2", h)
	}
	if a := e.count("assets"); a != assets+2 {
		t.Fatalf("assets = %d, want %d", a, assets+2)
	}
}

func TestTrafficIngestSilentFormerOwnerLosesOwnership(t *testing.T) {
	e := newTrafficEnv(t)
	e.lab()
	if o := e.owner(tfMACA); o != "host-a" {
		t.Fatalf("owner = %q", o)
	}
	// The NIC is moved to host-b in the IPAM; host-a sends no new
	// result. The record change alone must drop host-a's ownership,
	// without waiting for the hourly reconcile.
	runs := e.sync.n
	if err := e.ipam.LinkHost(context.Background(), "nic-a", "host-b"); err != nil {
		t.Fatal(err)
	}
	e.now = e.now.Add(time.Second)
	if !e.loop.check(context.Background()) || e.sync.n != runs+1 {
		t.Fatal("record change did not sync")
	}
	if o := e.owner(tfMACA); o != "" {
		t.Fatalf("silent former owner kept ownership: %q", o)
	}
}

func TestTrafficLoopSyncsOnlyOnChange(t *testing.T) {
	e := newTrafficEnv(t)
	e.lab()
	ctx := context.Background()
	runs := e.sync.n
	// Nothing new, same hour: no Sync.
	e.now = e.now.Add(time.Minute)
	if e.loop.check(ctx) || e.sync.n != runs {
		t.Fatal("synced without change")
	}
	// A new net.facts result in the same second as the last one.
	e.run("host-b", tfT0.Add(5*time.Minute), netFactsResult(t, "host-b", "ss-t1.txt"))
	if !e.loop.check(ctx) {
		t.Fatal("new result not synced")
	}
	// The mark change alone neither reconciles nor prunes: both stay
	// bound to record changes and the clock hour.
	if e.sync.last.Reconciled || e.sync.last.Pruned {
		t.Fatalf("mark-change sync reconciled or pruned: %+v", e.sync.last)
	}
	// An inventory change.
	h, err := e.inv.Get(ctx, "host-b")
	if err != nil {
		t.Fatal(err)
	}
	h.Endpoints = append(h.Endpoints, inventory.Endpoint{Address: "192.168.10.21"})
	if _, err := e.inv.Update(ctx, h); err != nil {
		t.Fatal(err)
	}
	if !e.loop.check(ctx) {
		t.Fatal("inventory change not synced")
	}
	// The changed records reconcile, but the prune stays hourly.
	if !e.sync.last.Reconciled || e.sync.last.Pruned {
		t.Fatalf("record-change sync: %+v", e.sync.last)
	}
	if e.loop.check(ctx) {
		t.Fatal("synced twice")
	}
	// A bucket older than the retention, outside anything the store
	// would accept: the hourly prune must remove it.
	expired := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC).Unix() / 3600
	e.expiredBucket(expired)
	// The next clock hour (hourly reconcile and prune in the ingester).
	e.now = e.now.Add(time.Hour)
	if !e.loop.check(ctx) {
		t.Fatal("hourly sync missing")
	}
	// The hourly Sync must have reconciled and pruned.
	if !e.sync.last.Reconciled || !e.sync.last.Pruned {
		t.Fatalf("hourly sync skipped reconcile or prune: %+v", e.sync.last)
	}
	var n int
	if err := e.db.QueryRow(`SELECT COUNT(*) FROM flow_buckets WHERE hour = ?`, expired).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("expired bucket survived the hourly prune: %d rows", n)
	}
	if n := e.count("flow_buckets"); n < 1 {
		t.Fatalf("prune removed the fresh buckets: %d left", n)
	}
}

// TestTrafficIngestPrunesToConfiguredRetention checks that the ingest
// store prunes to the configured retention, not the 21-day default:
// with a 7-day retention the first (hourly) Sync removes a 10-day-old
// bucket that the default retention would keep.
func TestTrafficIngestPrunesToConfiguredRetention(t *testing.T) {
	e := newTrafficEnvWithRetention(t, 7*24*time.Hour)
	ctx := context.Background()
	// A bucket 10 days before the first check: inside the 21-day
	// default, outside the 7-day retention.
	old := tfT0.Add(-10*24*time.Hour).Truncate(time.Hour).Unix() / 3600
	e.expiredBucket(old)
	if !e.loop.check(ctx) {
		t.Fatal("first check did not sync")
	}
	if !e.sync.last.Pruned {
		t.Fatalf("first sync did not prune: %+v", e.sync.last)
	}
	var n int
	if err := e.db.QueryRow(`SELECT COUNT(*) FROM flow_buckets WHERE hour = ?`, old).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("10d-old bucket survived the prune with a 7d retention: %d rows", n)
	}
}

// TestNetFactsMarkPlanUsesActionIndex pins the 30 s change-mark query
// to the idx_executions_action_id index: without it the planner scans
// the whole executions table (or all of execution_hosts) on every
// check, so the poll's cost grows with the retained history of every
// action instead of only the net.facts runs.
func TestNetFactsMarkPlanUsesActionIndex(t *testing.T) {
	e := newTrafficEnv(t)
	ctx := context.Background()
	// Retained history: many runs of other actions plus a handful of
	// net.facts runs, as in a lab that keeps its execution history.
	for i := 0; i < 300; i++ {
		e.runAction("reboot", fmt.Sprintf("host-%02d", i%10), tfT0.Add(time.Duration(i)*time.Second), nil)
	}
	for i := 0; i < 20; i++ {
		e.run("host-a", tfT0.Add(time.Duration(i)*time.Hour), nil)
	}
	var details []string
	rows, err := e.db.QueryContext(ctx, "EXPLAIN QUERY PLAN "+netFactsMarkSQL, trafficingest.ActionID)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var id, parent, notused int
		var detail string
		if err := rows.Scan(&id, &parent, &notused, &detail); err != nil {
			t.Fatal(err)
		}
		details = append(details, detail)
	}
	if err := rows.Close(); err != nil {
		t.Fatal(err)
	}
	plan := strings.Join(details, "\n")
	if !strings.Contains(plan, "idx_executions_action_id") {
		t.Fatalf("mark query does not use the action index:\n%s", plan)
	}
	for _, d := range details {
		if strings.HasPrefix(d, "SCAN e") {
			t.Fatalf("mark query scans all executions:\n%s", plan)
		}
	}
}

func TestTrafficRecordsOnlyFromServerRecords(t *testing.T) {
	e := newTrafficEnv(t)
	shared := netip.MustParseAddr("192.168.10.99")
	e.host("host-a", tfAddrA.String(), "host-a.lan", "fe80::1", shared.String())
	e.host("host-b", tfAddrB.String(), shared.String())
	e.nic("nic-a", tfMACA, "host-a", netip.MustParseAddr("10.0.0.7"))
	// The same MAC recorded for host-b and host-a: it belongs to neither.
	e.nic("dup", tfMACA, "host-b")
	e.nic("nic-b", tfMACB, "host-b")
	// Not linked, or linked to a host that is not managed: ignored.
	e.nic("loose", "52:54:00:00:77:77", "", netip.MustParseAddr("10.0.0.8"))
	e.nic("ghost", "52:54:00:00:88:88", "host-z", netip.MustParseAddr("10.0.0.9"))

	recs, err := e.loop.records.HostIdentities(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 {
		t.Fatalf("records = %+v, want host-a and host-b only", recs)
	}
	got := trafficingest.Exclusive(recs)
	wantA := []netip.Addr{netip.MustParseAddr("10.0.0.7"), netip.MustParseAddr("fe80::1"), tfAddrA}
	slices.SortFunc(wantA, netip.Addr.Compare)
	if !slices.Equal(got["host-a"].Addrs, wantA) || len(got["host-a"].MACs) != 0 {
		t.Fatalf("host-a = %+v", got["host-a"])
	}
	if !slices.Equal(got["host-b"].Addrs, []netip.Addr{tfAddrB}) || !slices.Equal(got["host-b"].MACs, []string{tfMACB}) {
		t.Fatalf("host-b = %+v", got["host-b"])
	}
}

func TestTrafficRecordsHostLimitFailsClosed(t *testing.T) {
	e := newTrafficEnv(t)
	e.host("host-a", tfAddrA.String())
	e.host("host-b", tfAddrB.String())
	r := e.loop.records.(trafficRecords)
	r.maxHosts = 1
	if _, err := r.HostIdentities(context.Background()); !errors.Is(err, errTooManyTrafficHosts) {
		t.Fatalf("err = %v", err)
	}
	// The loop does not sync from a failed record load.
	e.loop.records = r
	if e.loop.check(context.Background()) || e.sync.n != 0 {
		t.Fatal("synced without records")
	}
}

func TestTrafficLoopRetriesAfterFailedRecords(t *testing.T) {
	e := newTrafficEnv(t)
	e.host("host-a", tfAddrA.String())
	fail := true
	e.loop.records = trafficRecords{maxHosts: maxTrafficHosts, assets: e.ipam.Assets,
		hosts: func(ctx context.Context) ([]inventory.Host, error) {
			if fail {
				return nil, errors.New("db busy")
			}
			return e.inv.List(ctx)
		}}
	if e.loop.check(context.Background()) {
		t.Fatal("synced without records")
	}
	fail = false
	if !e.loop.check(context.Background()) {
		t.Fatal("no sync after recovery")
	}
}

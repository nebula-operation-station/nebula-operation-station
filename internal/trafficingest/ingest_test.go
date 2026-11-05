// SPDX-License-Identifier: AGPL-3.0-or-later

package trafficingest

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/flowagg"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/trafficstore"
)

var t0 = time.Date(2026, 11, 5, 10, 0, 0, 0, time.UTC)

const (
	macA  = "52:54:00:00:10:37"
	macB  = "52:54:00:00:10:20"
	macGW = "52:54:00:00:10:01"
)

var (
	addrA  = netip.MustParseAddr("192.168.10.37")
	addrB  = netip.MustParseAddr("192.168.10.20")
	addrGW = netip.MustParseAddr("192.168.10.1")
)

// env is a server database with execution records, a traffic store and
// an ingester on a controllable clock.
type env struct {
	t       *testing.T
	db      *sql.DB
	store   *trafficstore.Store
	spy     *spyStore
	records *staticRecords
	now     time.Time
	in      *Ingester
	n       int
}

type staticRecords struct {
	ids map[string]trafficstore.Identity
	err error
}

func (r *staticRecords) HostIdentities(context.Context) (map[string]trafficstore.Identity, error) {
	out := make(map[string]trafficstore.Identity, len(r.ids))
	for k, v := range r.ids {
		out[k] = v
	}
	return out, r.err
}

// spyStore records the reconcile and prune calls of the real store.
type spyStore struct {
	*trafficstore.Store
	reconciles []map[string]trafficstore.Identity
	prunes     int
}

func (s *spyStore) ReconcileIdentities(ctx context.Context, cur map[string]trafficstore.Identity) (trafficstore.ReconcileResult, error) {
	s.reconciles = append(s.reconciles, cur)
	return s.Store.ReconcileIdentities(ctx, cur)
}

func (s *spyStore) Prune(ctx context.Context) (int64, int64, error) {
	s.prunes++
	return s.Store.Prune(ctx)
}

func defaultRecords() map[string]trafficstore.Identity {
	return map[string]trafficstore.Identity{
		"host-a": {MACs: []string{macA}, Addrs: []netip.Addr{addrA}},
		"host-b": {MACs: []string{macB}, Addrs: []netip.Addr{addrB}},
	}
}

func newEnv(t *testing.T) *env {
	t.Helper()
	db, err := serverdb.Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	e := &env{t: t, db: db, now: t0, records: &staticRecords{ids: defaultRecords()}}
	e.store = trafficstore.NewWithNow(db, func() time.Time { return e.now })
	e.spy = &spyStore{Store: e.store}
	e.in = e.newIngester()
	return e
}

func (e *env) newIngester() *Ingester {
	e.t.Helper()
	in, err := New(Config{Source: ExecutionSource{DB: e.db}, Records: e.records, Store: e.spy,
		Now: func() time.Time { return e.now }})
	if err != nil {
		e.t.Fatalf("new ingester: %v", err)
	}
	return in
}

// run records a finished, successful net.facts run of host.
func (e *env) run(host string, finished time.Time, result []byte) string {
	e.t.Helper()
	e.n++
	id := fmt.Sprintf("%08d-0000-4000-8000-%012d", e.n, e.n)
	if _, err := e.db.Exec(`INSERT INTO executions (id, action_id, module_version, artifact_sha256, risk, state,
		durable, timeout_s, created_by, created_at, finished_at) VALUES (?, ?, '1.0.0', ?, 'read', 'finished', 0, 60, 'test', ?, ?)`,
		id, ActionID, strings.Repeat("a", 64), finished.Unix()-1, finished.Unix()); err != nil {
		e.t.Fatalf("insert execution: %v", err)
	}
	if _, err := e.db.Exec(`INSERT INTO execution_hosts (execution_id, host_id, fingerprint, credential_ref, endpoints,
		state, class, exit_code, result, started_at, finished_at) VALUES (?, ?, 'fp', 'cred', '[]', 'finished', 'success', 0, ?, ?, ?)`,
		id, host, result, finished.Unix()-1, finished.Unix()); err != nil {
		e.t.Fatalf("insert execution host: %v", err)
	}
	return id
}

func (e *env) sync() SyncResult {
	e.t.Helper()
	res, err := e.in.Sync(context.Background())
	if err != nil {
		e.t.Fatalf("sync: %v", err)
	}
	for _, h := range res.Hosts {
		if h.Err != nil {
			e.t.Fatalf("host %s: %v", h.Host, h.Err)
		}
	}
	return res
}

func hostResult(t *testing.T, res SyncResult, host string) HostResult {
	t.Helper()
	for _, h := range res.Hosts {
		if h.Host == host {
			return h
		}
	}
	t.Fatalf("no result for %s in %+v", host, res.Hosts)
	return HostResult{}
}

func (e *env) buckets() int {
	e.t.Helper()
	n, err := e.store.CountBuckets(context.Background())
	if err != nil {
		e.t.Fatalf("count buckets: %v", err)
	}
	return n
}

func (e *env) top(node netip.Addr) []flowagg.FlowTotal {
	e.t.Helper()
	w := flowagg.Window{From: t0.Add(-time.Hour), To: e.now.Add(time.Hour)}
	ts, err := e.store.TopN(context.Background(), node, w, 20)
	if err != nil {
		e.t.Fatalf("TopN: %v", err)
	}
	return ts
}

func findFlow(ts []flowagg.FlowTotal, a, b string, port uint16) (flowagg.FlowTotal, bool) {
	for _, f := range ts {
		if f.Key.A.String() == a && f.Key.B.String() == b && f.Key.ServerPort == port {
			return f, true
		}
	}
	return flowagg.FlowTotal{}, false
}

// twoRounds ingests the recorded t0 and t1 snapshots of both hosts.
func (e *env) twoRounds() {
	e.t.Helper()
	e.run("host-a", t0, netFactsDoc(e.t, "host-a", "ss-t0.txt"))
	e.run("host-b", t0, netFactsDoc(e.t, "host-b", "ss-t0.txt"))
	e.now = t0.Add(time.Minute)
	r := e.sync()
	for _, h := range r.Hosts {
		if h.Outcome != OutcomeBaseline {
			e.t.Fatalf("first round %s: outcome %s, want baseline", h.Host, h.Outcome)
		}
	}
	if n := e.buckets(); n != 0 {
		e.t.Fatalf("baseline wrote %d buckets", n)
	}
	t1 := t0.Add(5 * time.Minute)
	e.run("host-a", t1, netFactsDoc(e.t, "host-a", "ss-t1.txt"))
	e.run("host-b", t1, netFactsDoc(e.t, "host-b", "ss-t1.txt"))
	e.now = t1.Add(time.Minute)
	r = e.sync()
	for _, h := range r.Hosts {
		if h.Outcome != OutcomeFlows {
			e.t.Fatalf("second round %s: outcome %s, want flows", h.Host, h.Outcome)
		}
	}
}

func TestIngestRecordedSnapshotsToFlows(t *testing.T) {
	e := newEnv(t)
	e.twoRounds()
	ts := e.top(addrA)

	ssh, ok := findFlow(ts, "192.168.10.20", "192.168.10.37", 22)
	if !ok {
		t.Fatalf("ssh flow missing: %+v", ts)
	}
	// Server end (host-a) counted: .37 sent 3600 to .20, received 720.
	if ssh.BytesAB != 720 || ssh.BytesBA != 3600 || !ssh.ServerReported || !ssh.Confirmed {
		t.Fatalf("ssh flow = %+v", ssh)
	}
	if ssh.Key.Server != flowagg.SideB || ssh.Key.Proto != flowagg.TCP || ssh.Key.Tier != flowagg.TierSocket {
		t.Fatalf("ssh key = %+v", ssh.Key)
	}
	// Mapped IPv4 local on a dual-stack listener: host-a is the server.
	exp, ok := findFlow(ts, "192.168.10.37", "192.168.20.5", 9100)
	if !ok || exp.BytesAB != 360000 || exp.BytesBA != 360 || !exp.ServerReported {
		t.Fatalf("exporter flow = %+v %v", exp, ok)
	}
	web, ok := findFlow(ts, "1.1.1.1", "192.168.10.37", 443)
	if !ok || web.BytesAB != 36000 || web.BytesBA != 360 || web.ServerReported {
		t.Fatalf("web flow = %+v %v", web, ok)
	}
	for _, f := range ts {
		if f.Key.A.IsLoopback() || f.Key.B.IsLoopback() || f.Key.ServerPort == 40130 {
			t.Fatalf("loopback or TIME-WAIT flow stored: %+v", f)
		}
	}
	if len(ts) != 3 {
		t.Fatalf("flows = %d, want 3: %+v", len(ts), ts)
	}
}

func TestIngestIsIdempotent(t *testing.T) {
	e := newEnv(t)
	e.twoRounds()
	before, nb := e.top(addrA), e.buckets()
	epBefore, _ := e.store.CountEndpoints(context.Background())

	// The same executions again: nothing changes.
	r := e.sync()
	for _, h := range r.Hosts {
		if h.Outcome != OutcomeUnchanged || h.Buckets != 0 || h.Endpoints != 0 {
			t.Fatalf("repeat %s = %+v", h.Host, h)
		}
	}
	// A restarted ingester sees the same latest results: a baseline that
	// counts nothing.
	e.in = e.newIngester()
	r = e.sync()
	for _, h := range r.Hosts {
		if h.Outcome != OutcomeBaseline || h.Buckets != 0 {
			t.Fatalf("after restart %s = %+v", h.Host, h)
		}
	}
	if after := e.top(addrA); !slices.Equal(after, before) || e.buckets() != nb {
		t.Fatalf("flows changed:\nbefore %+v\nafter  %+v", before, after)
	}
	if epAfter, _ := e.store.CountEndpoints(context.Background()); epAfter != epBefore {
		t.Fatalf("endpoints %d -> %d", epBefore, epAfter)
	}
}

func TestIngestSameTimeOtherExecutionIsStale(t *testing.T) {
	e := newEnv(t)
	e.run("host-a", t0, netFactsDoc(t, "host-a", "ss-t0.txt"))
	e.now = t0.Add(time.Minute)
	e.sync()
	// A second run in the same second with a higher ID becomes "latest"
	// but is not newer: it must not be diffed or counted.
	e.run("host-a", t0, netFactsDoc(t, "host-a", "ss-t1.txt"))
	if got := hostResult(t, e.sync(), "host-a"); got.Outcome != OutcomeStale {
		t.Fatalf("outcome = %s, want stale", got.Outcome)
	}
	if e.buckets() != 0 {
		t.Fatal("stale result counted")
	}
}

func TestIngestReporterLabelsAreServerHostIDs(t *testing.T) {
	e := newEnv(t)
	e.twoRounds()
	ctx := context.Background()
	gw, ok, err := e.store.LookupEndpoint(ctx, macGW, netip.Addr{})
	if err != nil || !ok {
		t.Fatalf("gateway endpoint: %v %v", ok, err)
	}
	if !slices.Equal(gw.SeenBy, []string{"host-a", "host-b"}) || gw.Owner != "" {
		t.Fatalf("gateway seen by %v owner %q", gw.SeenBy, gw.Owner)
	}
	for _, o := range gw.Observations {
		if o.Tier != flowagg.TierSocket || !o.LastSeen.Equal(t0.Add(5*time.Minute)) {
			t.Fatalf("observation %+v: want socket tier and the server's finish time", o)
		}
	}
	// host-a's own NIC: owned by host-a through the server's records.
	a, ok, err := e.store.LookupEndpoint(ctx, macA, netip.Addr{})
	if err != nil || !ok || a.Owner != "host-a" || a.HostID != "host-a" {
		t.Fatalf("host-a endpoint = %+v %v %v", a, ok, err)
	}
	// The flow buckets carry the reporting host as server and client end.
	var reporters []string
	rows, err := e.db.Query(`SELECT DISTINCT reporter FROM flow_buckets ORDER BY reporter`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var r string
		if err := rows.Scan(&r); err != nil {
			t.Fatal(err)
		}
		reporters = append(reporters, r)
	}
	if !slices.Equal(reporters, []string{"host-a", "host-b"}) {
		t.Fatalf("bucket reporters = %v", reporters)
	}
}

// mismatchSource returns another host's record.
type mismatchSource struct{ Source }

func (m mismatchSource) LatestNetFacts(ctx context.Context, host string) (Result, bool, error) {
	r, ok, err := m.Source.LatestNetFacts(ctx, "host-b")
	return r, ok, err
}

func TestIngestRefusesResultOfOtherHost(t *testing.T) {
	e := newEnv(t)
	e.records.ids = map[string]trafficstore.Identity{"host-a": defaultRecords()["host-a"]}
	e.run("host-b", t0, netFactsDoc(t, "host-b", "ss-t0.txt"))
	in, err := New(Config{Source: mismatchSource{ExecutionSource{DB: e.db}}, Records: e.records, Store: e.spy,
		Now: func() time.Time { return e.now }})
	if err != nil {
		t.Fatal(err)
	}
	e.now = t0.Add(time.Minute)
	res, err := in.Sync(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if h := hostResult(t, res, "host-a"); h.Outcome != OutcomeInvalid || h.Err == nil {
		t.Fatalf("result = %+v", h)
	}
	if n, _ := e.store.CountEndpoints(context.Background()); n != 0 {
		t.Fatalf("%d endpoints written from another host's result", n)
	}
}

func TestIngestOwnAddressesOnlyFromServerRecords(t *testing.T) {
	e := newEnv(t)
	// host-a lies: its address table claims host-b's address, and it
	// reports a socket served from host-b's address and port 22.
	lie := func(ss string) []byte {
		b := readFixture(t, filepath.Join("host-a", ss))
		return append(b, []byte("tcp   ESTAB  0      0         192.168.10.20:22   192.168.10.99:5555\n\t cubic bytes_acked:777 bytes_received:777\n")...)
	}
	addr := bytes.Replace(readFixture(t, "host-a/addr.json"),
		[]byte(`{"family":"inet","local":"192.168.10.37","prefixlen":24}`),
		[]byte(`{"family":"inet","local":"192.168.10.37","prefixlen":24},{"family":"inet","local":"192.168.10.20","prefixlen":24}`), 1)
	doc := func(ss string) []byte {
		return netFactsDocWith(t, "host-a", lie(ss), map[string]fixtureSection{"addr": okSection(addr)})
	}
	e.run("host-a", t0, doc("ss-t0.txt"))
	e.now = t0.Add(time.Minute)
	e.sync()
	e.run("host-a", t0.Add(5*time.Minute), doc("ss-t1.txt"))
	e.now = t0.Add(6 * time.Minute)
	e.sync()
	if _, ok := findFlow(e.top(netip.MustParseAddr("192.168.10.99")), "192.168.10.20", "192.168.10.99", 22); ok {
		t.Fatal("flow on host-b's address accepted from host-a")
	}
	// The forged socket is foreign; host-a's own flows are unaffected.
	if h := e.top(addrA); len(h) != 3 {
		t.Fatalf("host-a's own flows = %+v", h)
	}
}

func TestIngestSharedRecordedAddressBelongsToNoHost(t *testing.T) {
	e := newEnv(t)
	ids := defaultRecords()
	// Both hosts have 192.168.10.37 on record (a stale inventory entry):
	// neither may speak for it.
	b := ids["host-b"]
	b.Addrs = append(b.Addrs, addrA)
	ids["host-b"] = b
	e.records.ids = ids
	for i, ss := range []string{"ss-t0.txt", "ss-t1.txt"} {
		at := t0.Add(time.Duration(i) * 5 * time.Minute)
		e.run("host-a", at, netFactsDoc(t, "host-a", ss))
		e.run("host-b", at, netFactsDoc(t, "host-b", ss))
		e.now = at.Add(time.Minute)
		e.sync()
	}
	if h := hostResult(t, e.sync(), "host-a"); h.Outcome != OutcomeUnchanged {
		t.Fatalf("host-a = %+v", h)
	}
	if ts := e.top(addrA); len(ts) != 1 {
		// Only host-b's client report of the ssh flow (its own end .20).
		t.Fatalf("flows with the shared address = %+v", ts)
	}
	if f, ok := findFlow(e.top(addrA), "192.168.10.20", "192.168.10.37", 22); !ok || f.ServerReported {
		t.Fatalf("ssh flow = %+v %v (server end must not be accepted)", f, ok)
	}
}

func okSection(b []byte) fixtureSection {
	return fixtureSection{Status: "ok", Data: b64(b)}
}

func TestIngestIncompleteSocketsStartFreshBaseline(t *testing.T) {
	e := newEnv(t)
	e.records.ids = map[string]trafficstore.Identity{"host-a": defaultRecords()["host-a"]}
	e.run("host-a", t0, netFactsDoc(t, "host-a", "ss-t0.txt"))
	e.now = t0.Add(time.Minute)
	e.sync()
	// Truncated socket table: sockets are missing.
	cut := netFactsDocWith(t, "host-a", nil, map[string]fixtureSection{
		"sockets": {Status: "ok", Truncated: true, Data: b64(readFixture(t, "host-a/ss-t1.txt")[:200])},
	})
	e.run("host-a", t0.Add(5*time.Minute), cut)
	e.now = t0.Add(6 * time.Minute)
	if h := hostResult(t, e.sync(), "host-a"); h.Outcome != OutcomeNoFlows || !h.Incomplete {
		t.Fatalf("cut result = %+v", h)
	}
	// The next complete snapshot is a baseline, not a diff against t0.
	e.run("host-a", t0.Add(10*time.Minute), netFactsDoc(t, "host-a", "ss-t1.txt"))
	e.now = t0.Add(11 * time.Minute)
	if h := hostResult(t, e.sync(), "host-a"); h.Outcome != OutcomeBaseline {
		t.Fatalf("after cut = %+v", h)
	}
	if e.buckets() != 0 {
		t.Fatal("bytes counted across an incomplete snapshot")
	}
}

func TestIngestLongGapIsFreshBaseline(t *testing.T) {
	e := newEnv(t)
	e.records.ids = map[string]trafficstore.Identity{"host-a": defaultRecords()["host-a"]}
	e.run("host-a", t0, netFactsDoc(t, "host-a", "ss-t0.txt"))
	e.now = t0.Add(time.Minute)
	e.sync()
	t1 := t0.Add(2 * time.Hour)
	e.run("host-a", t1, netFactsDoc(t, "host-a", "ss-t1.txt"))
	e.now = t1.Add(time.Minute)
	if h := hostResult(t, e.sync(), "host-a"); h.Outcome != OutcomeBaseline || h.Err != nil {
		t.Fatalf("long gap = %+v", h)
	}
	if e.buckets() != 0 {
		t.Fatal("bytes of a too-long interval counted")
	}
	// The snapshot after the gap is the new baseline: the next diff counts.
	ss2 := bytes.ReplaceAll(readFixture(t, "host-a/ss-t1.txt"), []byte("bytes_acked:13600"), []byte("bytes_acked:14600"))
	e.run("host-a", t1.Add(5*time.Minute), netFactsDocWith(t, "host-a", ss2, nil))
	e.now = t1.Add(6 * time.Minute)
	if h := hostResult(t, e.sync(), "host-a"); h.Outcome != OutcomeFlows {
		t.Fatalf("after gap = %+v", h)
	}
	f, ok := findFlow(e.top(addrA), "192.168.10.20", "192.168.10.37", 22)
	if !ok || f.BytesBA != 1000 || f.Connections != 0 {
		t.Fatalf("flow after gap = %+v %v", f, ok)
	}
}

func TestIngestSplitsIntervalAcrossHours(t *testing.T) {
	e := newEnv(t)
	e.records.ids = map[string]trafficstore.Identity{"host-a": defaultRecords()["host-a"]}
	start := t0.Add(-3 * time.Minute) // 09:57
	e.run("host-a", start, netFactsDoc(t, "host-a", "ss-t0.txt"))
	e.now = start.Add(time.Second)
	e.sync()
	e.run("host-a", start.Add(6*time.Minute), netFactsDoc(t, "host-a", "ss-t1.txt")) // 10:03
	e.now = start.Add(7 * time.Minute)
	h := hostResult(t, e.sync(), "host-a")
	if h.Outcome != OutcomeFlows || h.Buckets != 6 {
		t.Fatalf("result = %+v (want 3 flows x 2 hours)", h)
	}
	var sum int64
	if err := e.db.QueryRow(`SELECT SUM(bytes_ba) FROM flow_buckets WHERE server_port = 22`).Scan(&sum); err != nil {
		t.Fatal(err)
	}
	if sum != 3600 {
		t.Fatalf("ssh bytes over both hours = %d, want 3600", sum)
	}
}

func TestIngestGatewayHopFromResult(t *testing.T) {
	e := newEnv(t)
	e.twoRounds()
	hn, ok := e.in.HostNet("host-a")
	if !ok {
		t.Fatal("no host net")
	}
	if len(hn.Defaults) != 1 || hn.Defaults[0].Addr != addrGW || hn.Defaults[0].MAC != macGW {
		t.Fatalf("defaults = %+v", hn.Defaults)
	}
	// The exporter flow goes to another subnet: A → gateway → B.
	gw, ok := hn.Hop(netip.MustParseAddr("192.168.20.5"))
	if !ok || gw.MAC != macGW {
		t.Fatalf("hop = %+v %v", gw, ok)
	}
	// The gateway's MAC names a stored endpoint the map can draw.
	ep, ok, err := e.store.LookupEndpoint(context.Background(), gw.MAC, netip.Addr{})
	if err != nil || !ok || !slices.Contains(ep.Addresses, addrGW) {
		t.Fatalf("gateway endpoint = %+v %v %v", ep, ok, err)
	}
	if _, ok := hn.Hop(addrB); ok {
		t.Fatal("same-subnet peer has a hop")
	}
}

func TestIngestRefusesUntrustedResults(t *testing.T) {
	big := append([]byte(`{"format":"net-facts-v1","phase":"done","pad":"`), bytes.Repeat([]byte("A"), 1<<20)...)
	big = append(big, '"', '}')
	tests := map[string][]byte{
		"not json":         []byte("<html>"),
		"wrong format":     []byte(`{"format":"net-facts-v2","phase":"done"}`),
		"unknown field":    []byte(`{"format":"net-facts-v1","phase":"done","host":"host-b"}`),
		"over 1 MiB":       big,
		"trailing data":    append(netFactsDoc(t, "host-a", "ss-t0.txt"), []byte(" {}")...),
		"empty":            nil,
		"invalid utf8 b64": []byte(`{"format":"net-facts-v1","phase":"done","addr":{"status":"ok","truncated":false,"data":"\xff"}}`),
	}
	for name, doc := range tests {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			e.records.ids = map[string]trafficstore.Identity{"host-a": defaultRecords()["host-a"]}
			e.run("host-a", t0, doc)
			e.now = t0.Add(time.Minute)
			res, err := e.in.Sync(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if h := hostResult(t, res, "host-a"); h.Outcome != OutcomeInvalid || h.Err == nil {
				t.Fatalf("result = %+v", h)
			}
			if n, _ := e.store.CountEndpoints(context.Background()); n != 0 {
				t.Fatalf("%d endpoints from an invalid result", n)
			}
			// Seen once, not retried every round.
			res, _ = e.in.Sync(context.Background())
			if h := hostResult(t, res, "host-a"); h.Outcome != OutcomeUnchanged {
				t.Fatalf("second round = %+v", h)
			}
		})
	}
}

func TestIngestRefusesFutureFinishTime(t *testing.T) {
	e := newEnv(t)
	e.records.ids = map[string]trafficstore.Identity{"host-a": defaultRecords()["host-a"]}
	e.run("host-a", t0.Add(time.Hour), netFactsDoc(t, "host-a", "ss-t0.txt"))
	res, err := e.in.Sync(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if h := hostResult(t, res, "host-a"); h.Outcome != OutcomeInvalid {
		t.Fatalf("result = %+v", h)
	}
}

func TestIngestHostileNeighborEntriesAreDropped(t *testing.T) {
	e := newEnv(t)
	e.records.ids = map[string]trafficstore.Identity{"host-a": defaultRecords()["host-a"]}
	neigh := []byte(`[
	 {"dst":"224.0.0.251","dev":"eth0","lladdr":"01:00:5e:00:00:fb","state":["NOARP"]},
	 {"dst":"192.168.10.50","dev":"eth0","lladdr":"ff:ff:ff:ff:ff:ff","state":["REACHABLE"]},
	 {"dst":"127.0.0.1","dev":"lo","lladdr":"02:00:00:00:00:01","state":["REACHABLE"]},
	 {"dst":"192.168.10.51","dev":"eth0\u001b[31m","lladdr":"02:00:00:00:00:51","state":["REACHABLE"]},
	 {"dst":"192.168.10.52","dev":"eth0","lladdr":"02:00:00:00:00:52","state":["REACHABLE"]}
	]`)
	e.run("host-a", t0, netFactsDocWith(t, "host-a", readFixture(t, "host-a/ss-t0.txt"),
		map[string]fixtureSection{"neigh": okSection(neigh)}))
	e.now = t0.Add(time.Minute)
	e.sync()
	ctx := context.Background()
	for _, m := range []string{"01:00:5e:00:00:fb", "ff:ff:ff:ff:ff:ff", "02:00:00:00:00:01", "02:00:00:00:00:51"} {
		if _, ok, _ := e.store.LookupEndpoint(ctx, m, netip.Addr{}); ok {
			t.Fatalf("hostile neighbor %s stored", m)
		}
	}
	if _, ok, err := e.store.LookupEndpoint(ctx, "02:00:00:00:00:52", netip.Addr{}); !ok || err != nil {
		t.Fatalf("valid neighbor missing: %v %v", ok, err)
	}
}

func TestIngestNeverCreatesHosts(t *testing.T) {
	e := newEnv(t)
	// host-c has a result but no server record: it is not ingested.
	e.run("host-c", t0, netFactsDoc(t, "host-a", "ss-t0.txt"))
	e.now = t0.Add(time.Minute)
	res := e.sync()
	for _, h := range res.Hosts {
		if h.Host == "host-c" {
			t.Fatal("host without record ingested")
		}
	}
	var hosts int
	if err := e.db.QueryRow(`SELECT COUNT(*) FROM hosts`).Scan(&hosts); err != nil {
		t.Fatal(err)
	}
	if hosts != 0 {
		t.Fatalf("%d hosts created", hosts)
	}
}

func TestReconcileOnRecordChangeAndHourly(t *testing.T) {
	e := newEnv(t)
	e.twoRounds()
	if len(e.spy.reconciles) != 1 || e.spy.prunes != 1 {
		t.Fatalf("first hour: %d reconciles, %d prunes", len(e.spy.reconciles), e.spy.prunes)
	}
	ctx := context.Background()
	a, _, _ := e.store.LookupEndpoint(ctx, macA, netip.Addr{})
	if a.Owner != "host-a" {
		t.Fatalf("owner = %q", a.Owner)
	}
	// host-a's NIC is re-assigned in the inventory; host-a stays silent
	// (no new result). The changed records alone must drop its ownership.
	ids := defaultRecords()
	ids["host-a"] = trafficstore.Identity{MACs: []string{"52:54:00:00:99:99"}, Addrs: []netip.Addr{addrA}}
	e.records.ids = ids
	r := e.sync()
	if !r.Reconciled || r.Pruned || r.Reconcile.Released == 0 {
		t.Fatalf("record change: %+v", r)
	}
	if a, _, _ = e.store.LookupEndpoint(ctx, macA, netip.Addr{}); a.Owner != "" {
		t.Fatalf("silent former owner kept ownership: %q", a.Owner)
	}
	// Same records, same hour: no reconcile.
	n := len(e.spy.reconciles)
	if r := e.sync(); r.Reconciled {
		t.Fatal("reconciled without change")
	}
	// Next clock hour: reconcile and prune again.
	e.now = e.now.Add(time.Hour)
	if r := e.sync(); !r.Reconciled || !r.Pruned || len(e.spy.reconciles) != n+1 {
		t.Fatalf("hourly: %+v", r)
	}
	// Reconcile gets the exclusive identities, never shared values.
	last := e.spy.reconciles[len(e.spy.reconciles)-1]
	if !slices.Equal(last["host-a"].MACs, []string{"52:54:00:00:99:99"}) {
		t.Fatalf("reconciled identity = %+v", last["host-a"])
	}
}

func TestReconcileExplicit(t *testing.T) {
	e := newEnv(t)
	shared := defaultRecords()
	b := shared["host-b"]
	b.MACs = append(b.MACs, macA)
	shared["host-b"] = b
	e.records.ids = shared
	if _, err := e.in.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := e.spy.reconciles[0]
	if slices.Contains(got["host-a"].MACs, macA) || slices.Contains(got["host-b"].MACs, macA) {
		t.Fatalf("shared MAC passed to reconcile: %+v", got)
	}
}

func TestSyncRecordsErrorStopsRound(t *testing.T) {
	e := newEnv(t)
	e.records.err = errors.New("db down")
	if _, err := e.in.Sync(context.Background()); err == nil {
		t.Fatal("no error")
	}
	if len(e.spy.reconciles) != 0 {
		t.Fatal("reconciled without records")
	}
}

func TestNewRequiresDependencies(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Fatal("no error")
	}
}

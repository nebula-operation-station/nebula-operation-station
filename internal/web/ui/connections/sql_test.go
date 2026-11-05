// SPDX-License-Identifier: AGPL-3.0-or-later

package connections

import (
	"context"
	"database/sql"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/flowagg"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/trafficstore"
)

func newTestDB(t *testing.T) (*sql.DB, *trafficstore.Store) {
	t.Helper()
	db, err := serverdb.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db, trafficstore.NewWithNow(db, func() time.Time { return testNow })
}

func upsert(t *testing.T, s *trafficstore.Store, b trafficstore.Bucket, own netip.Addr) {
	t.Helper()
	if err := s.UpsertBucket(context.Background(), b, []netip.Addr{own}); err != nil {
		t.Fatalf("upsert %+v: %v", b, err)
	}
}

func lastHours(h time.Duration) flowagg.Window {
	return flowagg.Window{From: testNow.Add(-h), To: testNow}
}

// seed stores: web1 (hostAddr) → dns:53 reported by both ends one hour
// ago; nas → web1:443 reported by nas two hours and 30 hours ago; and an
// unrelated nas → dns flow.
func seed(t *testing.T, s *trafficstore.Store) {
	t.Helper()
	hour := testNow.Add(-time.Hour).Truncate(time.Hour)
	dnsKey := flowagg.FlowKey{A: hostAddr, B: dnsAddr, Proto: flowagg.TCP, ServerPort: 53, Server: flowagg.SideB, Tier: flowagg.TierSocket}
	upsert(t, s, trafficstore.Bucket{Hour: hour, Key: dnsKey, Reporter: "web1", BytesAB: 100, BytesBA: 900, Connections: 1}, hostAddr)
	upsert(t, s, trafficstore.Bucket{Hour: hour, Key: dnsKey, Reporter: "dnshost", ServerReported: true, BytesAB: 110, BytesBA: 950, Connections: 1}, dnsAddr)
	nasKey := flowagg.FlowKey{A: hostAddr, B: nasAddr, Proto: flowagg.TCP, ServerPort: 443, Server: flowagg.SideA, Tier: flowagg.TierSocket}
	upsert(t, s, trafficstore.Bucket{Hour: testNow.Add(-2 * time.Hour).Truncate(time.Hour), Key: nasKey, Reporter: "nas", BytesAB: 30, BytesBA: 20, Connections: 2, LowerBound: true}, nasAddr)
	upsert(t, s, trafficstore.Bucket{Hour: testNow.Add(-30 * time.Hour).Truncate(time.Hour), Key: nasKey, Reporter: "nas", BytesAB: 7000, BytesBA: 7000, Connections: 1}, nasAddr)
	otherKey := flowagg.FlowKey{A: nasAddr, B: dnsAddr, Proto: flowagg.UDP, ServerPort: 53, Server: flowagg.SideB, Tier: flowagg.TierSocket}
	upsert(t, s, trafficstore.Bucket{Hour: hour, Key: otherKey, Reporter: "nas", BytesAB: 1, BytesBA: 1}, nasAddr)
}

func TestSQLFlowsListsEveryFlowOfTheNodeMerged(t *testing.T) {
	db, s := newTestDB(t)
	seed(t, s)
	recs, err := SQLFlows(db, 0).Flows(context.Background(), []netip.Addr{hostAddr, hostAddr6}, lastHours(24*time.Hour), MaxRows+1)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 {
		t.Fatalf("got %d records: %+v", len(recs), recs)
	}
	dns := recs[0]
	if dns.Key.B != dnsAddr || dns.BytesAB != 110 || dns.BytesBA != 950 || !dns.Confirmed || !dns.ServerReported {
		t.Errorf("dns record %+v", dns)
	}
	if strings.Join(dns.Reporters, ",") != "dnshost,web1" {
		t.Errorf("dns reporters %v", dns.Reporters)
	}
	wantFirst := testNow.Add(-time.Hour).Truncate(time.Hour)
	if !dns.FirstSeen.Equal(wantFirst) || !dns.LastSeen.Equal(wantFirst.Add(time.Hour)) {
		t.Errorf("dns seen %v..%v", dns.FirstSeen, dns.LastSeen)
	}
	nas := recs[1]
	if nas.Key.B != nasAddr || nas.BytesAB != 30 || nas.BytesBA != 20 || nas.Confirmed || nas.ServerReported || !nas.LowerBound {
		t.Errorf("nas record (30 h old hour must be outside the window) %+v", nas)
	}
	if strings.Join(nas.Reporters, ",") != "nas" || nas.Process != "" {
		t.Errorf("nas reporters %v process %q", nas.Reporters, nas.Process)
	}
}

func TestSQLFlowsWindowAndLimit(t *testing.T) {
	db, s := newTestDB(t)
	seed(t, s)
	src := SQLFlows(db, 0)
	recs, err := src.Flows(context.Background(), []netip.Addr{hostAddr}, lastHours(7*24*time.Hour), MaxRows+1)
	if err != nil {
		t.Fatal(err)
	}
	// Over 7 days the nas flow (14,050 bytes) is the largest.
	if len(recs) != 2 || recs[0].Key.B != nasAddr || recs[0].Total() != 14050 {
		t.Fatalf("7d records %+v", recs)
	}
	recs, err = src.Flows(context.Background(), []netip.Addr{hostAddr}, lastHours(time.Hour), MaxRows+1)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 || recs[0].Key.B != dnsAddr {
		t.Fatalf("1h records %+v", recs)
	}
	recs, err = src.Flows(context.Background(), []netip.Addr{hostAddr}, lastHours(7*24*time.Hour), 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 || recs[0].Key.B != nasAddr {
		t.Fatalf("limit 1 records %+v", recs)
	}
}

// TestSQLFlowsLastSeenNotInFuture checks that a flow of the current,
// still open hour is last seen at the window end (now), not at the end
// of its hour bucket.
func TestSQLFlowsLastSeenNotInFuture(t *testing.T) {
	db, s := newTestDB(t)
	key := flowagg.FlowKey{A: hostAddr, B: dnsAddr, Proto: flowagg.TCP, ServerPort: 53, Server: flowagg.SideB, Tier: flowagg.TierSocket}
	upsert(t, s, trafficstore.Bucket{Hour: testNow.Truncate(time.Hour), Key: key, Reporter: "web1", BytesAB: 1, BytesBA: 1, Connections: 1}, hostAddr)
	recs, err := SQLFlows(db, 0).Flows(context.Background(), []netip.Addr{hostAddr}, lastHours(time.Hour), MaxRows+1)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 {
		t.Fatalf("got %d records", len(recs))
	}
	if !recs[0].LastSeen.Equal(testNow) || !recs[0].FirstSeen.Equal(testNow.Truncate(time.Hour)) {
		t.Errorf("seen %v..%v, want %v..%v", recs[0].FirstSeen, recs[0].LastSeen, testNow.Truncate(time.Hour), testNow)
	}
}

// TestSQLFlowsRetention checks that the source reports its retention and
// refuses wider windows.
func TestSQLFlowsRetention(t *testing.T) {
	db, _ := newTestDB(t)
	for _, c := range []struct{ in, want time.Duration }{
		{0, flowagg.Retention}, {-time.Hour, flowagg.Retention}, {flowagg.Retention + time.Hour, flowagg.Retention}, {7 * 24 * time.Hour, 7 * 24 * time.Hour},
	} {
		rr, ok := SQLFlows(db, c.in).(flowagg.RetentionReporter)
		if !ok || rr.Retention() != c.want {
			t.Errorf("SQLFlows(%s): retention reporter %v", c.in, rr)
		}
	}
	src := SQLFlows(db, 7*24*time.Hour)
	if _, err := src.Flows(context.Background(), []netip.Addr{hostAddr}, lastHours(7*24*time.Hour), 1); err != nil {
		t.Errorf("7d window: %v", err)
	}
	if _, err := src.Flows(context.Background(), []netip.Addr{hostAddr}, lastHours(8*24*time.Hour), 1); err == nil {
		t.Error("8d window over a 7d retention accepted")
	}
}

func TestSQLFlowsRejectsBadArguments(t *testing.T) {
	db, _ := newTestDB(t)
	src := SQLFlows(db, 0)
	many := make([]netip.Addr, MaxSubjectAddrs+1)
	for i := range many {
		many[i] = netip.AddrFrom4([4]byte{10, 1, byte(i >> 8), byte(i)})
	}
	cases := []struct {
		name  string
		nodes []netip.Addr
		w     flowagg.Window
		limit int
	}{
		{"no nodes", nil, lastHours(time.Hour), 1},
		{"too many nodes", many, lastHours(time.Hour), 1},
		{"invalid node", []netip.Addr{{}}, lastHours(time.Hour), 1},
		{"zero limit", []netip.Addr{hostAddr}, lastHours(time.Hour), 0},
		{"limit too high", []netip.Addr{hostAddr}, lastHours(time.Hour), MaxRows + 2},
		{"empty window", []netip.Addr{hostAddr}, flowagg.Window{From: testNow, To: testNow}, 1},
		{"window beyond retention", []netip.Addr{hostAddr}, lastHours(flowagg.Retention + time.Hour), 1},
	}
	for _, c := range cases {
		if _, err := src.Flows(context.Background(), c.nodes, c.w, c.limit); err == nil {
			t.Errorf("%s: want error", c.name)
		}
	}
}

func TestSQLFlowsRejectsCorruptStoredRows(t *testing.T) {
	db, _ := newTestDB(t)
	hour := testNow.Add(-time.Hour).Unix() / secondsPerHour
	for _, row := range []struct {
		a, b, tier string
		port, side int
	}{
		{"10.0.0.10", "not-an-ip", "socket", 53, 2},
		{"10.0.0.10", "10.0.0.53", "socket", 0, 2},
		{"10.0.0.10", "10.0.0.53", "socket", 53, 7},
		{"10.0.0.10", "10.0.0.53", "", 53, 2},
	} {
		if _, err := db.Exec(`DELETE FROM flow_buckets`); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`INSERT INTO flow_buckets (hour, a, b, proto, server_port, server_side, tier, server_reported, reporter, bytes_ab, bytes_ba)
			VALUES (?, ?, ?, 6, ?, ?, ?, 0, 'web1', 1, 1)`, hour, row.a, row.b, row.port, row.side, row.tier); err != nil {
			t.Fatal(err)
		}
		if _, err := SQLFlows(db, 0).Flows(context.Background(), []netip.Addr{hostAddr}, lastHours(24*time.Hour), 10); err == nil {
			t.Errorf("row %+v: want error", row)
		}
	}
}

func TestSplitReportersBounded(t *testing.T) {
	var parts []string
	for i := 0; i < maxRecordReporters+5; i++ {
		parts = append(parts, "r")
	}
	got, n := splitReporters(strings.Join(parts, reporterSep))
	if len(got) != maxRecordReporters || n != maxRecordReporters+5 {
		t.Fatalf("got %d reporters, count %d", len(got), n)
	}
	if got, n := splitReporters(""); got != nil || n != 0 {
		t.Fatalf("empty: %v %d", got, n)
	}
}

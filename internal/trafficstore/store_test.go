// SPDX-License-Identifier: AGPL-3.0-or-later

package trafficstore

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/flowagg"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
)

var (
	testNow    = time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	testWindow = flowagg.Window{
		From: time.Date(2026, 11, 1, 11, 0, 0, 0, time.UTC),
		To:   time.Date(2026, 11, 1, 13, 0, 0, 0, time.UTC),
	}
)

// newTestStore opens a migrated temp database with a fixed clock.
func newTestStore(t *testing.T) (*Store, *sql.DB, *time.Time) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.db")
	db, err := serverdb.Open(path)
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}
	now := testNow
	s := NewWithNow(db, func() time.Time { return now })
	t.Cleanup(func() { _ = db.Close() })
	return s, db, &now
}

func testEndpoint(addr, mac, reporter string) Endpoint {
	return Endpoint{
		MAC:       mac,
		Addresses: []netip.Addr{netip.MustParseAddr(addr)},
		VLAN:      10,
		Hostname:  "host-a",
		FirstSeen: testNow.Add(-time.Hour),
		LastSeen:  testNow,
		Tier:      flowagg.TierSocket,
		Reporter:  reporter,
	}
}

// testBucket is a client-end report by reporter-a, whose address is
// 10.0.0.1 (end A; the server is B).
func testBucket(peer string, port int, bytes uint64) Bucket {
	return Bucket{
		Hour: testNow,
		Key: flowagg.FlowKey{
			A:          netip.MustParseAddr("10.0.0.1"),
			B:          netip.MustParseAddr(peer),
			Proto:      flowagg.TCP,
			ServerPort: uint16(port),
			Server:     flowagg.SideB,
			Tier:       flowagg.TierSocket,
		},
		Reporter: "reporter-a",
		BytesAB:  bytes,
	}
}

// ownOf returns the reporter addresses that make b's claimed end owned.
func ownOf(b Bucket) []netip.Addr { return []netip.Addr{claimedEnd(&b)} }

// put stores b with the reporter owning its claimed end.
func put(t *testing.T, s *Store, b Bucket) {
	t.Helper()
	if err := s.UpsertBucket(context.Background(), b, ownOf(b)); err != nil {
		t.Fatalf("upsert bucket %s-%s:%d by %s: %v", b.Key.A, b.Key.B, b.Key.ServerPort, b.Reporter, err)
	}
}

// macIdentity is a reporter Identity that owns the given MACs.
func macIdentity(macs ...string) Identity { return Identity{MACs: macs} }

func mustLookup(t *testing.T, s *Store, mac, addr string) Endpoint {
	t.Helper()
	var a netip.Addr
	if addr != "" {
		a = netip.MustParseAddr(addr)
	}
	e, found, err := s.LookupEndpoint(context.Background(), mac, a)
	if err != nil || !found {
		t.Fatalf("lookup %q/%q: found=%v err=%v", mac, addr, found, err)
	}
	return e
}

func names(t *testing.T, db *sql.DB, typ string) map[string]bool {
	t.Helper()
	rows, err := db.Query(`SELECT name FROM sqlite_master WHERE type = ?`, typ)
	if err != nil {
		t.Fatalf("list %s: %v", typ, err)
	}
	defer rows.Close()
	out := make(map[string]bool)
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatalf("scan %s: %v", typ, err)
		}
		out[name] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("list %s: %v", typ, err)
	}
	return out
}

func countRows(t *testing.T, db *sql.DB, query string, args ...any) int {
	t.Helper()
	var n int
	if err := db.QueryRow(query, args...).Scan(&n); err != nil {
		t.Fatalf("count %q: %v", query, err)
	}
	return n
}

// checkCounters asserts that the trigger-maintained counts equal the
// real row counts, in total and per reporter.
func checkCounters(t *testing.T, s *Store, db *sql.DB) {
	t.Helper()
	ctx := context.Background()
	if got, want := mustCount(t, s.CountBuckets), countRows(t, db, `SELECT COUNT(*) FROM flow_buckets`); got != want {
		t.Errorf("bucket counter = %d, rows = %d", got, want)
	}
	if got, want := mustCount(t, s.CountEndpoints), countRows(t, db, `SELECT COUNT(*) FROM net_endpoints`); got != want {
		t.Errorf("endpoint counter = %d, rows = %d", got, want)
	}
	for _, q := range []struct{ name, table string }{
		{countBuckets, "flow_buckets"},
		{countEndpointSeen, "net_endpoint_reporters"},
	} {
		rows, err := db.Query(`SELECT reporter, COUNT(*) FROM ` + q.table + ` GROUP BY reporter`)
		if err != nil {
			t.Fatalf("group %s: %v", q.table, err)
		}
		want := make(map[string]int)
		for rows.Next() {
			var r string
			var n int
			if err := rows.Scan(&r, &n); err != nil {
				t.Fatalf("scan: %v", err)
			}
			want[r] = n
		}
		rows.Close()
		for r, n := range want {
			got, err := readCount(ctx, db, q.name, r)
			if err != nil {
				t.Fatalf("read count: %v", err)
			}
			if got != n {
				t.Errorf("%s counter of %s = %d, rows = %d", q.name, r, got, n)
			}
		}
		// No stale per-reporter counters stay behind.
		stale := countRows(t, db, `SELECT COUNT(*) FROM traffic_counts WHERE name = ? AND reporter != ''`, q.name)
		if stale != len(want) {
			t.Errorf("%s: %d per-reporter counters, %d reporters", q.name, stale, len(want))
		}
	}
}

func mustCount(t *testing.T, f func(context.Context) (int, error)) int {
	t.Helper()
	n, err := f(context.Background())
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	return n
}

func TestSchemaAndIndexes(t *testing.T) {
	_, db, _ := newTestStore(t)

	tables := names(t, db, "table")
	for _, want := range []string{"net_endpoints", "net_endpoint_reporters", "net_endpoint_addresses",
		"flow_buckets", "traffic_counts", "traffic_store_lock"} {
		if !tables[want] {
			t.Errorf("missing table %s", want)
		}
	}
	indexes := names(t, db, "index")
	for _, want := range []string{
		"idx_flow_buckets_a_hour",
		"idx_flow_buckets_b_hour",
		"idx_net_endpoints_mac",
		"idx_net_endpoints_last_seen",
		"idx_net_endpoints_owner",
		"idx_net_endpoint_reporters_last_seen",
		"idx_net_endpoint_addresses_address",
	} {
		if !indexes[want] {
			t.Errorf("missing index %s", want)
		}
	}
	// The primary key's leading hour column serves Prune; a separate hour
	// index would only add write cost.
	if indexes["idx_flow_buckets_hour"] {
		t.Error("redundant idx_flow_buckets_hour present")
	}
}

// queryPlan returns the EXPLAIN QUERY PLAN details of query.
func queryPlan(t *testing.T, db *sql.DB, query string, args ...any) string {
	t.Helper()
	rows, err := db.Query(`EXPLAIN QUERY PLAN `+query, args...)
	if err != nil {
		t.Fatalf("explain %q: %v", query, err)
	}
	defer rows.Close()
	var lines []string
	for rows.Next() {
		var id, parent, notused int
		var detail string
		if err := rows.Scan(&id, &parent, &notused, &detail); err != nil {
			t.Fatalf("scan plan: %v", err)
		}
		lines = append(lines, detail)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("explain %q: %v", query, err)
	}
	return strings.Join(lines, "\n")
}

func TestQueryPlansUseIndexes(t *testing.T) {
	_, db, _ := newTestStore(t)
	cases := []struct {
		name    string
		query   string
		args    []any
		want    []string
		notScan string
	}{
		{"prune buckets", pruneBucketsSQL, []any{1}, []string{"SEARCH flow_buckets", "(hour<?)"}, "SCAN flow_buckets"},
		{"prune seen-by", pruneEndpointSeenSQL, []any{1}, []string{"idx_net_endpoint_reporters_last_seen"}, "SCAN net_endpoint_reporters"},
		{"prune endpoints", pruneEndpointsSQL, []any{1}, []string{"idx_net_endpoints_last_seen"}, "SCAN net_endpoints"},
		{"top flows", topFlowsSQL, []any{"10.0.0.1", 1, 2, 5, maxTopRows},
			[]string{"idx_flow_buckets_a_hour (a=? AND hour>? AND hour<?)", "idx_flow_buckets_b_hour (b=? AND hour>? AND hour<?)"},
			"SCAN flow_buckets"},
		{"clear expired owners", clearOwnerSQL, nil, []string{"SCAN net_endpoints USING INDEX idx_net_endpoints_owner", "SEARCH r"}, "SCAN net_endpoints\n"},
		{"lookup owned address", lookupOwnedSQL, []any{"10.0.0.1"}, []string{"idx_net_endpoint_addresses_address"}, "SCAN net_endpoint_addresses"},
		{"lookup unowned address", lookupUnownedSQL, []any{"10.0.0.1"}, []string{"idx_net_endpoint_addresses_address"}, "SCAN net_endpoint_addresses"},
		{"cap counter", `SELECT n FROM traffic_counts WHERE name = ? AND reporter = ?`, []any{"buckets", ""},
			[]string{"SEARCH traffic_counts"}, "SCAN traffic_counts"},
		// Write path of UpsertEndpoint.
		{"find by mac", findByMACSQL, []any{"00:11:22:33:44:55"}, []string{"idx_net_endpoints_mac"}, "SCAN net_endpoints"},
		{"lookup by mac", lookupByMACSQL, []any{"00:11:22:33:44:55"}, []string{"idx_net_endpoints_mac"}, "SCAN net_endpoints"},
		{"learn mac by address", learnMACSQL("?,?"), []any{"10.0.0.1", "10.0.0.2", "r", true},
			[]string{"idx_net_endpoint_addresses_address", "SEARCH e USING INDEX sqlite_autoindex_net_endpoints_1", "SEARCH r"},
			"SCAN a"},
		{"match by address", matchAddressSQL("?,?", "?"), []any{"10.0.0.1", "10.0.0.2", true, "00:11:22:33:44:55", "r", "r"},
			[]string{"idx_net_endpoint_addresses_address", "SEARCH e USING INDEX sqlite_autoindex_net_endpoints_1"},
			"SCAN a"},
		{"match by address without macs", matchAddressSQL("?", ""), []any{"10.0.0.1", false, "r", "r"},
			[]string{"idx_net_endpoint_addresses_address"}, "SCAN a"},
		{"known addresses", knownAddressesSQL("?,?"), []any{"ep-x", "o", "o", "10.0.0.1", "10.0.0.2"},
			[]string{"SEARCH net_endpoint_addresses USING"}, "SCAN net_endpoint_addresses"},
		{"count addresses", countAddressesSQL("?,?"), []any{"10.0.0.1", "10.0.0.2", "ep-x", "r"},
			[]string{"SEARCH net_endpoint_addresses USING", "(endpoint_id=? AND reporter=?)"}, "SCAN net_endpoint_addresses"},
		{"count reporter addresses", countReporterAddressesSQL, []any{"ep-x", "r"},
			[]string{"SEARCH net_endpoint_addresses USING", "(endpoint_id=? AND reporter=?)"}, "SCAN net_endpoint_addresses"},
		{"drop unattested", dropUnattestedSQL("?"), []any{"ep-x", "r", "10.0.0.1"},
			[]string{"SEARCH net_endpoint_addresses USING", "(endpoint_id=? AND reporter=?)"}, "SCAN net_endpoint_addresses"},
		{"drop unattested without addresses", dropUnattestedSQL(""), []any{"ep-x", "r"},
			[]string{"SEARCH net_endpoint_addresses USING", "(endpoint_id=? AND reporter=?)"}, "SCAN net_endpoint_addresses"},
		{"count non-owner reporters", countNonOwnersSQL, []any{"ep-x", "o"},
			[]string{"SEARCH net_endpoint_reporters USING", "(endpoint_id=?)"}, "SCAN net_endpoint_reporters"},
		{"release stale attestations", releaseAttestedSQL("?,?"), []any{"10.0.0.1", "10.0.0.2", "ep-x", "o"},
			[]string{"SEARCH net_endpoint_addresses USING INDEX idx_net_endpoint_addresses_address", "SEARCH e USING INDEX sqlite_autoindex_net_endpoints_1"},
			"SCAN net_endpoint_addresses"},
		{"clear unattested owner", clearUnattestedOwnerSQL, []any{"ep-x"},
			[]string{"SEARCH net_endpoints USING INDEX sqlite_autoindex_net_endpoints_1", "SEARCH a USING"}, "SCAN"},
		// ReconcileIdentities.
		{"list owners", listOwnersSQL, nil, []string{"idx_net_endpoints_owner"}, "SCAN net_endpoints\n"},
		{"reconcile addresses", reconcileAddrsSQL("?,?"), []any{"o", "o", "10.0.0.1", "10.0.0.2"},
			[]string{"SEARCH net_endpoint_addresses USING", "(endpoint_id=? AND reporter=?)", "idx_net_endpoints_owner (owner=?)"},
			"SCAN"},
		{"reconcile addresses without addresses", reconcileAddrsSQL(""), []any{"o", "o"},
			[]string{"SEARCH net_endpoint_addresses USING", "idx_net_endpoints_owner (owner=?)"}, "SCAN"},
		{"release mac owner", releaseMACOwnerSQL("?,?"), []any{"o", "00:11:22:33:44:55", "00:11:22:33:44:56"},
			[]string{"idx_net_endpoints_owner (owner=?)"}, "SCAN"},
		{"release mac owner without macs", releaseMACOwnerSQL(""), []any{"o"},
			[]string{"idx_net_endpoints_owner (owner=?)"}, "SCAN"},
		{"release mac-less owner", releaseMACLessOwnerSQL, []any{"o"},
			[]string{"idx_net_endpoints_owner (owner=?)", "SEARCH a USING"}, "SCAN"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			plan := queryPlan(t, db, tc.query, tc.args...)
			for _, w := range tc.want {
				if !strings.Contains(plan, w) {
					t.Errorf("plan lacks %q:\n%s", w, plan)
				}
			}
			if strings.Contains(plan, tc.notScan) {
				t.Errorf("plan scans the table:\n%s", plan)
			}
		})
	}
}

func TestUpsertEndpoint(t *testing.T) {
	s, db, now := newTestStore(t)
	ctx := context.Background()

	e := testEndpoint("10.0.0.1", "00:11:22:33:44:55", "reporter-a")
	ownA := hostIdentity("00:11:22:33:44:55", "10.0.0.1", "10.0.0.2")
	if err := s.UpsertEndpoint(ctx, e, ownA); err != nil {
		t.Fatalf("upsert endpoint: %v", err)
	}
	got := mustLookup(t, s, "00:11:22:33:44:55", "")
	if !strings.HasPrefix(got.ID, endpointIDPrefix) {
		t.Errorf("id = %q, want prefix %q", got.ID, endpointIDPrefix)
	}
	id := got.ID
	if got.OUI != "001122" {
		t.Errorf("oui = %q, want 001122", got.OUI)
	}
	if got.FirstSeen != testNow.Add(-time.Hour) || got.LastSeen != testNow {
		t.Errorf("seen = %s..%s, want %s..%s", got.FirstSeen, got.LastSeen, testNow.Add(-time.Hour), testNow)
	}
	if len(got.Addresses) != 1 || got.Addresses[0] != netip.MustParseAddr("10.0.0.1") {
		t.Errorf("addresses = %v", got.Addresses)
	}
	if got.Owner != "reporter-a" || got.HostID != "reporter-a" || len(got.SeenBy) != 1 || got.SeenBy[0] != "reporter-a" {
		t.Errorf("owner/host/seen-by = %q/%q/%v", got.Owner, got.HostID, got.SeenBy)
	}

	// Re-upsert an hour later: last_seen advances, first_seen keeps,
	// empty hostname is not clobbered, a new address is added.
	*now = now.Add(time.Hour)
	e2 := testEndpoint("10.0.0.2", "00:11:22:33:44:55", "reporter-a")
	e2.Addresses = []netip.Addr{netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2")}
	e2.Hostname = ""
	e2.FirstSeen = time.Time{}
	e2.LastSeen = *now
	if err := s.UpsertEndpoint(ctx, e2, ownA); err != nil {
		t.Fatalf("re-upsert endpoint: %v", err)
	}
	got, err := s.Endpoint(ctx, id)
	if err != nil {
		t.Fatalf("read endpoint: %v", err)
	}
	if got.FirstSeen != testNow.Add(-time.Hour) {
		t.Errorf("first_seen = %s, want %s", got.FirstSeen, testNow.Add(-time.Hour))
	}
	if got.LastSeen != testNow.Add(time.Hour) {
		t.Errorf("last_seen = %s, want %s", got.LastSeen, testNow.Add(time.Hour))
	}
	if got.Hostname != "host-a" {
		t.Errorf("hostname = %q, want host-a", got.Hostname)
	}
	if len(got.Addresses) != 2 {
		t.Errorf("addresses = %v, want 2", got.Addresses)
	}

	// An out-of-order, earlier observation lowers first_seen.
	e3 := testEndpoint("10.0.0.1", "00:11:22:33:44:55", "reporter-a")
	e3.FirstSeen = testNow.Add(-5 * time.Hour)
	e3.LastSeen = testNow.Add(-4 * time.Hour)
	if err := s.UpsertEndpoint(ctx, e3, ownA); err != nil {
		t.Fatalf("upsert earlier observation: %v", err)
	}
	got, err = s.Endpoint(ctx, id)
	if err != nil {
		t.Fatalf("read endpoint: %v", err)
	}
	if got.FirstSeen != testNow.Add(-5*time.Hour) || got.LastSeen != testNow.Add(time.Hour) {
		t.Errorf("seen = %s..%s, want first lowered, last kept", got.FirstSeen, got.LastSeen)
	}
	if n := mustCount(t, s.CountEndpoints); n != 1 {
		t.Errorf("count = %d, want 1", n)
	}
	if _, err := s.Endpoint(ctx, "ep-missing"); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing endpoint: err = %v, want ErrNotFound", err)
	}
	checkCounters(t, s, db)
}

func TestEndpointAddressNormalization(t *testing.T) {
	s, _, _ := newTestStore(t)
	ctx := context.Background()

	e := testEndpoint("10.0.0.1", "", "reporter-a")
	e.Addresses = []netip.Addr{
		netip.MustParseAddr("::ffff:10.0.0.7"),
		netip.MustParseAddr("fe80::1%eth0"),
		netip.MustParseAddr("10.0.0.7"),
	}
	if err := s.UpsertEndpoint(ctx, e, Identity{}); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	got := mustLookup(t, s, "", "10.0.0.7")
	want := []netip.Addr{netip.MustParseAddr("10.0.0.7"), netip.MustParseAddr("fe80::1")}
	if len(got.Addresses) != len(want) || got.Addresses[0] != want[0] || got.Addresses[1] != want[1] {
		t.Errorf("addresses = %v, want %v (unmapped, zone dropped, deduplicated)", got.Addresses, want)
	}
	// Mapped and zoned lookups find the stored form.
	if g := mustLookup(t, s, "", "::ffff:10.0.0.7"); g.ID != got.ID {
		t.Errorf("mapped lookup id = %s, want %s", g.ID, got.ID)
	}
	if g := mustLookup(t, s, "", "fe80::1%eth1"); g.ID != got.ID {
		t.Errorf("zoned lookup id = %s, want %s", g.ID, got.ID)
	}
	// A zone on a global address makes no sense and is refused.
	bad := testEndpoint("10.0.0.1", "", "reporter-a")
	bad.Addresses = []netip.Addr{netip.MustParseAddr("2001:db8::1%eth0")}
	if err := s.UpsertEndpoint(ctx, bad, Identity{}); !errors.Is(err, ErrInvalidEndpoint) {
		t.Errorf("zoned global address: err = %v, want ErrInvalidEndpoint", err)
	}
	if _, _, err := s.LookupEndpoint(ctx, "", netip.MustParseAddr("2001:db8::1%eth0")); !errors.Is(err, ErrInvalidEndpoint) {
		t.Errorf("zoned global lookup: err = %v, want ErrInvalidEndpoint", err)
	}
}

func TestEndpointMergeByMACAndAddress(t *testing.T) {
	s, _, _ := newTestStore(t)
	ctx := context.Background()

	// First seen by address only.
	e1 := testEndpoint("10.0.0.9", "", "reporter-a")
	e1.LastSeen = testNow.Add(-time.Hour)
	e1.FirstSeen = testNow.Add(-time.Hour)
	if err := s.UpsertEndpoint(ctx, e1, Identity{}); err != nil {
		t.Fatalf("upsert by address: %v", err)
	}
	first := mustLookup(t, s, "", "10.0.0.9")
	if first.MAC != "" {
		t.Fatalf("mac = %q, want empty", first.MAC)
	}

	// The owner's later observation carries the MAC: it merges into the
	// same row, whose ID does not change.
	e2 := testEndpoint("10.0.0.9", "00:11:22:33:44:66", "reporter-a")
	if err := s.UpsertEndpoint(ctx, e2, Identity{}); err != nil {
		t.Fatalf("upsert with mac: %v", err)
	}
	if n := mustCount(t, s.CountEndpoints); n != 1 {
		t.Fatalf("count = %d, want 1 (merge, not duplicate)", n)
	}
	got := mustLookup(t, s, "00:11:22:33:44:66", "")
	if got.ID != first.ID {
		t.Errorf("id = %q, want unchanged %q", got.ID, first.ID)
	}
	if got.MAC != "00:11:22:33:44:66" || got.OUI != "001122" {
		t.Errorf("mac/oui = %q/%q, want 00:11:22:33:44:66/001122", got.MAC, got.OUI)
	}
	if got.FirstSeen != testNow.Add(-time.Hour) || got.LastSeen != testNow {
		t.Errorf("seen = %s..%s", got.FirstSeen, got.LastSeen)
	}

	// Another reporter's MAC observation for an address-only endpoint it
	// does not own does not merge into it.
	e3 := testEndpoint("10.0.0.20", "", "reporter-a")
	if err := s.UpsertEndpoint(ctx, e3, Identity{}); err != nil {
		t.Fatalf("upsert by address: %v", err)
	}
	addrOnlyID := mustLookup(t, s, "", "10.0.0.20").ID
	e4 := testEndpoint("10.0.0.20", "00:11:22:33:44:77", "reporter-b")
	if err := s.UpsertEndpoint(ctx, e4, Identity{}); err != nil {
		t.Fatalf("upsert foreign mac: %v", err)
	}
	if n := mustCount(t, s.CountEndpoints); n != 3 {
		t.Errorf("count = %d, want 3 (no merge into another owner's endpoint)", n)
	}
	addrOnly, err := s.Endpoint(ctx, addrOnlyID)
	if err != nil {
		t.Fatalf("read address-only endpoint: %v", err)
	}
	if addrOnly.MAC != "" || addrOnly.Owner != "" || len(addrOnly.SeenBy) != 1 || addrOnly.SeenBy[0] != "reporter-a" {
		t.Errorf("address-only endpoint = %+v, want it untouched", addrOnly)
	}
	if mustLookup(t, s, "00:11:22:33:44:77", "").ID == addrOnlyID {
		t.Error("foreign MAC merged into the address-only endpoint")
	}
}

func TestEndpointDHCPReuseCreatesNewEndpoint(t *testing.T) {
	s, db, now := newTestStore(t)
	ctx := context.Background()

	old := testEndpoint("10.0.0.9", "00:11:22:33:44:01", "reporter-a")
	old.LastSeen = testNow.Add(-2 * time.Hour)
	old.FirstSeen = old.LastSeen
	old.Hostname = "old-device"
	if err := s.UpsertEndpoint(ctx, old, Identity{}); err != nil {
		t.Fatalf("upsert old device: %v", err)
	}
	// A new device with another vendor's MAC gets the same lease.
	*now = now.Add(time.Hour)
	fresh := testEndpoint("10.0.0.9", "aa:bb:cc:00:00:02", "reporter-a")
	fresh.LastSeen = *now
	fresh.Hostname = "new-device"
	if err := s.UpsertEndpoint(ctx, fresh, Identity{}); err != nil {
		t.Fatalf("upsert new device: %v", err)
	}
	if n := mustCount(t, s.CountEndpoints); n != 2 {
		t.Fatalf("count = %d, want 2 (new MAC, new endpoint)", n)
	}
	o := mustLookup(t, s, "00:11:22:33:44:01", "")
	if o.OUI != "001122" || o.Hostname != "old-device" {
		t.Errorf("old device = %+v, want its own OUI and hostname kept", o)
	}
	n := mustLookup(t, s, "aa:bb:cc:00:00:02", "")
	if n.ID == o.ID || n.OUI != "aabbcc" || n.Hostname != "new-device" {
		t.Errorf("new device = %+v", n)
	}
	// Neither endpoint has an owner: the address is ambiguous rather than
	// resolved by a value a reporter controls.
	if _, found, err := s.LookupEndpoint(ctx, "", netip.MustParseAddr("10.0.0.9")); found || !errors.Is(err, ErrAmbiguous) {
		t.Errorf("address lookup: found=%v err=%v, want ErrAmbiguous", found, err)
	}
	// Once the new device reports its own MAC (server records), its
	// address resolves to it.
	self := fresh
	self.Reporter = "new-device"
	if err := s.UpsertEndpoint(ctx, self, hostIdentity("aa:bb:cc:00:00:02", "10.0.0.9")); err != nil {
		t.Fatalf("upsert owner: %v", err)
	}
	for range 3 {
		if g := mustLookup(t, s, "", "10.0.0.9"); g.ID != n.ID || g.Owner != "new-device" {
			t.Fatalf("address lookup = %s/%q, want the new device %s", g.ID, g.Owner, n.ID)
		}
	}
	// An address-only observation joins the owned endpoint whose owner
	// attached the address.
	addrOnly := testEndpoint("10.0.0.9", "", "reporter-b")
	addrOnly.LastSeen = *now
	if err := s.UpsertEndpoint(ctx, addrOnly, Identity{}); err != nil {
		t.Fatalf("upsert address-only: %v", err)
	}
	if g := mustLookup(t, s, "aa:bb:cc:00:00:02", ""); len(g.SeenBy) != 3 {
		t.Errorf("new device seen by %v, want new-device, reporter-a and reporter-b", g.SeenBy)
	}
	checkCounters(t, s, db)
}

func TestEndpointHostileFirstClaimer(t *testing.T) {
	s, db, _ := newTestStore(t)
	ctx := context.Background()
	const mac = "00:11:22:33:44:55"

	// A hostile host claims the victim's MAC first, with its own values,
	// a full set of addresses and identity links.
	evil := testEndpoint("10.0.0.1", mac, "intruder")
	evil.Hostname = "evil"
	evil.VLAN = 99
	evil.Tier = flowagg.TierSensor
	evil.HostID = "host-x"
	if err := s.UpsertEndpoint(ctx, evil, Identity{}); !errors.Is(err, ErrInvalidEndpoint) {
		t.Errorf("reporter-supplied host link: err = %v, want ErrInvalidEndpoint", err)
	}
	evil.HostID = ""
	evil.IPAMAssetID = "asset-x"
	if err := s.UpsertEndpoint(ctx, evil, Identity{}); !errors.Is(err, ErrInvalidEndpoint) {
		t.Errorf("reporter-supplied ipam link: err = %v, want ErrInvalidEndpoint", err)
	}
	evil.IPAMAssetID = ""
	evil.Addresses = []netip.Addr{netip.MustParseAddr("10.0.0.1")}
	for i := 1; i < MaxAddressesPerEndpoint; i++ {
		evil.Addresses = append(evil.Addresses, netip.MustParseAddr("10.9.0."+strconv.Itoa(i)))
	}
	if err := s.UpsertEndpoint(ctx, evil, Identity{}); err != nil {
		t.Fatalf("upsert intruder: %v", err)
	}
	got := mustLookup(t, s, mac, "")
	if got.Owner != "" || got.HostID != "" || got.IPAMAssetID != "" {
		t.Errorf("first claimer became owner or linked: %+v", got)
	}

	// An honest observer without authority disagrees: the conflicting
	// fields are flagged and not shown.
	obs := testEndpoint("10.0.0.1", mac, "observer")
	obs.Hostname = "victim"
	if err := s.UpsertEndpoint(ctx, obs, Identity{}); err != nil {
		t.Fatalf("upsert observer: %v", err)
	}
	got = mustLookup(t, s, mac, "")
	if got.Owner != "" || got.Hostname != "" || got.VLAN != 0 ||
		!slices.Equal(got.Conflicts, []string{ConflictHostname, ConflictVLAN}) {
		t.Errorf("unowned endpoint = hostname %q vlan %d conflicts %v, want both flagged", got.Hostname, got.VLAN, got.Conflicts)
	}

	// The managed host that has the MAC on its own interface (server
	// records) reports it: it owns the endpoint, its values are shown,
	// and the intruder's claims stay attributed to the intruder.
	owner := testEndpoint("10.0.0.1", mac, "owner")
	owner.Hostname = ""
	owner.VLAN = 0
	ownerID := Identity{MACs: []string{"aa:aa:aa:aa:aa:aa", mac}, Addrs: addrList("10.0.0.1", "10.0.0.2")}
	if err := s.UpsertEndpoint(ctx, owner, ownerID); err != nil {
		t.Fatalf("upsert owner: %v", err)
	}
	got = mustLookup(t, s, mac, "")
	if got.Owner != "owner" || got.HostID != "owner" || got.Hostname != "" || got.VLAN != 0 ||
		got.Tier != flowagg.TierSocket || len(got.Conflicts) != 0 {
		t.Errorf("endpoint = %+v, want the owner's values", got)
	}
	if !slices.Equal(got.Addresses, []netip.Addr{netip.MustParseAddr("10.0.0.1")}) {
		t.Errorf("addresses = %v, want only the owner's", got.Addresses)
	}
	if !slices.Equal(got.SeenBy, []string{"intruder", "observer", "owner"}) || len(got.Observations) != 3 {
		t.Fatalf("seen-by = %v", got.SeenBy)
	}
	if o := got.Observations[0]; o.Reporter != "intruder" || o.Hostname != "evil" || o.VLAN != 99 ||
		len(o.Addresses) != MaxAddressesPerEndpoint {
		t.Errorf("intruder observation = %+v", o)
	}
	// The intruder's addresses no longer resolve to the owned endpoint.
	if _, found, err := s.LookupEndpoint(ctx, "", netip.MustParseAddr("10.9.0.5")); found || err != nil {
		t.Errorf("lookup of an intruder address: found=%v err=%v, want not found", found, err)
	}
	if g := mustLookup(t, s, "", "10.0.0.1"); g.ID != got.ID {
		t.Errorf("lookup of the owner's address = %s, want %s", g.ID, got.ID)
	}

	// The owner's updates keep working: its address slots are its own,
	// and only addresses in its records are attached.
	owner.Addresses = []netip.Addr{netip.MustParseAddr("10.0.0.2"), netip.MustParseAddr("10.9.0.7")}
	owner.Hostname = "real"
	if err := s.UpsertEndpoint(ctx, owner, ownerID); err != nil {
		t.Fatalf("owner update after intruder: %v", err)
	}
	got = mustLookup(t, s, mac, "")
	if got.Hostname != "real" || !slices.Equal(got.Addresses, addrList("10.0.0.1", "10.0.0.2")) {
		t.Errorf("hostname/addresses = %q/%v, want real and the two attested addresses", got.Hostname, got.Addresses)
	}
	// The intruder's further addresses are refused at its own limit.
	evil.Addresses = []netip.Addr{netip.MustParseAddr("10.9.1.1")}
	if err := s.UpsertEndpoint(ctx, evil, Identity{}); !errors.Is(err, ErrLimit) {
		t.Errorf("intruder beyond its address cap: err = %v, want ErrLimit", err)
	}
	// A reporter without the MAC in its records never takes over.
	if err := s.UpsertEndpoint(ctx, testEndpoint("10.0.0.3", mac, "second-claimer"), hostIdentity("", "10.0.0.3")); err != nil {
		t.Fatalf("upsert second claimer: %v", err)
	}
	if g := mustLookup(t, s, mac, ""); g.Owner != "owner" {
		t.Errorf("owner = %q after a claim without records, want owner", g.Owner)
	}
	// Ownership follows the server's current records: the host whose
	// records now hold the MAC (the caller leaves out shared MACs) is the
	// owner.
	if err := s.UpsertEndpoint(ctx, testEndpoint("10.0.0.3", mac, "second-claimer"), hostIdentity(mac, "10.0.0.3")); err != nil {
		t.Fatalf("upsert second claimer with records: %v", err)
	}
	if g := mustLookup(t, s, mac, ""); g.Owner != "second-claimer" || !slices.Equal(g.Addresses, addrList("10.0.0.3")) {
		t.Errorf("owner/addresses = %q/%v, want second-claimer with 10.0.0.3", g.Owner, g.Addresses)
	}

	// Links come from server-side matching.
	if err := s.SetEndpointLinks(ctx, got.ID, "asset-1", "host-1"); err != nil {
		t.Fatalf("set links: %v", err)
	}
	if g := mustLookup(t, s, mac, ""); g.IPAMAssetID != "asset-1" || g.HostID != "host-1" {
		t.Errorf("links = %q/%q, want asset-1/host-1", g.IPAMAssetID, g.HostID)
	}
	if err := s.SetEndpointLinks(ctx, "ep-missing", "", ""); !errors.Is(err, ErrNotFound) {
		t.Errorf("links of a missing endpoint: err = %v, want ErrNotFound", err)
	}
	if err := s.SetEndpointLinks(ctx, got.ID, strings.Repeat("a", maxIDLen+1), ""); !errors.Is(err, ErrInvalidEndpoint) {
		t.Errorf("overlong link: err = %v, want ErrInvalidEndpoint", err)
	}
	checkCounters(t, s, db)
}

func TestEndpointAddressAttribution(t *testing.T) {
	s, db, _ := newTestStore(t)
	ctx := context.Background()
	addr := netip.MustParseAddr

	// An owned MAC endpoint.
	owned := testEndpoint("10.0.0.1", "00:11:22:33:44:55", "owner")
	if err := s.UpsertEndpoint(ctx, owned, hostIdentity(owned.MAC, "10.0.0.1")); err != nil {
		t.Fatalf("upsert owned: %v", err)
	}
	ownedID := mustLookup(t, s, owned.MAC, "").ID
	// A MAC-less observation by another reporter sharing one address
	// joins it but attaches no new address.
	intr := testEndpoint("10.0.0.1", "", "intruder")
	intr.Addresses = []netip.Addr{addr("10.0.0.1"), addr("10.0.0.50"), addr("10.0.0.51")}
	if err := s.UpsertEndpoint(ctx, intr, Identity{}); err != nil {
		t.Fatalf("upsert intruder: %v", err)
	}
	got, err := s.Endpoint(ctx, ownedID)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(got.Observations) != 2 || got.Observations[0].Reporter != "intruder" ||
		!slices.Equal(got.Observations[0].Addresses, []netip.Addr{addr("10.0.0.1")}) {
		t.Errorf("observations = %+v, want the intruder with only the known address", got.Observations)
	}
	for _, a := range []string{"10.0.0.50", "10.0.0.51"} {
		if _, found, err := s.LookupEndpoint(ctx, "", addr(a)); found || err != nil {
			t.Errorf("lookup %s: found=%v err=%v, want not found", a, found, err)
		}
	}
	// A MAC observation by a non-owner attaches its addresses under its
	// own name, but they do not resolve to the owned endpoint.
	intrMAC := testEndpoint("10.0.0.77", owned.MAC, "intruder")
	if err := s.UpsertEndpoint(ctx, intrMAC, Identity{}); err != nil {
		t.Fatalf("upsert intruder mac: %v", err)
	}
	if _, found, err := s.LookupEndpoint(ctx, "", addr("10.0.0.77")); found || err != nil {
		t.Errorf("lookup of a non-owner address: found=%v err=%v, want not found", found, err)
	}
	if g := mustLookup(t, s, "", "10.0.0.1"); g.ID != ownedID {
		t.Errorf("lookup of the owner's address = %s, want %s", g.ID, ownedID)
	}

	// An unowned MAC endpoint: a MAC-less observation attaches only the
	// addresses it already has.
	dev := testEndpoint("10.0.1.1", "00:11:22:33:44:66", "observer")
	if err := s.UpsertEndpoint(ctx, dev, Identity{}); err != nil {
		t.Fatalf("upsert device: %v", err)
	}
	intr2 := testEndpoint("10.0.1.1", "", "intruder")
	intr2.Addresses = []netip.Addr{addr("10.0.1.1"), addr("10.0.1.2")}
	if err := s.UpsertEndpoint(ctx, intr2, Identity{}); err != nil {
		t.Fatalf("upsert intruder 2: %v", err)
	}
	if _, found, err := s.LookupEndpoint(ctx, "", addr("10.0.1.2")); found || err != nil {
		t.Errorf("lookup 10.0.1.2: found=%v err=%v, want not found", found, err)
	}
	if g := mustLookup(t, s, "", "10.0.1.1"); g.MAC != dev.MAC {
		t.Errorf("lookup 10.0.1.1 = %+v, want the device", g)
	}

	// A MAC-less endpoint without owner collects every reporter's
	// addresses, attributed.
	a := testEndpoint("10.0.2.1", "", "reporter-a")
	b := testEndpoint("10.0.2.1", "", "reporter-b")
	b.Addresses = []netip.Addr{addr("10.0.2.1"), addr("10.0.2.2")}
	for _, e := range []Endpoint{a, b} {
		if err := s.UpsertEndpoint(ctx, e, Identity{}); err != nil {
			t.Fatalf("upsert %s: %v", e.Reporter, err)
		}
	}
	g := mustLookup(t, s, "", "10.0.2.2")
	if len(g.Observations) != 2 ||
		!slices.Equal(g.Observations[0].Addresses, []netip.Addr{addr("10.0.2.1")}) ||
		!slices.Equal(g.Observations[1].Addresses, []netip.Addr{addr("10.0.2.1"), addr("10.0.2.2")}) ||
		!slices.Equal(g.Addresses, []netip.Addr{addr("10.0.2.1"), addr("10.0.2.2")}) {
		t.Errorf("address-only endpoint = %+v", g)
	}

	// An address the records move to another host resolves to its
	// current holder: the former owner's attestation is released.
	for i, rep := range []string{"host-1", "host-2"} {
		e := testEndpoint("10.0.3.1", fmt.Sprintf("00:11:22:33:55:0%d", i), rep)
		if err := s.UpsertEndpoint(ctx, e, hostIdentity(e.MAC, "10.0.3.1")); err != nil {
			t.Fatalf("upsert %s: %v", rep, err)
		}
	}
	if g := mustLookup(t, s, "", "10.0.3.1"); g.Owner != "host-2" {
		t.Errorf("moved owned address: owner %q, want host-2", g.Owner)
	}
	// The same address on two endpoints of one owner is ambiguous.
	for i := range 2 {
		e := testEndpoint("10.0.3.5", fmt.Sprintf("00:11:22:33:56:0%d", i), "host-5")
		own := Identity{MACs: []string{"00:11:22:33:56:00", "00:11:22:33:56:01"}, Addrs: []netip.Addr{addr("10.0.3.5")}}
		if err := s.UpsertEndpoint(ctx, e, own); err != nil {
			t.Fatalf("upsert host-5: %v", err)
		}
	}
	if _, found, err := s.LookupEndpoint(ctx, "", addr("10.0.3.5")); found || !errors.Is(err, ErrAmbiguous) {
		t.Errorf("shared owned address: found=%v err=%v, want ErrAmbiguous", found, err)
	}

	// A MAC-less endpoint owned by its addresses.
	self := testEndpoint("10.0.4.1", "", "host-4")
	if err := s.UpsertEndpoint(ctx, self, Identity{Addrs: []netip.Addr{addr("10.0.4.1")}}); err != nil {
		t.Fatalf("upsert self: %v", err)
	}
	if g := mustLookup(t, s, "", "10.0.4.1"); g.Owner != "host-4" {
		t.Errorf("owner = %q, want host-4", g.Owner)
	}
	checkCounters(t, s, db)
}

func TestEndpointFirstSeenClamped(t *testing.T) {
	s, db, now := newTestStore(t)
	ctx := context.Background()
	const mac = "00:11:22:33:44:55"

	owner := testEndpoint("10.0.0.1", mac, "owner")
	if err := s.UpsertEndpoint(ctx, owner, macIdentity(mac)); err != nil {
		t.Fatalf("upsert owner: %v", err)
	}
	// A joining reporter claims the epoch.
	joiner := testEndpoint("10.0.0.1", mac, "joiner")
	joiner.FirstSeen = time.Unix(0, 0)
	if err := s.UpsertEndpoint(ctx, joiner, Identity{}); err != nil {
		t.Fatalf("upsert joiner: %v", err)
	}
	ingest := testNow
	got := mustLookup(t, s, mac, "")
	if got.FirstSeen != testNow.Add(-time.Hour) {
		t.Errorf("first seen = %s, want the owner's %s", got.FirstSeen, testNow.Add(-time.Hour))
	}
	if j := got.Observations[0]; j.Reporter != "joiner" || j.FirstSeen != ingest.Add(-MaxFirstSeenLead) {
		t.Errorf("joiner first seen = %s, want %s", j.FirstSeen, ingest.Add(-MaxFirstSeenLead))
	}
	// Later reports cannot move it further back: the bound is the first
	// receipt, not the current time.
	*now = now.Add(2 * time.Hour)
	joiner.LastSeen = *now
	if err := s.UpsertEndpoint(ctx, joiner, Identity{}); err != nil {
		t.Fatalf("upsert joiner again: %v", err)
	}
	got = mustLookup(t, s, mac, "")
	if j := got.Observations[0]; j.FirstSeen != ingest.Add(-MaxFirstSeenLead) {
		t.Errorf("joiner first seen = %s, want %s", j.FirstSeen, ingest.Add(-MaxFirstSeenLead))
	}
	// Without an owner the endpoint shows the earliest clamped value.
	e := testEndpoint("10.0.0.9", "", "reporter-a")
	e.FirstSeen = time.Unix(0, 0)
	e.LastSeen = *now
	if err := s.UpsertEndpoint(ctx, e, Identity{}); err != nil {
		t.Fatalf("upsert unowned: %v", err)
	}
	if g := mustLookup(t, s, "", "10.0.0.9"); g.FirstSeen != now.Add(-MaxFirstSeenLead) {
		t.Errorf("unowned first seen = %s, want %s", g.FirstSeen, now.Add(-MaxFirstSeenLead))
	}
	// An old observation keeps first_seen at or before its last_seen.
	old := testEndpoint("10.0.0.10", "", "reporter-a")
	old.FirstSeen = time.Unix(0, 0)
	old.LastSeen = now.Add(-3 * 24 * time.Hour)
	if err := s.UpsertEndpoint(ctx, old, Identity{}); err != nil {
		t.Fatalf("upsert old: %v", err)
	}
	if g := mustLookup(t, s, "", "10.0.0.10"); g.FirstSeen != old.LastSeen {
		t.Errorf("old first seen = %s, want %s", g.FirstSeen, old.LastSeen)
	}
	// A shorter retention bounds the lead.
	s2h, err := NewWithNowAndRetention(db, func() time.Time { return *now }, 2*time.Hour)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	short := testEndpoint("10.0.0.11", "", "reporter-a")
	short.FirstSeen = time.Unix(0, 0)
	short.LastSeen = *now
	if err := s2h.UpsertEndpoint(ctx, short, Identity{}); err != nil {
		t.Fatalf("upsert short: %v", err)
	}
	if g := mustLookup(t, s2h, "", "10.0.0.11"); g.FirstSeen != now.Add(-2*time.Hour) {
		t.Errorf("short-retention first seen = %s, want %s", g.FirstSeen, now.Add(-2*time.Hour))
	}
}

func TestEndpointIdentityValidation(t *testing.T) {
	s, _, _ := newTestStore(t)
	ctx := context.Background()
	e := testEndpoint("10.0.0.1", "00:11:22:33:44:55", "reporter-a")
	many := make([]string, MaxIdentityMACs+1)
	for i := range many {
		many[i] = "00:11:22:33:44:55"
	}
	for name, id := range map[string]Identity{
		"bad mac":        {MACs: []string{"00:11:22:33:44:ZZ"}},
		"too many macs":  {MACs: many},
		"invalid addr":   {Addrs: []netip.Addr{{}}},
		"too many addrs": {Addrs: make([]netip.Addr, flowagg.MaxHostAddrs+1)},
	} {
		if err := s.UpsertEndpoint(ctx, e, id); !errors.Is(err, ErrInvalidEndpoint) {
			t.Errorf("%s: err = %v, want ErrInvalidEndpoint", name, err)
		}
	}
}

func TestEndpointCaps(t *testing.T) {
	s, db, _ := newTestStore(t)
	ctx := context.Background()
	s.endpointCap = 3
	s.endpointCapReporter = 2

	macs := []string{"00:11:22:33:44:51", "00:11:22:33:44:52", "00:11:22:33:44:53",
		"00:11:22:33:44:54", "00:11:22:33:44:55"}
	addrs := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5"}

	for i, rep := range []string{"reporter-a", "reporter-a", "reporter-a", "reporter-b", "reporter-b"} {
		err := s.UpsertEndpoint(ctx, testEndpoint(addrs[i], macs[i], rep), Identity{})
		switch i {
		case 2:
			if !errors.Is(err, ErrLimit) {
				t.Errorf("upsert 3: err = %v, want ErrLimit (per reporter)", err)
			}
		case 4:
			if !errors.Is(err, ErrLimit) {
				t.Errorf("upsert 5: err = %v, want ErrLimit (total)", err)
			}
		default:
			if err != nil {
				t.Fatalf("upsert %d: %v", i, err)
			}
		}
	}
	if n := mustCount(t, s.CountEndpoints); n != 3 {
		t.Errorf("count = %d, want 3", n)
	}
	// reporter-b joins reporter-a's endpoints: that counts against
	// reporter-b only, and reporter-a's updates keep working.
	if err := s.UpsertEndpoint(ctx, testEndpoint(addrs[0], macs[0], "reporter-b"), Identity{}); err != nil {
		t.Fatalf("reporter-b joins: %v", err)
	}
	if err := s.UpsertEndpoint(ctx, testEndpoint(addrs[1], macs[1], "reporter-b"), Identity{}); !errors.Is(err, ErrLimit) {
		t.Errorf("reporter-b beyond its cap: err = %v, want ErrLimit", err)
	}
	for i := range 2 {
		if err := s.UpsertEndpoint(ctx, testEndpoint(addrs[i], macs[i], "reporter-a"), Identity{}); err != nil {
			t.Errorf("owner update %d: %v", i, err)
		}
	}
	checkCounters(t, s, db)
}

func TestEndpointReportersPerEndpointCap(t *testing.T) {
	s, _, _ := newTestStore(t)
	ctx := context.Background()
	for i := range MaxReportersPerEndpoint {
		if err := s.UpsertEndpoint(ctx, testEndpoint("10.0.0.1", "00:11:22:33:44:55", fmt.Sprintf("r%02d", i)), Identity{}); err != nil {
			t.Fatalf("reporter %d: %v", i, err)
		}
	}
	if err := s.UpsertEndpoint(ctx, testEndpoint("10.0.0.1", "00:11:22:33:44:55", "late"), Identity{}); !errors.Is(err, ErrLimit) {
		t.Errorf("reporter beyond the endpoint cap: err = %v, want ErrLimit", err)
	}
	// Existing reporters keep updating.
	if err := s.UpsertEndpoint(ctx, testEndpoint("10.0.0.1", "00:11:22:33:44:55", "r00"), Identity{}); err != nil {
		t.Errorf("existing reporter: %v", err)
	}
}

func TestEndpointValidation(t *testing.T) {
	s, _, _ := newTestStore(t)
	ctx := context.Background()
	cases := []struct {
		name string
		mut  func(*Endpoint)
		want error
	}{
		{"bad mac", func(e *Endpoint) { e.MAC = "00:11:22:33:44:ZZ" }, ErrInvalidEndpoint},
		{"uppercase mac", func(e *Endpoint) { e.MAC = "00:11:22:33:44:5A" }, ErrInvalidEndpoint},
		{"no addresses", func(e *Endpoint) { e.Addresses = nil }, ErrInvalidEndpoint},
		{"too many addresses", func(e *Endpoint) {
			var addrs []netip.Addr
			for i := 1; i <= MaxAddressesPerEndpoint+1; i++ {
				addrs = append(addrs, netip.MustParseAddr("10.0.1."+strconv.Itoa(i)))
			}
			e.Addresses = addrs
		}, ErrInvalidEndpoint},
		{"invalid address", func(e *Endpoint) { e.Addresses = []netip.Addr{{}} }, ErrInvalidEndpoint},
		{"loopback address", func(e *Endpoint) { e.Addresses = []netip.Addr{netip.MustParseAddr("127.0.0.1")} }, ErrInvalidEndpoint},
		{"mapped loopback address", func(e *Endpoint) { e.Addresses = []netip.Addr{netip.MustParseAddr("::ffff:127.0.0.1")} }, ErrInvalidEndpoint},
		{"unspecified address", func(e *Endpoint) { e.Addresses = []netip.Addr{netip.MustParseAddr("0.0.0.0")} }, ErrInvalidEndpoint},
		{"zoned global address", func(e *Endpoint) { e.Addresses = []netip.Addr{netip.MustParseAddr("2001:db8::1%eth0")} }, ErrInvalidEndpoint},
		{"vlan too high", func(e *Endpoint) { e.VLAN = 5000 }, ErrInvalidEndpoint},
		{"vlan negative", func(e *Endpoint) { e.VLAN = -1 }, ErrInvalidEndpoint},
		{"bad oui without mac", func(e *Endpoint) { e.MAC = ""; e.OUI = "GGGGGG" }, ErrInvalidEndpoint},
		{"hostname control char", func(e *Endpoint) { e.Hostname = "a\x00b" }, ErrInvalidEndpoint},
		{"hostname invalid utf8", func(e *Endpoint) { e.Hostname = "a\xffb" }, ErrInvalidEndpoint},
		{"hostname too long", func(e *Endpoint) { e.Hostname = strings.Repeat("h", maxHostnameLen+1) }, ErrInvalidEndpoint},
		{"unknown tier", func(e *Endpoint) { e.Tier = "bogus" }, ErrInvalidEndpoint},
		{"empty tier", func(e *Endpoint) { e.Tier = "" }, ErrInvalidEndpoint},
		{"empty reporter", func(e *Endpoint) { e.Reporter = "" }, ErrInvalidEndpoint},
		{"reporter too long", func(e *Endpoint) { e.Reporter = strings.Repeat("r", flowagg.MaxHostIDLen+1) }, ErrInvalidEndpoint},
		{"host id too long", func(e *Endpoint) { e.HostID = strings.Repeat("h", maxIDLen+1) }, ErrInvalidEndpoint},
		{"zero last seen", func(e *Endpoint) { e.LastSeen = time.Time{} }, ErrInvalidEndpoint},
		{"last seen before retention", func(e *Endpoint) { e.LastSeen = testNow.Add(-22 * 24 * time.Hour) }, ErrOutOfRange},
		{"last seen in the future", func(e *Endpoint) { e.LastSeen = testNow.Add(time.Hour) }, ErrOutOfRange},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := testEndpoint("10.0.0.1", "00:11:22:33:44:55", "reporter-a")
			tc.mut(&e)
			err := s.UpsertEndpoint(ctx, e, Identity{})
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
	if n := mustCount(t, s.CountEndpoints); n != 0 {
		t.Errorf("count = %d after rejected writes, want 0", n)
	}
}

func TestUpsertBucketAccumulates(t *testing.T) {
	s, _, _ := newTestStore(t)
	ctx := context.Background()

	b := testBucket("10.0.0.2", 443, 100)
	b.Connections = 2
	put(t, s, b)
	b2 := testBucket("10.0.0.2", 443, 50)
	b2.Connections = 1
	b2.LowerBound = true
	put(t, s, b2)
	if n := mustCount(t, s.CountBuckets); n != 1 {
		t.Fatalf("count = %d, want 1 (accumulate, not duplicate)", n)
	}
	totals, err := s.TopN(ctx, netip.MustParseAddr("10.0.0.1"), testWindow, 5)
	if err != nil {
		t.Fatalf("top n: %v", err)
	}
	if len(totals) != 1 {
		t.Fatalf("totals = %d, want 1", len(totals))
	}
	if totals[0].BytesAB != 150 || totals[0].Connections != 3 || !totals[0].LowerBound {
		t.Errorf("total = %+v, want bytes_ab 150, connections 3, lower_bound", totals[0])
	}
}

func TestBucketCountersSaturate(t *testing.T) {
	s, _, _ := newTestStore(t)
	ctx := context.Background()
	b := testBucket("10.0.0.2", 443, math.MaxUint64)
	b.Connections = math.MaxUint64
	put(t, s, b)
	put(t, s, b)
	totals, err := s.TopN(ctx, netip.MustParseAddr("10.0.0.1"), testWindow, 5)
	if err != nil {
		t.Fatalf("top n: %v", err)
	}
	if len(totals) != 1 || totals[0].BytesAB != uint64(maxStoredCounter) || totals[0].Connections != uint64(maxStoredCounter) {
		t.Errorf("totals = %+v, want counters saturated at %d", totals, int64(maxStoredCounter))
	}
}

func TestCounterHeadroomCoversRetention(t *testing.T) {
	hours := int64(DefaultRetention/time.Hour) + 1 // a window may straddle one extra hour
	if 2*hours > counterHeadroom {
		t.Fatalf("2 x %d hours exceed counterHeadroom %d", hours, counterHeadroom)
	}
	s, db, _ := newTestStore(t)
	ctx := context.Background()
	w := flowagg.Window{From: testNow.Add(-DefaultRetention).Add(time.Hour), To: testNow.Add(time.Hour)}
	lo, hi := hourRange(w)
	for h := lo; h <= hi; h++ {
		if _, err := db.Exec(`
			INSERT INTO flow_buckets (hour, a, b, proto, server_port, server_side, tier, server_reported,
			                          reporter, bytes_ab, bytes_ba, connections, lower_bound)
			VALUES (?, '10.0.0.1', '10.0.0.2', 6, 443, 2, 'socket', 0, 'reporter-a', ?, ?, ?, 0)`,
			h, int64(maxStoredCounter), int64(maxStoredCounter), int64(maxStoredCounter)); err != nil {
			t.Fatalf("insert hour %d: %v", h, err)
		}
	}
	totals, err := s.TopN(ctx, netip.MustParseAddr("10.0.0.1"), w, 5)
	if err != nil {
		t.Fatalf("top n over saturated hours: %v", err)
	}
	want := uint64(hi-lo+1) * uint64(maxStoredCounter)
	if len(totals) != 1 || totals[0].BytesAB != want || totals[0].BytesBA != want {
		t.Errorf("totals = %+v, want %d per direction", totals, want)
	}
}

func TestBucketCaps(t *testing.T) {
	s, db, _ := newTestStore(t)
	ctx := context.Background()
	s.bucketCap = 3
	s.bucketCapReporter = 2

	peers := []string{"10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5", "10.0.0.6"}
	reporters := []string{"reporter-a", "reporter-a", "reporter-a", "reporter-b", "reporter-b"}
	for i, rep := range reporters {
		// Each reporter reports as the server end it owns.
		b := testBucket(peers[i], 443+i, uint64(i+1))
		b.Reporter = rep
		b.ServerReported = true
		own := []netip.Addr{b.Key.B}
		err := s.UpsertBucket(ctx, b, own)
		switch i {
		case 2:
			if !errors.Is(err, ErrLimit) {
				t.Errorf("upsert 3: err = %v, want ErrLimit (per reporter)", err)
			}
		case 4:
			if !errors.Is(err, ErrLimit) {
				t.Errorf("upsert 5: err = %v, want ErrLimit (total)", err)
			}
		default:
			if err != nil {
				t.Fatalf("upsert %d: %v", i, err)
			}
		}
	}
	if n := mustCount(t, s.CountBuckets); n != 3 {
		t.Errorf("count = %d, want 3", n)
	}
	// Existing rows keep accepting data at the cap.
	b := testBucket(peers[0], 443, 5)
	b.ServerReported = true
	if err := s.UpsertBucket(ctx, b, []netip.Addr{b.Key.B}); err != nil {
		t.Errorf("existing row at cap: %v", err)
	}
	checkCounters(t, s, db)
	// Pruning frees the counts: after the retention every row is gone and
	// new rows are accepted again.
	if _, err := db.Exec(`UPDATE flow_buckets SET hour = hour - 24 * 30`); err != nil {
		t.Fatalf("age rows: %v", err)
	}
	if _, _, err := s.Prune(ctx); err != nil {
		t.Fatalf("prune: %v", err)
	}
	checkCounters(t, s, db)
	if n := mustCount(t, s.CountBuckets); n != 0 {
		t.Errorf("count after prune = %d, want 0", n)
	}
	b = testBucket(peers[2], 445, 1)
	b.ServerReported = true
	if err := s.UpsertBucket(ctx, b, []netip.Addr{b.Key.B}); err != nil {
		t.Errorf("new row after prune: %v", err)
	}
}

func TestBucketOwnershipAndConflicts(t *testing.T) {
	s, db, _ := newTestStore(t)
	ctx := context.Background()

	client := testBucket("10.0.0.2", 443, 100) // client end is 10.0.0.1
	// A reporter that does not own the client end it claims is refused.
	if err := s.UpsertBucket(ctx, client, []netip.Addr{netip.MustParseAddr("10.0.0.2")}); !errors.Is(err, ErrForeign) {
		t.Errorf("foreign client end: err = %v, want ErrForeign", err)
	}
	server := client
	server.ServerReported = true
	server.Reporter = "reporter-b"
	if err := s.UpsertBucket(ctx, server, []netip.Addr{netip.MustParseAddr("10.0.0.1")}); !errors.Is(err, ErrForeign) {
		t.Errorf("foreign server end: err = %v, want ErrForeign", err)
	}
	// Reporter addresses are checked like flowagg's.
	for name, own := range map[string][]netip.Addr{
		"none":      nil,
		"invalid":   {{}},
		"too many":  make([]netip.Addr, flowagg.MaxHostAddrs+1),
		"unspecifd": {netip.MustParseAddr("0.0.0.0")},
	} {
		if err := s.UpsertBucket(ctx, client, own); !errors.Is(err, ErrInvalidBucket) {
			t.Errorf("own %s: err = %v, want ErrInvalidBucket", name, err)
		}
	}
	// Mapped forms of the reporter's own address count as owned.
	if err := s.UpsertBucket(ctx, client, []netip.Addr{netip.MustParseAddr("::ffff:10.0.0.1")}); err != nil {
		t.Fatalf("client end owned: %v", err)
	}
	put(t, s, server)

	// Another host claiming the same end (an ambiguous address the
	// caller failed to leave out) cannot override or add to it, whatever
	// its name sorts as.
	for _, intruder := range []string{"aaa", "zzz"} {
		c := client
		c.Reporter = intruder
		c.BytesAB = 999999
		if err := s.UpsertBucket(ctx, c, ownOf(c)); !errors.Is(err, ErrConflict) {
			t.Errorf("second client reporter %s: err = %v, want ErrConflict", intruder, err)
		}
		sv := server
		sv.Reporter = intruder
		if err := s.UpsertBucket(ctx, sv, ownOf(sv)); !errors.Is(err, ErrConflict) {
			t.Errorf("second server reporter %s: err = %v, want ErrConflict", intruder, err)
		}
	}
	totals, err := s.TopN(ctx, netip.MustParseAddr("10.0.0.1"), testWindow, 5)
	if err != nil {
		t.Fatalf("top n: %v", err)
	}
	if len(totals) != 1 || totals[0].BytesAB != 100 || !totals[0].Confirmed {
		t.Errorf("totals = %+v, want the holders' 100 bytes, confirmed", totals)
	}
	if n := countRows(t, db, `SELECT COUNT(*) FROM flow_buckets`); n != 2 {
		t.Errorf("rows = %d, want 2 (one per side)", n)
	}
}

func TestBucketValidation(t *testing.T) {
	s, _, _ := newTestStore(t)
	ctx := context.Background()
	cases := []struct {
		name string
		mut  func(*Bucket)
		want error
	}{
		{"zero hour", func(b *Bucket) { b.Hour = time.Time{} }, ErrInvalidBucket},
		{"unsupported proto", func(b *Bucket) { b.Key.Proto = flowagg.Proto(1) }, ErrInvalidBucket},
		{"port zero", func(b *Bucket) { b.Key.ServerPort = 0 }, ErrInvalidBucket},
		{"bad server side", func(b *Bucket) { b.Key.Server = flowagg.Side(9) }, ErrInvalidBucket},
		{"endpoints not ordered", func(b *Bucket) { b.Key.A, b.Key.B = b.Key.B, b.Key.A }, ErrInvalidBucket},
		{"invalid endpoint", func(b *Bucket) { b.Key.B = netip.Addr{} }, ErrInvalidBucket},
		{"loopback endpoint", func(b *Bucket) { b.Key.A = netip.MustParseAddr("127.0.0.1") }, ErrInvalidBucket},
		{"mapped endpoint", func(b *Bucket) { b.Key.B = netip.MustParseAddr("::ffff:10.0.0.2") }, ErrInvalidBucket},
		{"mapped equal endpoints", func(b *Bucket) { b.Key.B = netip.MustParseAddr("::ffff:10.0.0.1") }, ErrInvalidBucket},
		{"zoned endpoint", func(b *Bucket) {
			b.Key.A = netip.MustParseAddr("fe80::1%eth0")
			b.Key.B = netip.MustParseAddr("fe80::2")
		}, ErrInvalidBucket},
		{"unknown tier", func(b *Bucket) { b.Key.Tier = "bogus" }, ErrInvalidBucket},
		{"empty reporter", func(b *Bucket) { b.Reporter = "" }, ErrInvalidBucket},
		{"reporter too long", func(b *Bucket) { b.Reporter = strings.Repeat("r", flowagg.MaxHostIDLen+1) }, ErrInvalidBucket},
		{"reporter control char", func(b *Bucket) { b.Reporter = "a\nb" }, ErrInvalidBucket},
		{"hour before retention", func(b *Bucket) { b.Hour = testNow.Add(-22 * 24 * time.Hour) }, ErrOutOfRange},
		{"hour in the future", func(b *Bucket) { b.Hour = testNow.Add(2 * time.Hour) }, ErrOutOfRange},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := testBucket("10.0.0.2", 443, 10)
			tc.mut(&b)
			own := []netip.Addr{netip.MustParseAddr("10.0.0.1")}
			if b.Key.A.IsValid() && b.Key.B.IsValid() {
				own = append(own, b.Key.A.Unmap().WithZone(""), b.Key.B.Unmap().WithZone(""))
			}
			err := s.UpsertBucket(ctx, b, own)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
	if n := mustCount(t, s.CountBuckets); n != 0 {
		t.Errorf("count = %d after rejected writes, want 0", n)
	}
}

func insertRawBucket(t *testing.T, db *sql.DB, hour int64, a, b, reporter string) {
	t.Helper()
	if _, err := db.Exec(`
		INSERT INTO flow_buckets (hour, a, b, proto, server_port, server_side, tier, server_reported,
		                          reporter, bytes_ab, bytes_ba, connections, lower_bound)
		VALUES (?, ?, ?, 6, 443, 2, 'socket', 0, ?, 1, 0, 0, 0)`, hour, a, b, reporter); err != nil {
		t.Fatalf("insert raw bucket: %v", err)
	}
}

func TestPrune(t *testing.T) {
	s, db, _ := newTestStore(t)
	ctx := context.Background()

	put(t, s, testBucket("10.0.0.4", 443, 1)) // runs the hour's automatic prune
	if err := s.UpsertEndpoint(ctx, testEndpoint("10.0.0.8", "00:11:22:33:44:56", "reporter-a"), Identity{}); err != nil {
		t.Fatalf("upsert kept endpoint: %v", err)
	}

	// Rows at the exact retention boundary, inserted directly (bypassing
	// the write-time check). cutoff = testNow - 21d lies on an hour
	// start: the hour ending at cutoff is expired, the one starting there
	// is kept.
	cutoff := testNow.Add(-DefaultRetention)
	boundary := hourOf(cutoff)
	insertRawBucket(t, db, boundary-1, "10.0.0.1", "10.0.0.2", "reporter-a") // ends at cutoff: pruned
	insertRawBucket(t, db, boundary, "10.0.0.1", "10.0.0.3", "reporter-b")   // ends after cutoff: kept

	// An endpoint last seen one second before the cutoff (pruned, with
	// its addresses and seen-by rows) and one seen exactly at it (kept).
	for _, ep := range []struct {
		id, mac string
		seen    time.Time
	}{
		{"ep-old", "00:11:22:33:44:55", cutoff.Add(-time.Second)},
		{"ep-edge", "00:11:22:33:44:57", cutoff},
	} {
		if _, err := db.Exec(`
			INSERT INTO net_endpoints (id, mac, last_seen, owner) VALUES (?, ?, ?, 'reporter-a')`,
			ep.id, ep.mac, ep.seen.Unix()); err != nil {
			t.Fatalf("insert endpoint: %v", err)
		}
		if _, err := db.Exec(`
			INSERT INTO net_endpoint_reporters (endpoint_id, reporter, tier, first_seen, first_ingest, last_seen)
			VALUES (?, 'reporter-a', 'socket', ?, ?, ?)`, ep.id, ep.seen.Unix(), ep.seen.Unix(), ep.seen.Unix()); err != nil {
			t.Fatalf("insert endpoint reporter: %v", err)
		}
		if _, err := db.Exec(`
			INSERT INTO net_endpoint_addresses (endpoint_id, reporter, address) VALUES (?, 'reporter-a', '10.1.0.1')`, ep.id); err != nil {
			t.Fatalf("insert endpoint address: %v", err)
		}
	}
	checkCounters(t, s, db)

	buckets, endpoints, err := s.Prune(ctx)
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if buckets != 1 || endpoints != 1 {
		t.Errorf("pruned = %d buckets, %d endpoints, want 1, 1", buckets, endpoints)
	}
	if n := countRows(t, db, `SELECT COUNT(*) FROM flow_buckets WHERE hour = ?`, boundary); n != 1 {
		t.Errorf("boundary bucket kept = %d, want 1", n)
	}
	if n := countRows(t, db, `SELECT COUNT(*) FROM flow_buckets`); n != 2 {
		t.Errorf("buckets left = %d, want 2", n)
	}
	for table, want := range map[string]int{
		"net_endpoint_reporters": 0,
		"net_endpoint_addresses": 0,
	} {
		if n := countRows(t, db, `SELECT COUNT(*) FROM `+table+` WHERE endpoint_id = 'ep-old'`); n != want {
			t.Errorf("%s rows of the pruned endpoint = %d, want %d (cascade)", table, n, want)
		}
	}
	if _, err := s.Endpoint(ctx, "ep-edge"); err != nil {
		t.Errorf("endpoint at the cutoff pruned: %v", err)
	}
	if _, found, err := s.LookupEndpoint(ctx, "00:11:22:33:44:56", netip.Addr{}); err != nil || !found {
		t.Errorf("kept endpoint missing: found=%v err=%v", found, err)
	}
	checkCounters(t, s, db)
	// Prune is idempotent.
	if b, e, err := s.Prune(ctx); err != nil || b != 0 || e != 0 {
		t.Errorf("second prune = %d, %d, %v, want 0, 0, nil", b, e, err)
	}
}

func TestPruneClearsExpiredOwner(t *testing.T) {
	s, db, now := newTestStore(t)
	ctx := context.Background()
	const mac = "00:11:22:33:44:55"

	owner := testEndpoint("10.0.0.1", mac, "owner")
	owner.FirstSeen = testNow.Add(-20 * 24 * time.Hour)
	owner.LastSeen = owner.FirstSeen
	if err := s.UpsertEndpoint(ctx, owner, macIdentity(mac)); err != nil {
		t.Fatalf("upsert owner: %v", err)
	}
	// Other reporters, one claiming a far earlier first_seen.
	for i, r := range []string{"second", "third"} {
		e := testEndpoint("10.0.0.1", mac, r)
		e.FirstSeen = time.Unix(0, 0)
		e.LastSeen = testNow.Add(time.Duration(i-2) * time.Hour)
		e.Tier = []string{flowagg.TierConntrack, flowagg.TierSensor}[i]
		if err := s.UpsertEndpoint(ctx, e, Identity{}); err != nil {
			t.Fatalf("upsert %s: %v", r, err)
		}
	}
	if g := mustLookup(t, s, mac, ""); g.Owner != "owner" || g.Tier != flowagg.TierSocket {
		t.Fatalf("owner/tier = %q/%q, want owner/socket", g.Owner, g.Tier)
	}
	// Two days later the owner's observation has expired: no reporter
	// takes over, whatever first_seen it claimed, and the tier is the
	// most recently seen reporter's.
	*now = now.Add(2 * 24 * time.Hour)
	if _, _, err := s.Prune(ctx); err != nil {
		t.Fatalf("prune: %v", err)
	}
	got := mustLookup(t, s, mac, "")
	if got.Owner != "" || got.HostID != "" {
		t.Errorf("owner/host = %q/%q, want none", got.Owner, got.HostID)
	}
	if got.Tier != flowagg.TierSensor {
		t.Errorf("tier = %q, want the latest reporter's %q", got.Tier, flowagg.TierSensor)
	}
	if !slices.Equal(got.SeenBy, []string{"second", "third"}) {
		t.Errorf("seen-by = %v, want second and third", got.SeenBy)
	}
	// The owner reports again: it owns the endpoint and its latest tier
	// is shown.
	owner.FirstSeen = time.Time{}
	owner.LastSeen = *now
	owner.Tier = flowagg.TierConntrack
	if err := s.UpsertEndpoint(ctx, owner, macIdentity(mac)); err != nil {
		t.Fatalf("owner reports again: %v", err)
	}
	if g := mustLookup(t, s, mac, ""); g.Owner != "owner" || g.Tier != flowagg.TierConntrack || g.FirstSeen != *now {
		t.Errorf("owner/tier/first = %q/%q/%s, want owner/conntrack/%s", g.Owner, g.Tier, g.FirstSeen, *now)
	}
	checkCounters(t, s, db)
}

func TestRetentionConfigurableLowerOnly(t *testing.T) {
	_, db, now := newTestStore(t)
	ctx := context.Background()
	nowFn := func() time.Time { return *now }

	if _, err := NewWithNowAndRetention(db, nowFn, 30*24*time.Hour); err == nil {
		t.Error("retention above the default accepted, want error")
	}
	if _, err := NewWithRetention(db, 30*24*time.Hour); err == nil {
		t.Error("retention above the default accepted, want error")
	}
	if _, err := NewWithNowAndRetention(db, nowFn, 0); err == nil {
		t.Error("zero retention accepted, want error")
	}
	if _, err := NewWithNowAndRetention(db, nil, 7*24*time.Hour); err != nil {
		t.Fatalf("nil now rejected: %v", err)
	}

	s7, err := NewWithNowAndRetention(db, nowFn, 7*24*time.Hour)
	if err != nil {
		t.Fatalf("new store 7d: %v", err)
	}
	old := testBucket("10.0.0.2", 443, 1)
	old.Hour = testNow.Add(-10 * 24 * time.Hour)
	if err := s7.UpsertBucket(ctx, old, ownOf(old)); !errors.Is(err, ErrOutOfRange) {
		t.Errorf("upsert 10d old with 7d retention: err = %v, want ErrOutOfRange", err)
	}
	kept := testBucket("10.0.0.3", 443, 1)
	kept.Hour = testNow.Add(-5 * 24 * time.Hour)
	put(t, s7, kept)
	oldE := testEndpoint("10.0.0.9", "00:11:22:33:44:55", "reporter-a")
	oldE.LastSeen = testNow.Add(-10 * 24 * time.Hour)
	oldE.FirstSeen = oldE.LastSeen
	if err := s7.UpsertEndpoint(ctx, oldE, Identity{}); !errors.Is(err, ErrOutOfRange) {
		t.Errorf("upsert 10d old endpoint: err = %v, want ErrOutOfRange", err)
	}
	wide := flowagg.Window{From: testNow.Add(-8 * 24 * time.Hour), To: testNow}
	if _, err := s7.TopN(ctx, netip.MustParseAddr("10.0.0.1"), wide, 5); !errors.Is(err, ErrInvalidWindow) {
		t.Errorf("8d window with 7d retention: err = %v, want ErrInvalidWindow", err)
	}
}

func TestAutoPruneHourly(t *testing.T) {
	s, db, now := newTestStore(t)

	put(t, s, testBucket("10.0.0.2", 443, 1))
	// An expired row inserted directly (bypassing validation) after the
	// first write's automatic prune.
	insertRawBucket(t, db, hourOf(*now)-22*24, "10.0.0.1", "10.0.0.9", "reporter-a")
	// A second write in the same clock hour must not re-prune.
	put(t, s, testBucket("10.0.0.3", 443, 1))
	if n := mustCount(t, s.CountBuckets); n != 3 {
		t.Fatalf("buckets = %d, want 3 (no prune within the same hour)", n)
	}
	// The next clock hour prunes on write.
	*now = now.Add(2 * time.Hour)
	b := testBucket("10.0.0.4", 443, 1)
	b.Hour = *now
	put(t, s, b)
	if n := mustCount(t, s.CountBuckets); n != 3 {
		t.Errorf("buckets = %d, want 3 (expired row pruned in the new hour)", n)
	}
	checkCounters(t, s, db)
}

func TestConcurrentWritersAreSerialized(t *testing.T) {
	s, db, _ := newTestStore(t)
	ctx := context.Background()
	const writers, perWriter = 4, 25
	var wg sync.WaitGroup
	errs := make(chan error, writers*perWriter*2)
	for w := range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			reporter := fmt.Sprintf("reporter-%d", w)
			for i := range perWriter {
				b := testBucket(fmt.Sprintf("10.%d.0.%d", w+1, i+1), 443, 1)
				b.Reporter = reporter
				b.ServerReported = true
				if err := s.UpsertBucket(ctx, b, []netip.Addr{b.Key.B}); err != nil {
					errs <- err
				}
				e := testEndpoint(fmt.Sprintf("10.%d.1.%d", w+1, i+1), "", reporter)
				if err := s.UpsertEndpoint(ctx, e, Identity{}); err != nil {
					errs <- err
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent write: %v", err)
	}
	if n := mustCount(t, s.CountBuckets); n != writers*perWriter {
		t.Errorf("buckets = %d, want %d", n, writers*perWriter)
	}
	checkCounters(t, s, db)
}

func TestTopN(t *testing.T) {
	s, _, _ := newTestStore(t)
	ctx := context.Background()

	flows := []struct {
		peer  string
		port  int
		bytes uint64
	}{
		{"10.0.0.2", 443, 1000},
		{"10.0.0.10", 80, 500}, // sorts after 10.0.0.4 as an address, before it as text
		{"10.0.0.4", 53, 500},
		{"10.0.0.5", 22, 2000},
		{"10.0.0.6", 8080, 100},
		{"10.0.0.7", 9000, 50},
	}
	for _, f := range flows {
		b := testBucket(f.peer, f.port, f.bytes)
		if f.peer == "10.0.0.5" {
			b.Key.Server = flowagg.SideA // server is the node itself
		}
		if f.peer == "10.0.0.4" {
			b.Key.Proto = flowagg.UDP
		}
		put(t, s, b)
	}
	// A huge flow outside the window must not appear.
	out := testBucket("10.0.0.8", 7000, 999999)
	out.Hour = time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)
	put(t, s, out)

	totals, err := s.TopN(ctx, netip.MustParseAddr("10.0.0.1"), testWindow, 5)
	if err != nil {
		t.Fatalf("top n: %v", err)
	}
	want := []struct {
		peer  string
		port  int
		total uint64
	}{
		{"10.0.0.5", 22, 2000},
		{"10.0.0.2", 443, 1000},
		{"10.0.0.4", 53, 500}, // tie with 10.0.0.10, ordered by address
		{"10.0.0.10", 80, 500},
		{"10.0.0.6", 8080, 100},
	}
	if len(totals) != len(want) {
		t.Fatalf("totals = %d, want %d", len(totals), len(want))
	}
	for i, w := range want {
		g := totals[i]
		if g.Key.B.String() != w.peer || int(g.Key.ServerPort) != w.port {
			t.Errorf("totals[%d] = %s:%d, want %s:%d", i, g.Key.B, g.Key.ServerPort, w.peer, w.port)
		}
		if g.Total() != w.total {
			t.Errorf("totals[%d].total = %d, want %d", i, g.Total(), w.total)
		}
		if g.FirstSeen != time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC) ||
			g.LastSeen != time.Date(2026, 11, 1, 13, 0, 0, 0, time.UTC) {
			t.Errorf("totals[%d].seen = %s..%s", i, g.FirstSeen, g.LastSeen)
		}
	}

	// The node as server end (B) is found through the b index, and a
	// mapped node address is normalized.
	totals, err = s.TopN(ctx, netip.MustParseAddr("::ffff:10.0.0.5"), testWindow, 0)
	if err != nil {
		t.Fatalf("top n of b: %v", err)
	}
	if len(totals) != 1 || totals[0].Total() != 2000 {
		t.Errorf("totals of 10.0.0.5 = %+v", totals)
	}

	// A node without flows gets an empty result.
	totals, err = s.TopN(ctx, netip.MustParseAddr("10.0.0.9"), testWindow, 5)
	if err != nil {
		t.Fatalf("top n empty node: %v", err)
	}
	if len(totals) != 0 {
		t.Errorf("totals = %d, want 0", len(totals))
	}
}

func TestTopNTiesBeyondRowCap(t *testing.T) {
	s, _, _ := newTestStore(t)
	ctx := context.Background()
	// More equal flows than maxTopRows: the result is still exactly n,
	// deterministic across calls.
	for i := range maxTopRows + 10 {
		put(t, s, testBucket(fmt.Sprintf("10.1.%d.%d", i/250, i%250+1), 443, 7))
	}
	var first []flowagg.FlowTotal
	for range 2 {
		totals, err := s.TopN(ctx, netip.MustParseAddr("10.0.0.1"), testWindow, 5)
		if err != nil {
			t.Fatalf("top n: %v", err)
		}
		if len(totals) != 5 {
			t.Fatalf("totals = %d, want 5", len(totals))
		}
		if first == nil {
			first = totals
			continue
		}
		for i := range totals {
			if totals[i].Key != first[i].Key {
				t.Errorf("totals[%d] = %v, then %v", i, first[i].Key, totals[i].Key)
			}
		}
	}
}

func TestTopNTiesBeyondRowCapFollowKeyOrder(t *testing.T) {
	s, _, _ := newTestStore(t)
	ctx := context.Background()
	// More tied flows than maxTopRows, where text order of the peers
	// ("10.10.…" < "10.9.…") differs from address order (10.9 < 10.10):
	// the result must be flowagg's key order, the smallest peers.
	for i := range maxTopRows + 10 {
		put(t, s, testBucket(fmt.Sprintf("10.10.%d.%d", i/250, i%250+1), 443, 7))
	}
	for i := 1; i <= 5; i++ {
		put(t, s, testBucket(fmt.Sprintf("10.9.0.%d", i), 443, 7))
	}
	totals, err := s.TopN(ctx, netip.MustParseAddr("10.0.0.1"), testWindow, 5)
	if err != nil {
		t.Fatalf("top n: %v", err)
	}
	if len(totals) != 5 {
		t.Fatalf("totals = %d, want 5", len(totals))
	}
	for i, tot := range totals {
		if want := netip.MustParseAddr(fmt.Sprintf("10.9.0.%d", i+1)); tot.Key.B != want {
			t.Errorf("totals[%d].B = %s, want %s", i, tot.Key.B, want)
		}
	}
}

func TestAddrOrderKeyMatchesCompare(t *testing.T) {
	addrs := []netip.Addr{
		netip.MustParseAddr("10.0.0.9"), netip.MustParseAddr("10.0.0.10"),
		netip.MustParseAddr("9.255.255.255"), netip.MustParseAddr("255.0.0.1"),
		netip.MustParseAddr("::1:2"), netip.MustParseAddr("2001:db8::1"),
		netip.MustParseAddr("fe80::1"), netip.MustParseAddr("::ffff:0:1"),
	}
	for _, a1 := range addrs {
		for _, b1 := range addrs {
			for _, a2 := range addrs {
				for _, b2 := range addrs {
					want := a1.Compare(a2)
					if want == 0 {
						want = b1.Compare(b2)
					}
					got := bytes.Compare(addrOrderKey(a1, b1), addrOrderKey(a2, b2))
					if got != want {
						t.Fatalf("order of (%s,%s) vs (%s,%s) = %d, want %d", a1, b1, a2, b2, got, want)
					}
				}
			}
		}
	}
}

func TestBucketClockSkewAtHourBoundary(t *testing.T) {
	s, _, now := newTestStore(t)
	ctx := context.Background()
	// The server is two seconds before the hour, the reporter already in
	// the next one.
	*now = testNow.Add(time.Hour - 2*time.Second)
	b := testBucket("10.0.0.2", 443, 1)
	b.Hour = testNow.Add(time.Hour + time.Second)
	if err := s.UpsertBucket(ctx, b, ownOf(b)); err != nil {
		t.Errorf("hour within the clock skew: %v", err)
	}
	// Beyond the skew it is refused.
	*now = testNow.Add(time.Hour - flowagg.DefaultMaxClockSkew - time.Second)
	b.Key.B = netip.MustParseAddr("10.0.0.3")
	if err := s.UpsertBucket(ctx, b, ownOf(b)); !errors.Is(err, ErrOutOfRange) {
		t.Errorf("hour beyond the clock skew: err = %v, want ErrOutOfRange", err)
	}
}

func TestTopNServerPreferredOverClient(t *testing.T) {
	s, db, _ := newTestStore(t)
	ctx := context.Background()

	key := flowagg.FlowKey{
		A:          netip.MustParseAddr("10.0.0.1"),
		B:          netip.MustParseAddr("10.0.0.2"),
		Proto:      flowagg.TCP,
		ServerPort: 443,
		Server:     flowagg.SideB,
		Tier:       flowagg.TierSocket,
	}
	client := Bucket{Hour: testNow, Key: key, Reporter: "client-a", BytesAB: 100}
	put(t, s, client)
	server := client
	server.Reporter = "server-b"
	server.ServerReported = true
	server.BytesAB = 42
	put(t, s, server)
	// A second hour reported by the client only.
	earlier := client
	earlier.Hour = testNow.Add(-time.Hour)
	earlier.BytesAB = 10
	earlier.LowerBound = true
	put(t, s, earlier)

	totals, err := s.TopN(ctx, netip.MustParseAddr("10.0.0.1"), testWindow, 5)
	if err != nil {
		t.Fatalf("top n: %v", err)
	}
	if len(totals) != 1 {
		t.Fatalf("totals = %d, want 1", len(totals))
	}
	g := totals[0]
	if g.BytesAB != 52 || !g.ServerReported || g.Confirmed || !g.LowerBound {
		t.Errorf("total = %+v, want 42 (server) + 10 (client-only hour), not confirmed in every hour, lower bound", g)
	}
	if g.FirstSeen != testNow.Add(-time.Hour) || g.LastSeen != testNow.Add(time.Hour) {
		t.Errorf("seen = %s..%s", g.FirstSeen, g.LastSeen)
	}

	// Only the hour both ends reported: confirmed.
	w := flowagg.Window{From: testNow, To: testNow.Add(time.Hour)}
	totals, err = s.TopN(ctx, netip.MustParseAddr("10.0.0.2"), w, 5)
	if err != nil {
		t.Fatalf("top n: %v", err)
	}
	if len(totals) != 1 || totals[0].BytesAB != 42 || !totals[0].Confirmed || totals[0].LowerBound {
		t.Errorf("totals = %+v, want 42 confirmed", totals)
	}

	// Without the server end's report the client row is used.
	if _, err := db.ExecContext(ctx, `DELETE FROM flow_buckets WHERE reporter = ?`, "server-b"); err != nil {
		t.Fatalf("delete server row: %v", err)
	}
	totals, err = s.TopN(ctx, netip.MustParseAddr("10.0.0.1"), w, 5)
	if err != nil {
		t.Fatalf("top n: %v", err)
	}
	if len(totals) != 1 || totals[0].BytesAB != 100 || totals[0].ServerReported || totals[0].Confirmed {
		t.Errorf("totals = %+v, want bytes 100, client reported, not confirmed", totals)
	}
}

func TestQueryRejectsCorruptStoredRows(t *testing.T) {
	s, db, _ := newTestStore(t)
	ctx := context.Background()
	for _, bad := range []string{"not-an-address", "10.0.0.1%eth0"} {
		if _, err := db.Exec(`DELETE FROM flow_buckets`); err != nil {
			t.Fatalf("clear: %v", err)
		}
		insertRawBucket(t, db, hourOf(testNow), "10.0.0.1", bad, "reporter-a")
		if _, err := s.TopN(ctx, netip.MustParseAddr("10.0.0.1"), testWindow, 5); err == nil {
			t.Errorf("stored %q: TopN succeeded, want an error", bad)
		}
	}
}

func TestOverviewUnion(t *testing.T) {
	s, _, _ := newTestStore(t)
	ctx := context.Background()

	add := func(a, b string, port int, bytes uint64) {
		t.Helper()
		key := flowagg.FlowKey{
			A:          netip.MustParseAddr(a),
			B:          netip.MustParseAddr(b),
			Proto:      flowagg.TCP,
			ServerPort: uint16(port),
			Server:     flowagg.SideB,
			Tier:       flowagg.TierSocket,
		}
		put(t, s, Bucket{Hour: testNow, Key: key, Reporter: "reporter-" + a, BytesAB: bytes})
	}
	add("10.0.0.1", "10.0.0.2", 443, 1000)
	add("10.0.0.1", "10.0.0.3", 80, 900)
	add("10.0.0.2", "10.0.0.3", 8080, 800)
	add("10.0.0.1", "10.0.0.4", 22, 700)
	add("10.0.0.2", "10.0.0.4", 9000, 600)

	nodes := []netip.Addr{netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2"), netip.MustParseAddr("::ffff:10.0.0.1")}
	totals, err := s.OverviewUnion(ctx, nodes, testWindow, 2)
	if err != nil {
		t.Fatalf("overview union: %v", err)
	}
	// node 1 top-2: 1-2 (1000), 1-3 (900); node 2 top-2: 1-2 (1000),
	// 2-3 (800). Union: 1000, 900, 800.
	want := []struct {
		a, b  string
		total uint64
	}{
		{"10.0.0.1", "10.0.0.2", 1000},
		{"10.0.0.1", "10.0.0.3", 900},
		{"10.0.0.2", "10.0.0.3", 800},
	}
	if len(totals) != len(want) {
		t.Fatalf("totals = %d, want %d (%+v)", len(totals), len(want), totals)
	}
	for i, w := range want {
		if totals[i].Key.A.String() != w.a || totals[i].Key.B.String() != w.b {
			t.Errorf("totals[%d] = %s-%s, want %s-%s", i, totals[i].Key.A, totals[i].Key.B, w.a, w.b)
		}
		if totals[i].Total() != w.total {
			t.Errorf("totals[%d].total = %d, want %d", i, totals[i].Total(), w.total)
		}
	}
}

func TestQueryLimits(t *testing.T) {
	s, _, _ := newTestStore(t)
	ctx := context.Background()
	node := netip.MustParseAddr("10.0.0.1")

	if _, err := s.TopN(ctx, node, testWindow, MaxTopN+1); !errors.Is(err, ErrInvalidQuery) {
		t.Errorf("n above MaxTopN: err = %v, want ErrInvalidQuery", err)
	}
	if _, err := s.OverviewUnion(ctx, []netip.Addr{node}, testWindow, MaxTopN+1); !errors.Is(err, ErrInvalidQuery) {
		t.Errorf("union n above MaxTopN: err = %v, want ErrInvalidQuery", err)
	}
	many := make([]netip.Addr, MaxOverviewNodes+1)
	for i := range many {
		many[i] = netip.AddrFrom4([4]byte{10, 2, byte(i >> 8), byte(i)})
	}
	if _, err := s.OverviewUnion(ctx, many, testWindow, 5); !errors.Is(err, ErrInvalidQuery) {
		t.Errorf("too many nodes: err = %v, want ErrInvalidQuery", err)
	}
	if _, err := s.OverviewUnion(ctx, many[:MaxOverviewNodes], testWindow, MaxTopN); err != nil {
		t.Errorf("MaxOverviewNodes nodes: %v", err)
	}
}

func TestWindowValidation(t *testing.T) {
	s, _, _ := newTestStore(t)
	ctx := context.Background()
	node := netip.MustParseAddr("10.0.0.1")

	empty := flowagg.Window{From: testNow, To: testNow}
	if _, err := s.TopN(ctx, node, empty, 5); !errors.Is(err, ErrInvalidWindow) {
		t.Errorf("empty window: err = %v, want ErrInvalidWindow", err)
	}
	inverted := flowagg.Window{From: testNow, To: testNow.Add(-time.Hour)}
	if _, err := s.TopN(ctx, node, inverted, 5); !errors.Is(err, ErrInvalidWindow) {
		t.Errorf("inverted window: err = %v, want ErrInvalidWindow", err)
	}
	tooWide := flowagg.Window{From: testNow.Add(-22 * 24 * time.Hour), To: testNow}
	if _, err := s.TopN(ctx, node, tooWide, 5); !errors.Is(err, ErrInvalidWindow) {
		t.Errorf("too wide window: err = %v, want ErrInvalidWindow", err)
	}
	if _, err := s.OverviewUnion(ctx, []netip.Addr{node}, tooWide, 5); !errors.Is(err, ErrInvalidWindow) {
		t.Errorf("too wide union window: err = %v, want ErrInvalidWindow", err)
	}
	for _, bad := range []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("0.0.0.0"), {}, netip.MustParseAddr("2001:db8::1%eth0")} {
		if _, err := s.TopN(ctx, bad, testWindow, 5); !errors.Is(err, ErrInvalidQuery) {
			t.Errorf("node %v: err = %v, want ErrInvalidQuery", bad, err)
		}
		if _, err := s.OverviewUnion(ctx, []netip.Addr{node, bad}, testWindow, 5); !errors.Is(err, ErrInvalidQuery) {
			t.Errorf("union node %v: err = %v, want ErrInvalidQuery", bad, err)
		}
	}
}

func TestHourHelpers(t *testing.T) {
	if got := hourOf(time.Unix(-1, 0)); got != -1 {
		t.Errorf("hourOf(-1s) = %d, want -1", got)
	}
	if got := pruneHourBound(7200); got != 1 {
		t.Errorf("pruneHourBound(7200) = %d, want 1 (hour 1 ends at 7200)", got)
	}
	if got := pruneHourBound(7199); got != 0 {
		t.Errorf("pruneHourBound(7199) = %d, want 0", got)
	}
	lo, hi := hourRange(flowagg.Window{From: time.Unix(3600, 0), To: time.Unix(7200, 0)})
	if lo != 1 || hi != 1 {
		t.Errorf("hourRange = %d..%d, want 1..1", lo, hi)
	}
}

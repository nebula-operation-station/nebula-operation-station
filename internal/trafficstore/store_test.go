// SPDX-License-Identifier: AGPL-3.0-or-later

package trafficstore

import (
	"context"
	"database/sql"
	"errors"
	"math"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"
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

func TestSchemaAndIndexes(t *testing.T) {
	_, db, _ := newTestStore(t)
	ctx := context.Background()

	var tables map[string]bool
	rows, err := db.QueryContext(ctx, `SELECT name FROM sqlite_master WHERE type = 'table'`)
	if err != nil {
		t.Fatalf("list tables: %v", err)
	}
	tables = make(map[string]bool)
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatalf("scan table: %v", err)
		}
		tables[name] = true
	}
	if err := rows.Close(); err != nil {
		t.Fatalf("close tables: %v", err)
	}
	for _, want := range []string{"net_endpoints", "net_endpoint_addresses", "flow_buckets"} {
		if !tables[want] {
			t.Errorf("missing table %s", want)
		}
	}

	var indexes map[string]bool
	rows, err = db.QueryContext(ctx, `SELECT name FROM sqlite_master WHERE type = 'index'`)
	if err != nil {
		t.Fatalf("list indexes: %v", err)
	}
	indexes = make(map[string]bool)
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatalf("scan index: %v", err)
		}
		indexes[name] = true
	}
	if err := rows.Close(); err != nil {
		t.Fatalf("close indexes: %v", err)
	}
	// Top-5 queries scan (a, hour) / (b, hour); pruning scans (hour);
	// per-reporter caps count on (reporter).
	for _, want := range []string{
		"idx_flow_buckets_a_hour",
		"idx_flow_buckets_b_hour",
		"idx_flow_buckets_hour",
		"idx_flow_buckets_reporter",
		"idx_net_endpoints_mac",
		"idx_net_endpoints_last_seen",
		"idx_net_endpoints_reporter",
		"idx_net_endpoint_addresses_address",
	} {
		if !indexes[want] {
			t.Errorf("missing index %s", want)
		}
	}
}

func TestUpsertEndpoint(t *testing.T) {
	s, _, now := newTestStore(t)
	ctx := context.Background()

	e := testEndpoint("10.0.0.1", "00:11:22:33:44:55", "reporter-a")
	if err := s.UpsertEndpoint(ctx, e); err != nil {
		t.Fatalf("upsert endpoint: %v", err)
	}
	got, err := s.Endpoint(ctx, "mac:00:11:22:33:44:55")
	if err != nil {
		t.Fatalf("read endpoint: %v", err)
	}
	if got.OUI != "001122" {
		t.Errorf("oui = %q, want 001122", got.OUI)
	}
	if got.FirstSeen != testNow.Add(-time.Hour) || got.LastSeen != testNow {
		t.Errorf("seen = %s..%s, want %s..%s", got.FirstSeen, got.LastSeen, testNow.Add(-time.Hour), testNow)
	}
	if len(got.Addresses) != 1 || got.Addresses[0] != netip.MustParseAddr("10.0.0.1") {
		t.Errorf("addresses = %v", got.Addresses)
	}

	// Re-upsert an hour later: last_seen advances, first_seen keeps,
	// empty hostname is not clobbered, a new address is added.
	*now = now.Add(time.Hour)
	e2 := testEndpoint("10.0.0.2", "00:11:22:33:44:55", "reporter-a")
	e2.Addresses = []netip.Addr{netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2")}
	e2.Hostname = ""
	e2.FirstSeen = time.Time{}
	e2.LastSeen = *now
	if err := s.UpsertEndpoint(ctx, e2); err != nil {
		t.Fatalf("re-upsert endpoint: %v", err)
	}
	got, err = s.Endpoint(ctx, "mac:00:11:22:33:44:55")
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
	n, err := s.CountEndpoints(ctx)
	if err != nil {
		t.Fatalf("count endpoints: %v", err)
	}
	if n != 1 {
		t.Errorf("count = %d, want 1", n)
	}
}

func TestEndpointMergeByMACAndAddress(t *testing.T) {
	s, _, _ := newTestStore(t)
	ctx := context.Background()

	// First seen by address only.
	e1 := testEndpoint("10.0.0.9", "", "reporter-a")
	e1.LastSeen = testNow.Add(-time.Hour)
	e1.FirstSeen = testNow.Add(-time.Hour)
	if err := s.UpsertEndpoint(ctx, e1); err != nil {
		t.Fatalf("upsert by address: %v", err)
	}
	got, err := s.Endpoint(ctx, "addr:10.0.0.9")
	if err != nil {
		t.Fatalf("read endpoint: %v", err)
	}
	if got.MAC != "" {
		t.Fatalf("mac = %q, want empty", got.MAC)
	}

	// Later observation carries the MAC: it must merge into the same row.
	e2 := testEndpoint("10.0.0.9", "00:11:22:33:44:66", "reporter-a")
	if err := s.UpsertEndpoint(ctx, e2); err != nil {
		t.Fatalf("upsert with mac: %v", err)
	}
	n, err := s.CountEndpoints(ctx)
	if err != nil {
		t.Fatalf("count endpoints: %v", err)
	}
	if n != 1 {
		t.Fatalf("count = %d, want 1 (merge, not duplicate)", n)
	}
	got, err = s.Endpoint(ctx, "addr:10.0.0.9")
	if err != nil {
		t.Fatalf("read endpoint: %v", err)
	}
	if got.MAC != "00:11:22:33:44:66" || got.OUI != "001122" {
		t.Errorf("mac/oui = %q/%q, want 00:11:22:33:44:66/001122", got.MAC, got.OUI)
	}
	if got.FirstSeen != testNow.Add(-time.Hour) {
		t.Errorf("first_seen = %s, want %s", got.FirstSeen, testNow.Add(-time.Hour))
	}
	if got.LastSeen != testNow {
		t.Errorf("last_seen = %s, want %s", got.LastSeen, testNow)
	}

	e, found, err := s.LookupEndpoint(ctx, "00:11:22:33:44:66", netip.Addr{})
	if err != nil || !found {
		t.Fatalf("lookup by mac: found=%v err=%v", found, err)
	}
	if e.ID != "addr:10.0.0.9" {
		t.Errorf("id = %q, want addr:10.0.0.9", e.ID)
	}
	_, found, err = s.LookupEndpoint(ctx, "", netip.MustParseAddr("10.0.0.9"))
	if err != nil || !found {
		t.Fatalf("lookup by address: found=%v err=%v", found, err)
	}
}

func TestEndpointCaps(t *testing.T) {
	s, _, _ := newTestStore(t)
	ctx := context.Background()
	s.endpointCap = 3
	s.endpointCapReporter = 2

	macs := []string{"00:11:22:33:44:51", "00:11:22:33:44:52", "00:11:22:33:44:53",
		"00:11:22:33:44:54", "00:11:22:33:44:55"}
	addrs := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5"}

	for i, rep := range []string{"reporter-a", "reporter-a", "reporter-a", "reporter-b", "reporter-b"} {
		e := testEndpoint(addrs[i], macs[i], rep)
		err := s.UpsertEndpoint(ctx, e)
		switch i {
		case 2:
			// reporter-a already has 2 endpoints.
			if !errors.Is(err, ErrLimit) {
				t.Errorf("upsert 3: err = %v, want ErrLimit (per reporter)", err)
			}
		case 4:
			// total is at the cap (3).
			if !errors.Is(err, ErrLimit) {
				t.Errorf("upsert 5: err = %v, want ErrLimit (total)", err)
			}
		default:
			if err != nil {
				t.Fatalf("upsert %d: %v", i, err)
			}
		}
	}
	n, err := s.CountEndpoints(ctx)
	if err != nil {
		t.Fatalf("count endpoints: %v", err)
	}
	if n != 3 {
		t.Errorf("count = %d, want 3", n)
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
		{"loopback address", func(e *Endpoint) { e.Addresses = []netip.Addr{netip.MustParseAddr("127.0.0.1")} }, ErrInvalidEndpoint},
		{"unspecified address", func(e *Endpoint) { e.Addresses = []netip.Addr{netip.MustParseAddr("0.0.0.0")} }, ErrInvalidEndpoint},
		{"vlan too high", func(e *Endpoint) { e.VLAN = 5000 }, ErrInvalidEndpoint},
		{"vlan negative", func(e *Endpoint) { e.VLAN = -1 }, ErrInvalidEndpoint},
		{"bad oui without mac", func(e *Endpoint) { e.MAC = ""; e.OUI = "GGGGGG" }, ErrInvalidEndpoint},
		{"hostname control char", func(e *Endpoint) { e.Hostname = "a\x00b" }, ErrInvalidEndpoint},
		{"hostname too long", func(e *Endpoint) { e.Hostname = strings.Repeat("h", maxHostnameLen+1) }, ErrInvalidEndpoint},
		{"unknown tier", func(e *Endpoint) { e.Tier = "bogus" }, ErrInvalidEndpoint},
		{"empty tier", func(e *Endpoint) { e.Tier = "" }, ErrInvalidEndpoint},
		{"empty reporter", func(e *Endpoint) { e.Reporter = "" }, ErrInvalidEndpoint},
		{"reporter too long", func(e *Endpoint) { e.Reporter = strings.Repeat("r", flowagg.MaxHostIDLen+1) }, ErrInvalidEndpoint},
		{"zero last seen", func(e *Endpoint) { e.LastSeen = time.Time{} }, ErrInvalidEndpoint},
		{"last seen before retention", func(e *Endpoint) { e.LastSeen = testNow.Add(-22 * 24 * time.Hour) }, ErrOutOfRange},
		{"last seen in the future", func(e *Endpoint) { e.LastSeen = testNow.Add(time.Hour) }, ErrOutOfRange},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := testEndpoint("10.0.0.1", "00:11:22:33:44:55", "reporter-a")
			tc.mut(&e)
			err := s.UpsertEndpoint(ctx, e)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestUpsertBucketAccumulates(t *testing.T) {
	s, _, _ := newTestStore(t)
	ctx := context.Background()

	b := testBucket("10.0.0.2", 443, 100)
	b.Connections = 2
	if err := s.UpsertBucket(ctx, b); err != nil {
		t.Fatalf("upsert bucket: %v", err)
	}
	b2 := testBucket("10.0.0.2", 443, 50)
	b2.Connections = 1
	b2.LowerBound = true
	if err := s.UpsertBucket(ctx, b2); err != nil {
		t.Fatalf("upsert bucket again: %v", err)
	}
	n, err := s.CountBuckets(ctx)
	if err != nil {
		t.Fatalf("count buckets: %v", err)
	}
	if n != 1 {
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

func TestBucketCaps(t *testing.T) {
	s, _, _ := newTestStore(t)
	ctx := context.Background()
	s.bucketCap = 3
	s.bucketCapReporter = 2

	peers := []string{"10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5", "10.0.0.6"}
	reporters := []string{"reporter-a", "reporter-a", "reporter-a", "reporter-b", "reporter-b"}
	for i, rep := range reporters {
		b := testBucket(peers[i], 443+i, uint64(i+1))
		b.Reporter = rep
		err := s.UpsertBucket(ctx, b)
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
	n, err := s.CountBuckets(ctx)
	if err != nil {
		t.Fatalf("count buckets: %v", err)
	}
	if n != 3 {
		t.Errorf("count = %d, want 3", n)
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
		{"endpoints not ordered", func(b *Bucket) { b.Key.A, b.Key.B = b.Key.B, b.Key.A }, ErrInvalidBucket},
		{"loopback endpoint", func(b *Bucket) { b.Key.A = netip.MustParseAddr("127.0.0.1") }, ErrInvalidBucket},
		{"unknown tier", func(b *Bucket) { b.Key.Tier = "bogus" }, ErrInvalidBucket},
		{"empty reporter", func(b *Bucket) { b.Reporter = "" }, ErrInvalidBucket},
		{"reporter too long", func(b *Bucket) { b.Reporter = strings.Repeat("r", flowagg.MaxHostIDLen+1) }, ErrInvalidBucket},
		{"bytes out of range", func(b *Bucket) { b.BytesAB = uint64(math.MaxInt64) + 1 }, ErrInvalidBucket},
		{"connections out of range", func(b *Bucket) { b.Connections = uint64(math.MaxInt64) + 1 }, ErrInvalidBucket},
		{"hour before retention", func(b *Bucket) { b.Hour = testNow.Add(-22 * 24 * time.Hour) }, ErrOutOfRange},
		{"hour in the future", func(b *Bucket) { b.Hour = testNow.Add(2 * time.Hour) }, ErrOutOfRange},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := testBucket("10.0.0.2", 443, 10)
			tc.mut(&b)
			err := s.UpsertBucket(ctx, b)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestPrune(t *testing.T) {
	s, db, _ := newTestStore(t)
	ctx := context.Background()

	kept := testBucket("10.0.0.3", 443, 1)
	kept.Hour = testNow.Add(-20 * 24 * time.Hour)
	if err := s.UpsertBucket(ctx, kept); err != nil {
		t.Fatalf("upsert kept bucket: %v", err)
	}
	if err := s.UpsertBucket(ctx, testBucket("10.0.0.4", 443, 1)); err != nil {
		t.Fatalf("upsert current bucket: %v", err)
	}
	if err := s.UpsertEndpoint(ctx, testEndpoint("10.0.0.8", "00:11:22:33:44:56", "reporter-a")); err != nil {
		t.Fatalf("upsert kept endpoint: %v", err)
	}

	// Expired rows are inserted directly after the first write (whose
	// automatic prune has already run), bypassing the write-time
	// retention check, so the explicit Prune can observe them.
	oldHour := hourOf(testNow) - 22*24
	if _, err := db.ExecContext(ctx, `
		INSERT INTO flow_buckets (hour, a, b, proto, server_port, server_side, tier,
		                          bytes_ab, bytes_ba, connections, lower_bound, reporter, server_reported)
		VALUES (?, ?, ?, ?, ?, ?, ?, 0, 0, 0, 0, ?, 0)`,
		oldHour, "10.0.0.1", "10.0.0.2", 6, 443, 2, "socket", "reporter-a"); err != nil {
		t.Fatalf("insert old bucket: %v", err)
	}
	oldSeen := testNow.Add(-22 * 24 * time.Hour)
	if _, err := db.ExecContext(ctx, `
		INSERT INTO net_endpoints (id, mac, vlan, hostname, first_seen, last_seen, tier, reporter, ipam_asset_id, host_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"mac:00:11:22:33:44:55", "00:11:22:33:44:55", 10, "", oldSeen.Unix(), oldSeen.Unix(), "socket", "reporter-a", "", ""); err != nil {
		t.Fatalf("insert old endpoint: %v", err)
	}

	buckets, endpoints, err := s.Prune(ctx)
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if buckets != 1 || endpoints != 1 {
		t.Errorf("pruned = %d buckets, %d endpoints, want 1, 1", buckets, endpoints)
	}
	n, err := s.CountBuckets(ctx)
	if err != nil {
		t.Fatalf("count buckets: %v", err)
	}
	if n != 2 {
		t.Errorf("buckets left = %d, want 2", n)
	}
	if _, found, err := s.LookupEndpoint(ctx, "00:11:22:33:44:55", netip.Addr{}); err != nil || found {
		t.Errorf("old endpoint still present: found=%v err=%v", found, err)
	}
	if _, found, err := s.LookupEndpoint(ctx, "00:11:22:33:44:56", netip.Addr{}); err != nil || !found {
		t.Errorf("kept endpoint missing: found=%v err=%v", found, err)
	}
	// Prune is idempotent.
	if b, e, err := s.Prune(ctx); err != nil || b != 0 || e != 0 {
		t.Errorf("second prune = %d, %d, %v, want 0, 0, nil", b, e, err)
	}
}

func TestRetentionConfigurableLowerOnly(t *testing.T) {
	_, db, now := newTestStore(t)
	ctx := context.Background()
	nowFn := func() time.Time { return *now }

	if _, err := NewWithNowAndRetention(db, nowFn, 30*24*time.Hour); err == nil {
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
	if err := s7.UpsertBucket(ctx, old); !errors.Is(err, ErrOutOfRange) {
		t.Errorf("upsert 10d old with 7d retention: err = %v, want ErrOutOfRange", err)
	}
	kept := testBucket("10.0.0.3", 443, 1)
	kept.Hour = testNow.Add(-5 * 24 * time.Hour)
	if err := s7.UpsertBucket(ctx, kept); err != nil {
		t.Fatalf("upsert 5d old with 7d retention: %v", err)
	}
	oldE := testEndpoint("10.0.0.9", "00:11:22:33:44:55", "reporter-a")
	oldE.LastSeen = testNow.Add(-10 * 24 * time.Hour)
	oldE.FirstSeen = oldE.LastSeen
	if err := s7.UpsertEndpoint(ctx, oldE); !errors.Is(err, ErrOutOfRange) {
		t.Errorf("upsert 10d old endpoint: err = %v, want ErrOutOfRange", err)
	}
}

func TestAutoPruneHourly(t *testing.T) {
	s, db, now := newTestStore(t)
	ctx := context.Background()

	if err := s.UpsertBucket(ctx, testBucket("10.0.0.2", 443, 1)); err != nil {
		t.Fatalf("upsert 1: %v", err)
	}
	// An expired row inserted directly (bypassing validation) after the
	// first write's automatic prune.
	oldHour := hourOf(*now) - 22*24
	if _, err := db.ExecContext(ctx, `
		INSERT INTO flow_buckets (hour, a, b, proto, server_port, server_side, tier,
		                          bytes_ab, bytes_ba, connections, lower_bound, reporter, server_reported)
		VALUES (?, ?, ?, ?, ?, ?, ?, 0, 0, 0, 0, ?, 0)`,
		oldHour, "10.0.0.1", "10.0.0.9", 6, 443, 2, "socket", "reporter-a"); err != nil {
		t.Fatalf("insert old row: %v", err)
	}
	// A second write in the same clock hour must not re-prune.
	if err := s.UpsertBucket(ctx, testBucket("10.0.0.3", 443, 1)); err != nil {
		t.Fatalf("upsert 2: %v", err)
	}
	n, err := s.CountBuckets(ctx)
	if err != nil {
		t.Fatalf("count buckets: %v", err)
	}
	if n != 3 {
		t.Fatalf("buckets = %d, want 3 (no prune within the same hour)", n)
	}
	// The next clock hour prunes on write.
	*now = now.Add(2 * time.Hour)
	b := testBucket("10.0.0.4", 443, 1)
	b.Hour = *now
	if err := s.UpsertBucket(ctx, b); err != nil {
		t.Fatalf("upsert 3: %v", err)
	}
	n, err = s.CountBuckets(ctx)
	if err != nil {
		t.Fatalf("count buckets: %v", err)
	}
	if n != 3 {
		t.Errorf("buckets = %d, want 3 (expired row pruned in the new hour)", n)
	}
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
		{"10.0.0.3", 80, 500},
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
		if err := s.UpsertBucket(ctx, b); err != nil {
			t.Fatalf("upsert %s: %v", f.peer, err)
		}
	}
	// A huge flow outside the window must not appear.
	out := testBucket("10.0.0.8", 7000, 999999)
	out.Hour = time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)
	if err := s.UpsertBucket(ctx, out); err != nil {
		t.Fatalf("upsert out-of-window: %v", err)
	}

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
		{"10.0.0.3", 80, 500}, // tie with 10.0.0.4, ordered by key
		{"10.0.0.4", 53, 500},
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

	// A node without flows gets an empty result.
	totals, err = s.TopN(ctx, netip.MustParseAddr("10.0.0.9"), testWindow, 5)
	if err != nil {
		t.Fatalf("top n empty node: %v", err)
	}
	if len(totals) != 0 {
		t.Errorf("totals = %d, want 0", len(totals))
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
	if err := s.UpsertBucket(ctx, client); err != nil {
		t.Fatalf("upsert client: %v", err)
	}
	server := client
	server.Reporter = "server-b"
	server.ServerReported = true
	server.BytesAB = 42
	if err := s.UpsertBucket(ctx, server); err != nil {
		t.Fatalf("upsert server: %v", err)
	}

	totals, err := s.TopN(ctx, netip.MustParseAddr("10.0.0.1"), testWindow, 5)
	if err != nil {
		t.Fatalf("top n: %v", err)
	}
	if len(totals) != 1 {
		t.Fatalf("totals = %d, want 1", len(totals))
	}
	if totals[0].BytesAB != 42 || !totals[0].ServerReported || !totals[0].Confirmed {
		t.Errorf("total = %+v, want bytes 42, server reported, confirmed", totals[0])
	}

	// Without the server end's report the client row is used.
	if _, err := db.ExecContext(ctx, `DELETE FROM flow_buckets WHERE reporter = ?`, "server-b"); err != nil {
		t.Fatalf("delete server row: %v", err)
	}
	totals, err = s.TopN(ctx, netip.MustParseAddr("10.0.0.1"), testWindow, 5)
	if err != nil {
		t.Fatalf("top n: %v", err)
	}
	if len(totals) != 1 {
		t.Fatalf("totals = %d, want 1", len(totals))
	}
	if totals[0].BytesAB != 100 || totals[0].ServerReported || totals[0].Confirmed {
		t.Errorf("total = %+v, want bytes 100, client reported, not confirmed", totals[0])
	}

	// Two client reporters: the lexicographically smallest wins.
	zeta := client
	zeta.Reporter = "zeta"
	zeta.BytesAB = 5
	alpha := client
	alpha.Reporter = "alpha"
	alpha.BytesAB = 7
	for _, c := range []Bucket{zeta, alpha} {
		if err := s.UpsertBucket(ctx, c); err != nil {
			t.Fatalf("upsert %s: %v", c.Reporter, err)
		}
	}
	totals, err = s.TopN(ctx, netip.MustParseAddr("10.0.0.1"), testWindow, 5)
	if err != nil {
		t.Fatalf("top n: %v", err)
	}
	if len(totals) != 1 || totals[0].BytesAB != 7 {
		t.Errorf("total = %+v, want bytes 7 (smallest reporter wins)", totals)
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
		if err := s.UpsertBucket(ctx, Bucket{Hour: testNow, Key: key, Reporter: "reporter-a", BytesAB: bytes}); err != nil {
			t.Fatalf("upsert %s-%s: %v", a, b, err)
		}
	}
	add("10.0.0.1", "10.0.0.2", 443, 1000)
	add("10.0.0.1", "10.0.0.3", 80, 900)
	add("10.0.0.2", "10.0.0.3", 8080, 800)
	add("10.0.0.1", "10.0.0.4", 22, 700)
	add("10.0.0.2", "10.0.0.4", 9000, 600)

	nodes := []netip.Addr{netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2")}
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
	if _, err := s.TopN(ctx, netip.MustParseAddr("127.0.0.1"), testWindow, 5); !errors.Is(err, ErrInvalidWindow) {
		t.Errorf("loopback node: err = %v, want ErrInvalidWindow", err)
	}
	if _, err := s.OverviewUnion(ctx, []netip.Addr{netip.MustParseAddr("0.0.0.0")}, testWindow, 5); !errors.Is(err, ErrInvalidWindow) {
		t.Errorf("unspecified node: err = %v, want ErrInvalidWindow", err)
	}
}

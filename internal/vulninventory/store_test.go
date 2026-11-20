// SPDX-License-Identifier: AGPL-3.0-or-later

package vulninventory

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
)

// base is the fixed clock every test reads from; no test uses time.Now.
var base = time.Unix(1_700_000_000, 0).UTC()

func openStore(t *testing.T) (*Store, *sql.DB) {
	t.Helper()
	db, err := serverdb.Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatalf("open server db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	s, err := New(db)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s, db
}

// testRead is a valid read of one host at base+at seconds.
func testRead(host string, complete bool, at int64) Read {
	return Read{
		HostID:      host,
		ExecutionID: "exec-1",
		ReadAt:      base.Add(time.Duration(at) * time.Second),
		Complete:    complete,
		Reason:      "",
		Dropped:     0,
		Ecosystem:   "debian:12",
		Kernel:      Kernel{Release: "6.1.0-18-amd64", State: "mapped", Source: "uname", Version: "#1 SMP"},
		Components: []Component{{
			Source:        "openssl",
			SourceVersion: "3.0.11-1",
			Binaries:      []Binary{{Name: "libssl3", Version: "3.0.11-1", Arch: "amd64"}},
		}},
	}
}

func mustPut(t *testing.T, s *Store, r Read) int64 {
	t.Helper()
	id, err := s.Put(context.Background(), r)
	if err != nil {
		t.Fatalf("Put(%s, complete=%v): %v", r.HostID, r.Complete, err)
	}
	return id
}

func rowCount(t *testing.T, db *sql.DB) int {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM vuln_inventory_reads`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestLatestAndLastCompleteFollowReadTime(t *testing.T) {
	type step struct {
		complete bool
		at       int64
	}
	cases := []struct {
		name         string
		steps        []step
		wantLatest   int // index into steps (1-based id), 0 for ErrNoRead
		wantComplete int
	}{
		{"complete then incomplete", []step{{true, 1}, {false, 2}}, 2, 1},
		{"several complete and incomplete", []step{{true, 1}, {true, 2}, {false, 3}, {false, 4}}, 4, 2},
		{"only incomplete", []step{{false, 1}}, 1, 0},
		{"latest is complete", []step{{false, 1}, {true, 2}}, 2, 2},
		{"newest by read time, not insert order", []step{{true, 5}, {false, 1}}, 1, 1},
		{"same second ordered by insert", []step{{true, 7}, {true, 7}}, 2, 2},
	}
	// One database for all cases (opening one runs every migration); each case
	// uses its own host.
	s, _ := openStore(t)
	for i, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx := context.Background()
			host := fmt.Sprintf("host-%d", i)
			ids := make([]int64, len(c.steps))
			for j, st := range c.steps {
				ids[j] = mustPut(t, s, testRead(host, st.complete, st.at))
			}
			latest, err := s.Latest(ctx, host)
			if err != nil {
				t.Fatalf("Latest: %v", err)
			}
			if latest.ID != ids[c.wantLatest-1] {
				t.Errorf("Latest id = %d, want %d", latest.ID, ids[c.wantLatest-1])
			}
			lc, err := s.LastComplete(ctx, host)
			if c.wantComplete == 0 {
				if !errors.Is(err, ErrNoRead) {
					t.Fatalf("LastComplete err = %v, want ErrNoRead", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("LastComplete: %v", err)
			}
			if lc.ID != ids[c.wantComplete-1] || !lc.Complete {
				t.Errorf("LastComplete id = %d complete=%v, want %d complete", lc.ID, lc.Complete, ids[c.wantComplete-1])
			}
		})
	}
}

func TestLatestWithoutReadsReturnsErrNoRead(t *testing.T) {
	s, _ := openStore(t)
	ctx := context.Background()
	if _, err := s.Latest(ctx, "nobody"); !errors.Is(err, ErrNoRead) {
		t.Errorf("Latest err = %v, want ErrNoRead", err)
	}
	if _, err := s.LastComplete(ctx, "nobody"); !errors.Is(err, ErrNoRead) {
		t.Errorf("LastComplete err = %v, want ErrNoRead", err)
	}
	if _, err := s.Get(ctx, 42); !errors.Is(err, ErrNoRead) {
		t.Errorf("Get err = %v, want ErrNoRead", err)
	}
}

func TestIdenticalReadIsANewImmutableRow(t *testing.T) {
	s, db := openStore(t)
	ctx := context.Background()
	r := testRead("host-a", true, 1)
	first := mustPut(t, s, r)
	second := mustPut(t, s, r)
	if first == second {
		t.Fatalf("identical reads share id %d", first)
	}
	if rowCount(t, db) != 2 {
		t.Fatalf("row count = %d, want 2", rowCount(t, db))
	}
	// Mutating the caller's slice after Put must not change the stored read.
	r.Components[0].Binaries[0].Name = "changed"
	got, err := s.Get(ctx, first)
	if err != nil {
		t.Fatal(err)
	}
	if got.Components[0].Binaries[0].Name != "libssl3" {
		t.Errorf("stored read changed after caller mutation: %+v", got.Components)
	}
}

func TestPutAndGetRoundTripIsCanonical(t *testing.T) {
	s, _ := openStore(t)
	ctx := context.Background()
	r := Read{
		HostID:      "host-a",
		ExecutionID: "exec-9",
		ReadAt:      base,
		Complete:    false,
		Reason:      "truncated",
		Dropped:     3,
		Ecosystem:   "ubuntu:24.04",
		Kernel:      Kernel{Release: "6.8.0", State: "unmapped", Source: "", Version: ""},
		Components: []Component{
			{Source: "zlib", SourceVersion: "1:1.3", Binaries: []Binary{{Name: "zlib1g", Version: "1:1.3", Arch: "amd64"}}},
			{Source: "bash", SourceVersion: "5.2-1", Binaries: []Binary{
				{Name: "bash", Version: "5.2-1", Arch: "amd64"},
				{Name: "bash-doc", Version: "5.2-1", Arch: ""},
			}},
			{Source: "empty", SourceVersion: "1", Binaries: nil},
		},
	}
	id := mustPut(t, s, r)
	got, err := s.Get(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	want := Read{
		ID:          id,
		HostID:      "host-a",
		ExecutionID: "exec-9",
		ReadAt:      base,
		Complete:    false,
		Reason:      "truncated",
		Dropped:     3,
		Ecosystem:   "ubuntu:24.04",
		Kernel:      Kernel{Release: "6.8.0", State: "unmapped"},
		Components: []Component{
			{Source: "bash", SourceVersion: "5.2-1", Binaries: []Binary{
				{Name: "bash", Version: "5.2-1", Arch: "amd64"},
				{Name: "bash-doc", Version: "5.2-1", Arch: ""},
			}},
			{Source: "empty", SourceVersion: "1", Binaries: []Binary{}},
			{Source: "zlib", SourceVersion: "1:1.3", Binaries: []Binary{{Name: "zlib1g", Version: "1:1.3", Arch: "amd64"}}},
		},
	}
	if got.ID != want.ID || got.HostID != want.HostID || got.ExecutionID != want.ExecutionID ||
		!got.ReadAt.Equal(want.ReadAt) || got.Complete != want.Complete || got.Reason != want.Reason ||
		got.Dropped != want.Dropped || got.Ecosystem != want.Ecosystem || got.Kernel != want.Kernel {
		t.Fatalf("header = %+v, want %+v", got, want)
	}
	if len(got.Components) != len(want.Components) {
		t.Fatalf("components = %+v, want %+v", got.Components, want.Components)
	}
	for i := range want.Components {
		g, w := got.Components[i], want.Components[i]
		if g.Source != w.Source || g.SourceVersion != w.SourceVersion || len(g.Binaries) != len(w.Binaries) {
			t.Fatalf("component %d = %+v, want %+v", i, g, w)
		}
		for j := range w.Binaries {
			if g.Binaries[j] != w.Binaries[j] {
				t.Errorf("component %d binary %d = %+v, want %+v", i, j, g.Binaries[j], w.Binaries[j])
			}
		}
	}
}

func TestBodyIsSameForReordersOfTheSameComponents(t *testing.T) {
	s, db := openStore(t)
	a := testRead("host-a", true, 1)
	a.Components = []Component{
		{Source: "bash", SourceVersion: "5", Binaries: []Binary{{Name: "b", Version: "1", Arch: "amd64"}, {Name: "a", Version: "1", Arch: "amd64"}}},
		{Source: "zlib", SourceVersion: "1", Binaries: []Binary{{Name: "z", Version: "1", Arch: ""}}},
	}
	b := testRead("host-a", true, 2)
	b.Components = []Component{
		{Source: "zlib", SourceVersion: "1", Binaries: []Binary{{Name: "z", Version: "1", Arch: ""}}},
		{Source: "bash", SourceVersion: "5", Binaries: []Binary{{Name: "a", Version: "1", Arch: "amd64"}, {Name: "b", Version: "1", Arch: "amd64"}}},
	}
	ida := mustPut(t, s, a)
	idb := mustPut(t, s, b)
	var bodyA, bodyB []byte
	if err := db.QueryRow(`SELECT body FROM vuln_inventory_reads WHERE id = ?`, ida).Scan(&bodyA); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT body FROM vuln_inventory_reads WHERE id = ?`, idb).Scan(&bodyB); err != nil {
		t.Fatal(err)
	}
	if string(bodyA) != string(bodyB) {
		t.Errorf("canonical bodies differ:\n%s\n%s", bodyA, bodyB)
	}
	want := `[{"source":"bash","source_version":"5","binaries":[{"name":"a","version":"1","arch":"amd64"},{"name":"b","version":"1","arch":"amd64"}]},{"source":"zlib","source_version":"1","binaries":[{"name":"z","version":"1","arch":""}]}]`
	if string(bodyA) != want {
		t.Errorf("body = %s\nwant %s", bodyA, want)
	}
}

// fill returns n components with one binary each, all fields at maximum length.
func maximalComponents(n int) []Component {
	comps := make([]Component, n)
	for i := range comps {
		comps[i] = Component{
			Source:        strings.Repeat("s", maxNameBytes),
			SourceVersion: strings.Repeat("v", maxVersionBytes),
			Binaries: []Binary{{
				Name:    strings.Repeat("n", maxNameBytes),
				Version: strings.Repeat("v", maxVersionBytes),
				Arch:    strings.Repeat("a", maxArchBytes),
			}},
		}
	}
	return comps
}

func TestMaximalReadIsAcceptedAndFitsBodyLimit(t *testing.T) {
	s, db := openStore(t)
	r := testRead("host-max", true, 1)
	r.Components = maximalComponents(MaxBinaries)
	id := mustPut(t, s, r)
	var n int
	if err := db.QueryRow(`SELECT length(body) FROM vuln_inventory_reads WHERE id = ?`, id).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n > MaxBodyBytes {
		t.Fatalf("maximal body %d bytes exceeds MaxBodyBytes %d", n, MaxBodyBytes)
	}
	if n < MaxBodyBytes/2 {
		t.Fatalf("maximal body %d bytes is far below MaxBodyBytes %d; the bound is not derived from the field lengths", n, MaxBodyBytes)
	}
}

func TestPutRejectsOverLimitInput(t *testing.T) {
	tooManyBinaries := func() []Component {
		c := maximalComponents(1)
		c[0].Binaries = make([]Binary, MaxBinaries+1)
		for i := range c[0].Binaries {
			c[0].Binaries[i] = Binary{Name: "x", Version: "1"}
		}
		return c
	}
	splitTooMany := func() []Component {
		c := maximalComponents(2)
		c[0].Binaries = make([]Binary, MaxBinaries/2)
		c[1].Binaries = make([]Binary, MaxBinaries/2+1)
		for i := range c[0].Binaries {
			c[0].Binaries[i] = Binary{Name: "x", Version: "1"}
		}
		for i := range c[1].Binaries {
			c[1].Binaries[i] = Binary{Name: "x", Version: "1"}
		}
		return c
	}
	tooManyComponents := func() []Component {
		c := make([]Component, MaxComponents+1)
		for i := range c {
			c[i] = Component{Source: "s", SourceVersion: "1"}
		}
		return c
	}
	cases := []struct {
		name    string
		mutate  func(*Read)
		wantErr error
	}{
		{"20001 binaries in one component", func(r *Read) { r.Components = tooManyBinaries() }, ErrLimit},
		{"20001 binaries over two components", func(r *Read) { r.Components = splitTooMany() }, ErrLimit},
		{"20001 components", func(r *Read) { r.Components = tooManyComponents() }, ErrLimit},
		{"reason 129 bytes", func(r *Read) { r.Reason = strings.Repeat("r", MaxReasonBytes+1) }, ErrInvalidRead},
		{"reason with multibyte runes over limit", func(r *Read) { r.Reason = strings.Repeat("ä", MaxReasonBytes/2+1) }, ErrInvalidRead},
		{"invalid UTF-8 in host", func(r *Read) { r.HostID = "h\xff" }, ErrInvalidRead},
		{"invalid UTF-8 in binary name", func(r *Read) { r.Components[0].Binaries[0].Name = "lib\xc3" }, ErrInvalidRead},
		{"invalid UTF-8 in reason", func(r *Read) { r.Reason = "\xfe" }, ErrInvalidRead},
		{"invalid UTF-8 in kernel version", func(r *Read) { r.Kernel.Version = "\xed\xa0\x80" }, ErrInvalidRead},
		{"invalid UTF-8 in source", func(r *Read) { r.Components[0].Source = "x\x80" }, ErrInvalidRead},
		{"kernel version 257 bytes", func(r *Read) { r.Kernel.Version = strings.Repeat("k", maxKernelVersionBytes+1) }, ErrInvalidRead},
		{"ecosystem 65 bytes", func(r *Read) { r.Ecosystem = strings.Repeat("e", maxEcosystemBytes+1) }, ErrInvalidRead},
		{"binary name 129 bytes", func(r *Read) { r.Components[0].Binaries[0].Name = strings.Repeat("n", maxNameBytes+1) }, ErrInvalidRead},
		{"binary name empty", func(r *Read) { r.Components[0].Binaries[0].Name = "" }, ErrInvalidRead},
		{"binary arch 33 bytes", func(r *Read) { r.Components[0].Binaries[0].Arch = strings.Repeat("a", maxArchBytes+1) }, ErrInvalidRead},
		{"source version empty", func(r *Read) { r.Components[0].SourceVersion = "" }, ErrInvalidRead},
		{"zero read time", func(r *Read) { r.ReadAt = time.Time{} }, ErrInvalidRead},
		{"negative dropped", func(r *Read) { r.Dropped = -1 }, ErrInvalidRead},
		{"empty host", func(r *Read) { r.HostID = "" }, ErrInvalidRead},
		{"empty execution id", func(r *Read) { r.ExecutionID = "" }, ErrInvalidRead},
		{"host id 129 bytes", func(r *Read) { r.HostID = strings.Repeat("h", maxHostIDBytes+1) }, ErrInvalidRead},
	}
	s, db := openStore(t)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			before := rowCount(t, db)
			r := testRead("host-a", true, 1)
			c.mutate(&r)
			_, err := s.Put(context.Background(), r)
			if !errors.Is(err, c.wantErr) {
				t.Fatalf("Put err = %v, want %v", err, c.wantErr)
			}
			if n := rowCount(t, db); n != before {
				t.Errorf("rejected read left %d new rows", n-before)
			}
		})
	}
}

func TestPutAcceptsBoundaryValues(t *testing.T) {
	s, _ := openStore(t)
	r := testRead(strings.Repeat("h", maxHostIDBytes), false, 1)
	r.Reason = strings.Repeat("r", MaxReasonBytes)
	r.Ecosystem = strings.Repeat("e", maxEcosystemBytes)
	r.Kernel.Version = strings.Repeat("k", maxKernelVersionBytes)
	r.Components[0].Binaries[0].Arch = ""
	r.Components[0].Binaries[0].Name = strings.Repeat("n", maxNameBytes)
	if _, err := s.Put(context.Background(), r); err != nil {
		t.Fatalf("boundary read refused: %v", err)
	}
}

func TestBodySizeCheckRejectsAboveLimit(t *testing.T) {
	if err := checkBodySize(MaxBodyBytes); err != nil {
		t.Errorf("body at limit refused: %v", err)
	}
	if err := checkBodySize(MaxBodyBytes + 1); !errors.Is(err, ErrLimit) {
		t.Errorf("body over limit err = %v, want ErrLimit", err)
	}
}

func TestLatestAllReturnsOneHeaderPerHost(t *testing.T) {
	s, _ := openStore(t)
	ctx := context.Background()
	mustPut(t, s, testRead("host-a", true, 1))
	wantA := mustPut(t, s, testRead("host-a", false, 2))
	mustPut(t, s, testRead("host-b", false, 1))
	wantB := mustPut(t, s, testRead("host-b", true, 3))
	mustPut(t, s, testRead("host-b", true, 2))
	got, err := s.LatestAll(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("LatestAll returned %d reads, want 2", len(got))
	}
	ids := map[string]int64{got[0].HostID: got[0].ID, got[1].HostID: got[1].ID}
	if ids["host-a"] != wantA || ids["host-b"] != wantB {
		t.Errorf("LatestAll ids = %v, want host-a %d host-b %d", ids, wantA, wantB)
	}
	for _, r := range got {
		if r.Components != nil {
			t.Errorf("LatestAll read %d carries components; headers only", r.ID)
		}
	}
}

func TestHostsDoNotAffectEachOther(t *testing.T) {
	s, _ := openStore(t)
	ctx := context.Background()
	a1 := mustPut(t, s, testRead("host-a", true, 1))
	mustPut(t, s, testRead("host-b", false, 5))
	mustPut(t, s, testRead("host-b", false, 6))
	lc, err := s.LastComplete(ctx, "host-a")
	if err != nil || lc.ID != a1 {
		t.Fatalf("LastComplete(host-a) = %d, %v; want %d", lc.ID, err, a1)
	}
	if _, err := s.LastComplete(ctx, "host-b"); !errors.Is(err, ErrNoRead) {
		t.Errorf("LastComplete(host-b) err = %v, want ErrNoRead", err)
	}
}

func TestNewRequiresDatabase(t *testing.T) {
	if _, err := New(nil); err == nil {
		t.Error("New(nil) accepted")
	}
}

// linkSnapshot creates snapshot snap (generation gen) pointing at reads.
func linkSnapshot(t *testing.T, db *sql.DB, snap string, gen int, reads ...int64) {
	t.Helper()
	if _, err := db.Exec(`INSERT INTO vuln_inventory_snapshots (id, generation, taken_at) VALUES (?, ?, 1)`, snap, gen); err != nil {
		t.Fatal(err)
	}
	for _, r := range reads {
		if _, err := db.Exec(`INSERT INTO vuln_inventory_snapshot_reads (snapshot_id, read_id) VALUES (?, ?)`, snap, r); err != nil {
			t.Fatal(err)
		}
	}
}

// remainingReads returns the ids of the host's reads still stored, in id order.
func remainingReads(t *testing.T, db *sql.DB, host string) []int64 {
	t.Helper()
	rows, err := db.Query(`SELECT id FROM vuln_inventory_reads WHERE host_id = ? ORDER BY id`, host)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return ids
}

func sameIDs(a, b []int64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestPruneKeepsExactlyTheThreeClasses(t *testing.T) {
	type step struct {
		complete bool
		at       int64
	}
	cases := []struct {
		name     string
		steps    []step
		snapshot []int // 1-based indexes of reads a snapshot points at
		keep     []int // 1-based indexes that must remain
	}{
		{"latest incomplete, last complete kept, middle dropped",
			[]step{{true, 1}, {false, 2}, {false, 3}, {false, 4}}, nil, []int{1, 4}},
		{"snapshot read kept between classes",
			[]step{{true, 1}, {false, 2}, {true, 3}, {false, 4}}, []int{2}, []int{2, 3, 4}},
		{"latest complete is both classes",
			[]step{{false, 1}, {true, 2}}, nil, []int{2}},
		{"only one read",
			[]step{{false, 1}}, nil, []int{1}},
		{"older complete reads dropped",
			[]step{{true, 1}, {true, 2}, {true, 3}}, nil, []int{3}},
		{"snapshot protects incomplete reads",
			[]step{{true, 1}, {false, 2}, {false, 3}, {false, 4}}, []int{2, 3}, []int{1, 2, 3, 4}},
	}
	// One database for all cases; each case has its own host and snapshot.
	// keepAll holds every host so earlier cases are never pruned again.
	s, db := openStore(t)
	keepAll := map[string]bool{}
	for i, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			host := fmt.Sprintf("host-%d", i)
			keepAll[host] = true
			ids := make([]int64, len(c.steps))
			for j, st := range c.steps {
				ids[j] = mustPut(t, s, testRead(host, st.complete, st.at))
			}
			if len(c.snapshot) > 0 {
				var reads []int64
				for _, j := range c.snapshot {
					reads = append(reads, ids[j-1])
				}
				linkSnapshot(t, db, fmt.Sprintf("snap-%d", i), i+1, reads...)
			}
			var want []int64
			for _, j := range c.keep {
				want = append(want, ids[j-1])
			}
			deleted, err := s.Prune(context.Background(), keepAll)
			if err != nil {
				t.Fatalf("Prune: %v", err)
			}
			if got := remainingReads(t, db, host); !sameIDs(got, want) {
				t.Errorf("kept %v, want %v", got, want)
			}
			if deleted != len(ids)-len(want) {
				t.Errorf("deleted = %d, want %d", deleted, len(ids)-len(want))
			}
		})
	}
}

func TestPruneDropsSnapshotReadOnlyAfterSnapshotEnds(t *testing.T) {
	s, db := openStore(t)
	ctx := context.Background()
	r1 := mustPut(t, s, testRead("host-a", true, 1))
	r2 := mustPut(t, s, testRead("host-a", false, 2))
	r3 := mustPut(t, s, testRead("host-a", false, 3))
	linkSnapshot(t, db, "snap-1", 1, r2)
	keep := map[string]bool{"host-a": true}
	if n, err := s.Prune(ctx, keep); err != nil || n != 0 {
		t.Fatalf("Prune with snapshot = %d, %v; want 0, nil", n, err)
	}
	if _, err := db.Exec(`DELETE FROM vuln_inventory_snapshots WHERE id = 'snap-1'`); err != nil {
		t.Fatal(err)
	}
	n, err := s.Prune(ctx, keep)
	if err != nil || n != 1 {
		t.Fatalf("Prune after snapshot ended = %d, %v; want 1, nil", n, err)
	}
	if got := remainingReads(t, db, "host-a"); !sameIDs(got, []int64{r1, r3}) {
		t.Errorf("kept %v, want latest and last complete", got)
	}
}

func TestPruneRemovedHostKeepsOnlySnapshotReads(t *testing.T) {
	cases := []struct {
		name     string
		snapshot bool
		keep     map[string]bool
		wantLeft int
	}{
		{"removed host, snapshot points at its complete read", true, map[string]bool{}, 1},
		{"removed host, no snapshot: everything goes", false, map[string]bool{}, 0},
		{"host mapped to false counts as removed", true, map[string]bool{"host-gone": false}, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, db := openStore(t)
			r1 := mustPut(t, s, testRead("host-gone", true, 1))
			mustPut(t, s, testRead("host-gone", false, 2))
			mustPut(t, s, testRead("host-gone", true, 3))
			if c.snapshot {
				linkSnapshot(t, db, "snap-1", 1, r1)
			}
			deleted, err := s.Prune(context.Background(), c.keep)
			if err != nil {
				t.Fatalf("Prune: %v", err)
			}
			got := remainingReads(t, db, "host-gone")
			if len(got) != c.wantLeft || deleted != 3-c.wantLeft {
				t.Errorf("left %v deleted %d; want %d left, %d deleted", got, deleted, c.wantLeft, 3-c.wantLeft)
			}
			if c.snapshot && (len(got) != 1 || got[0] != r1) {
				t.Errorf("snapshot read %d not kept: left %v", r1, got)
			}
		})
	}
}

func TestPruneHostsDoNotAffectEachOther(t *testing.T) {
	s, db := openStore(t)
	ctx := context.Background()
	a1 := mustPut(t, s, testRead("host-a", true, 1))
	a2 := mustPut(t, s, testRead("host-a", false, 2))
	mustPut(t, s, testRead("host-b", false, 1)) // b1: neither latest nor last complete
	b2 := mustPut(t, s, testRead("host-b", true, 2))
	b3 := mustPut(t, s, testRead("host-b", false, 3))
	mustPut(t, s, testRead("host-c", false, 1)) // c1: no complete read, not latest
	c2 := mustPut(t, s, testRead("host-c", false, 2))

	// host-b loses its place in the keep set only in the second call.
	n, err := s.Prune(ctx, map[string]bool{"host-a": true, "host-b": true, "host-c": true})
	if err != nil {
		t.Fatal(err)
	}
	// host-b: b1 is neither latest nor last complete; host-c: c1 is neither.
	if n != 2 {
		t.Errorf("first prune deleted %d, want 2", n)
	}
	if got := remainingReads(t, db, "host-a"); !sameIDs(got, []int64{a1, a2}) {
		t.Errorf("host-a = %v, want %v", got, []int64{a1, a2})
	}
	if got := remainingReads(t, db, "host-b"); !sameIDs(got, []int64{b2, b3}) {
		t.Errorf("host-b = %v, want %v", got, []int64{b2, b3})
	}
	if got := remainingReads(t, db, "host-c"); !sameIDs(got, []int64{c2}) {
		t.Errorf("host-c = %v, want %v", got, []int64{c2})
	}

	n, err = s.Prune(ctx, map[string]bool{"host-a": true})
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Errorf("second prune deleted %d, want 3 (b2, b3 and c2 of the removed hosts)", n)
	}
	if got := remainingReads(t, db, "host-a"); !sameIDs(got, []int64{a1, a2}) {
		t.Errorf("host-a after second prune = %v, want %v", got, []int64{a1, a2})
	}
	if got := remainingReads(t, db, "host-b"); len(got) != 0 {
		t.Errorf("removed host-b still has %v", got)
	}
}

func TestPruneEmptyStoreDeletesNothing(t *testing.T) {
	s, _ := openStore(t)
	n, err := s.Prune(context.Background(), nil)
	if err != nil || n != 0 {
		t.Errorf("Prune on empty store = %d, %v; want 0, nil", n, err)
	}
}

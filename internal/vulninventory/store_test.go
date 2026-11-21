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
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
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

func TestIdenticalReadIsANewRow(t *testing.T) {
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

// TestStoredReadCannotBeUpdated checks the database trigger: an UPDATE of any
// column of a stored read fails and leaves the row as it was.
func TestStoredReadCannotBeUpdated(t *testing.T) {
	cases := []struct {
		name  string
		query string
	}{
		{"reason", `UPDATE vuln_inventory_reads SET reason = 'changed' WHERE id = ?`},
		{"complete", `UPDATE vuln_inventory_reads SET complete = 1 - complete WHERE id = ?`},
		{"read time", `UPDATE vuln_inventory_reads SET read_at = read_at + 1 WHERE id = ?`},
		{"body", `UPDATE vuln_inventory_reads SET body = x'5b5d' WHERE id = ?`},
		{"all rows", `UPDATE vuln_inventory_reads SET dropped = 1`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, db := openStore(t)
			ctx := context.Background()
			id := mustPut(t, s, testRead("host-a", true, 1))
			before, err := s.Get(ctx, id)
			if err != nil {
				t.Fatal(err)
			}
			var args []any
			if strings.Contains(c.query, "?") {
				args = append(args, id)
			}
			if _, err := db.Exec(c.query, args...); err == nil {
				t.Fatal("UPDATE of a stored read succeeded; reads must be immutable")
			}
			after, err := s.Get(ctx, id)
			if err != nil {
				t.Fatal(err)
			}
			if after.Reason != before.Reason || after.Complete != before.Complete ||
				!after.ReadAt.Equal(before.ReadAt) || after.Dropped != before.Dropped ||
				len(after.Components) != len(before.Components) {
				t.Errorf("row changed after rejected UPDATE: %+v, was %+v", after, before)
			}
		})
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
		{Source: "bash", SourceVersion: "5", Binaries: []Binary{{Name: "bb", Version: "1", Arch: "amd64"}, {Name: "aa", Version: "1", Arch: "amd64"}}},
		{Source: "zlib", SourceVersion: "1", Binaries: []Binary{{Name: "zz", Version: "1", Arch: ""}}},
	}
	b := testRead("host-a", true, 2)
	b.Components = []Component{
		{Source: "zlib", SourceVersion: "1", Binaries: []Binary{{Name: "zz", Version: "1", Arch: ""}}},
		{Source: "bash", SourceVersion: "5", Binaries: []Binary{{Name: "aa", Version: "1", Arch: "amd64"}, {Name: "bb", Version: "1", Arch: "amd64"}}},
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
	want := `[{"source":"bash","source_version":"5","binaries":[{"name":"aa","version":"1","arch":"amd64"},{"name":"bb","version":"1","arch":"amd64"}]},{"source":"zlib","source_version":"1","binaries":[{"name":"zz","version":"1","arch":""}]}]`
	if string(bodyA) != want {
		t.Errorf("body = %s\nwant %s", bodyA, want)
	}
}

func TestPutRejectsDuplicateComponentsAndBinaries(t *testing.T) {
	cases := []struct {
		name    string
		comps   []Component
		wantErr error
	}{
		{"same source and version twice, different binaries", []Component{
			{Source: "bash", SourceVersion: "5", Binaries: []Binary{{Name: "aa", Version: "1", Arch: "amd64"}}},
			{Source: "bash", SourceVersion: "5", Binaries: []Binary{{Name: "bb", Version: "1", Arch: "amd64"}}},
		}, ErrInvalidRead},
		{"same binary twice in one component", []Component{
			{Source: "bash", SourceVersion: "5", Binaries: []Binary{
				{Name: "aa", Version: "1", Arch: "amd64"}, {Name: "aa", Version: "1", Arch: "amd64"}}},
		}, ErrInvalidRead},
		{"same source, other version, is a different component", []Component{
			{Source: "bash", SourceVersion: "5", Binaries: []Binary{{Name: "aa", Version: "1", Arch: "amd64"}}},
			{Source: "bash", SourceVersion: "6", Binaries: []Binary{{Name: "aa", Version: "1", Arch: "amd64"}}},
		}, nil},
		{"same binary name with other arch is a different binary", []Component{
			{Source: "bash", SourceVersion: "5", Binaries: []Binary{
				{Name: "aa", Version: "1", Arch: "amd64"}, {Name: "aa", Version: "1", Arch: "i386"}}},
		}, nil},
	}
	s, _ := openStore(t)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := testRead("host-dup", true, 1)
			r.Components = c.comps
			_, err := s.Put(context.Background(), r)
			if c.wantErr == nil {
				if err != nil {
					t.Fatalf("Put: %v", err)
				}
				return
			}
			if !errors.Is(err, c.wantErr) {
				t.Fatalf("Put err = %v, want %v", err, c.wantErr)
			}
		})
	}
}

// maximalComponents returns n components, each with one binary, all fields at
// their maximum length. Source names are distinct (128 digits, the index
// padded), so no two components are duplicates.
func maximalComponents(n int) []Component {
	comps := make([]Component, n)
	for i := range comps {
		comps[i] = Component{
			Source:        fmt.Sprintf("%0128d", i),
			SourceVersion: "v" + strings.Repeat("v", maxVersionBytes-1),
			Binaries: []Binary{{
				Name:    "n" + strings.Repeat("n", maxNameBytes-1),
				Version: "v" + strings.Repeat("v", maxVersionBytes-1),
				Arch:    "a" + strings.Repeat("a", maxArchBytes-1),
			}},
		}
	}
	return comps
}

// uniqueBinaries returns the binaries with indexes from..to-1, each with a
// distinct valid name, so that only the count limit can refuse them.
func uniqueBinaries(from, to int) []Binary {
	bs := make([]Binary, 0, to-from)
	for i := from; i < to; i++ {
		bs = append(bs, Binary{Name: fmt.Sprintf("%0128d", i), Version: "1", Arch: "amd64"})
	}
	return bs
}

// maxBinaryComponentsBytes is the body size of MaxBinaries maximal binaries
// split into k = ceil(MaxBinaries / MaxComponentBinaries) components, as
// encodeBody writes it: 303 bytes per component (its empty binaries list
// included), 322 bytes per binary, a comma between binaries and between
// components, and the "[]" envelope. The commas add up to 323 per binary
// minus one per component, which gives 303k + 323·MaxBinaries + 1.
func maxBinaryComponentsBytes() int {
	k := (MaxBinaries + MaxComponentBinaries - 1) / MaxComponentBinaries
	return 303*k + 323*MaxBinaries + 1
}

// TestPutRejectsMoreBinariesThanTheExportListsPerComponent checks the
// per-component binary limit. The export drops a component with more than
// vulnfinding.MaxBinaries binaries, so Put refuses such a read and stores
// nothing. The limit is per component: a read may hold more binaries in total,
// as long as no single component goes over.
func TestPutRejectsMoreBinariesThanTheExportListsPerComponent(t *testing.T) {
	s, db := openStore(t)
	ctx := context.Background()
	component := func(source string, n int) Component {
		return Component{Source: source, SourceVersion: "3.0.11-1", Binaries: uniqueBinaries(0, n)}
	}
	cases := []struct {
		name    string
		comps   []Component
		wantErr error
	}{
		{"one binary over the limit in one component", []Component{component("openssl", vulnfinding.MaxBinaries+1)}, ErrLimit},
		{"far over the limit in one component", []Component{component("openssl", MaxBinaries)}, ErrLimit},
		{"one over, next to a small component", []Component{component("gnutls", 1), component("openssl", vulnfinding.MaxBinaries+1)}, ErrLimit},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			before := rowCount(t, db)
			r := testRead("host-cb", true, 1)
			r.Components = c.comps
			if _, err := s.Put(ctx, r); !errors.Is(err, c.wantErr) {
				t.Fatalf("Put err = %v, want %v", err, c.wantErr)
			}
			if n := rowCount(t, db); n != before {
				t.Errorf("rejected read left %d new rows", n-before)
			}
		})
	}
	t.Run("exactly the limit in one component is stored", func(t *testing.T) {
		r := testRead("host-cb", true, 2)
		r.Components = []Component{component("openssl", vulnfinding.MaxBinaries)}
		id := mustPut(t, s, r)
		got, err := s.Get(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if n := len(got.Components[0].Binaries); n != vulnfinding.MaxBinaries {
			t.Errorf("read back %d binaries, want %d", n, vulnfinding.MaxBinaries)
		}
	})
	t.Run("two components at the limit make a larger total and are stored", func(t *testing.T) {
		r := testRead("host-cb", true, 3)
		r.Components = []Component{component("openssl", vulnfinding.MaxBinaries), component("gnutls", vulnfinding.MaxBinaries)}
		mustPut(t, s, r)
	})
}

// TestWorstCaseReadsFitEveryLimit stores the largest reads the limits allow
// and checks the exact body size, so the derivation of MaxBodyBytes is tested
// against real bytes, not only against the constant.
func TestWorstCaseReadsFitEveryLimit(t *testing.T) {
	// One component with 1 binary, all fields at maximum:
	// component 303 + binary 322 = 625 bytes; MaxComponents of them joined
	// by commas inside the "[]" envelope.
	const perComponent = 303 + 322

	cases := []struct {
		name      string
		comps     func() []Component
		wantBytes int
	}{
		{
			"MaxComponents components with one maximal binary each",
			func() []Component { return maximalComponents(MaxComponents) },
			MaxComponents*perComponent + (MaxComponents - 1) + 2,
		},
		{
			"MaxBinaries maximal-length binaries in components of MaxComponentBinaries",
			func() []Component {
				// Every component is full (MaxComponentBinaries binaries) but the
				// last, so the read holds MaxBinaries binaries in total.
				var out []Component
				for i := 0; i < MaxBinaries; i += MaxComponentBinaries {
					n := min(MaxComponentBinaries, MaxBinaries-i)
					bs := make([]Binary, n)
					for j := range bs {
						// 128 distinct digits; a digit is a valid first character.
						bs[j] = Binary{Name: fmt.Sprintf("%0128d", i+j), Version: "v" + strings.Repeat("v", maxVersionBytes-1), Arch: strings.Repeat("a", maxArchBytes)}
					}
					out = append(out, Component{
						Source:        fmt.Sprintf("%0128d", len(out)),
						SourceVersion: "v" + strings.Repeat("v", maxVersionBytes-1),
						Binaries:      bs,
					})
				}
				return out
			},
			// k components of 303 bytes each (the empty-list envelope), MaxBinaries
			// binaries of perBinary bytes, commas between binaries (MaxBinaries
			// minus k) and between components (k-1), and the "[]" envelope.
			maxBinaryComponentsBytes(),
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, db := openStore(t)
			r := testRead("host-max", true, 1)
			r.Components = c.comps()
			r.Dropped = MaxDropped
			r.Reason = strings.Repeat("r", MaxReasonBytes)
			r.Ecosystem = strings.Repeat("e", maxEcosystemBytes)
			r.Kernel = Kernel{
				Release: strings.Repeat("k", maxKernelReleaseBytes),
				State:   strings.Repeat("s", maxKernelStateBytes),
				Source:  strings.Repeat("s", maxKernelSourceBytes),
				Version: strings.Repeat("v", maxKernelVersionBytes),
			}
			id := mustPut(t, s, r)
			var n int
			if err := db.QueryRow(`SELECT length(body) FROM vuln_inventory_reads WHERE id = ?`, id).Scan(&n); err != nil {
				t.Fatal(err)
			}
			if n != c.wantBytes {
				t.Errorf("body = %d bytes, want %d", n, c.wantBytes)
			}
			if n > MaxBodyBytes {
				t.Fatalf("body %d bytes exceeds MaxBodyBytes %d", n, MaxBodyBytes)
			}
			got, err := s.Get(context.Background(), id)
			if err != nil {
				t.Fatalf("Get of worst-case read: %v", err)
			}
			if len(got.Components) != len(r.Components) || got.Dropped != MaxDropped {
				t.Errorf("worst-case read read back with %d components, dropped %d", len(got.Components), got.Dropped)
			}
		})
	}
}

func TestMaxBodyBytesIsTheWorstCase(t *testing.T) {
	// The bound must equal what the derivation in store.go says: every
	// component and every binary at its maximum encoded size.
	if MaxBodyBytes != 12540002 {
		t.Errorf("MaxBodyBytes = %d, want 12540002", MaxBodyBytes)
	}
}

func TestPutRejectsOverLimitInput(t *testing.T) {
	tooManyBinaries := func() []Component {
		c := maximalComponents(1)
		c[0].Binaries = uniqueBinaries(0, MaxBinaries+1)
		return c
	}
	splitTooMany := func() []Component {
		c := maximalComponents(2)
		c[0].Binaries = uniqueBinaries(0, MaxBinaries/2)
		c[1].Binaries = uniqueBinaries(MaxBinaries/2, MaxBinaries+1)
		return c
	}
	tooManyComponents := func() []Component {
		c := make([]Component, MaxComponents+1)
		for i := range c {
			c[i] = Component{Source: "ss", SourceVersion: "1"}
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
		{"dropped one over limit", func(r *Read) { r.Dropped = MaxDropped + 1 }, ErrLimit},
		{"reason 129 bytes", func(r *Read) { r.Reason = strings.Repeat("r", MaxReasonBytes+1) }, ErrInvalidRead},
		{"reason with multibyte runes over limit", func(r *Read) { r.Reason = strings.Repeat("ä", MaxReasonBytes/2+1) }, ErrInvalidRead},
		{"invalid UTF-8 in host", func(r *Read) { r.HostID = "h\xff" }, ErrInvalidRead},
		{"invalid UTF-8 in reason", func(r *Read) { r.Reason = "\xfe" }, ErrInvalidRead},
		{"invalid UTF-8 in kernel version", func(r *Read) { r.Kernel.Version = "\xed\xa0\x80" }, ErrInvalidRead},
		{"kernel version 257 bytes", func(r *Read) { r.Kernel.Version = strings.Repeat("k", maxKernelVersionBytes+1) }, ErrInvalidRead},
		{"ecosystem 65 bytes", func(r *Read) { r.Ecosystem = strings.Repeat("e", maxEcosystemBytes+1) }, ErrInvalidRead},
		{"binary name 129 bytes", func(r *Read) { r.Components[0].Binaries[0].Name = "n" + strings.Repeat("n", maxNameBytes) }, ErrInvalidRead},
		{"binary name empty", func(r *Read) { r.Components[0].Binaries[0].Name = "" }, ErrInvalidRead},
		{"binary arch 33 bytes", func(r *Read) { r.Components[0].Binaries[0].Arch = "a" + strings.Repeat("a", maxArchBytes) }, ErrInvalidRead},
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

// TestPutRejectsPackageFieldsOutsideExportPatterns checks that the store takes
// only what the export accepts: lowercase ASCII names, the export's version
// characters, and the export's architecture pattern. Control characters,
// spaces, markup and escapable characters are refused.
func TestPutRejectsPackageFieldsOutsideExportPatterns(t *testing.T) {
	type field struct {
		name  string
		set   func(*Component, string)
		ok    []string
		notOK []string
	}
	fields := []field{
		{
			name:  "source",
			set:   func(c *Component, v string) { c.Source = v },
			ok:    []string{"ab", "libc6", "g++", "a.b-c_d+e", strings.Repeat("a", 128)},
			notOK: []string{"a", "Bash", "a b", "a\nb", "<a>", "a&b", "a\"b", "a\\b", "é", "a/b", strings.Repeat("a", 129)},
		},
		{
			name:  "binary name",
			set:   func(c *Component, v string) { c.Binaries[0].Name = v },
			ok:    []string{"ab", "libssl3", "x11-common", strings.Repeat("a", 128)},
			notOK: []string{"a", "Lib", "a\tb", "a\x7fb", "a b", "a>b", "a,b", strings.Repeat("a", 129)},
		},
		{
			name:  "source version",
			set:   func(c *Component, v string) { c.SourceVersion = v },
			ok:    []string{"1", "1:2.3~rc1+b1", "3.0.11-1_x", strings.Repeat("9", 128)},
			notOK: []string{"-1", "1 2", "1\n2", "1<2", "1&2", "1\"2", strings.Repeat("9", 129)},
		},
		{
			name:  "binary arch",
			set:   func(c *Component, v string) { c.Binaries[0].Arch = v },
			ok:    []string{"", "a", "amd64", "x86-64", strings.Repeat("a", 32)},
			notOK: []string{"AMD64", "x86_64", "a b", "-a", strings.Repeat("a", 33)},
		},
	}
	s, _ := openStore(t)
	for _, f := range fields {
		for _, v := range f.ok {
			t.Run(fmt.Sprintf("%s accepts %q", f.name, shortValue(v)), func(t *testing.T) {
				r := testRead("host-pat", true, 1)
				f.set(&r.Components[0], v)
				if _, err := s.Put(context.Background(), r); err != nil {
					t.Fatalf("Put: %v", err)
				}
			})
		}
		for _, v := range f.notOK {
			t.Run(fmt.Sprintf("%s rejects %q", f.name, shortValue(v)), func(t *testing.T) {
				r := testRead("host-pat", true, 1)
				f.set(&r.Components[0], v)
				if _, err := s.Put(context.Background(), r); !errors.Is(err, ErrInvalidRead) {
					t.Fatalf("Put err = %v, want ErrInvalidRead", err)
				}
			})
		}
	}
}

// shortValue keeps test names readable for long boundary values.
func shortValue(v string) string {
	if len(v) > 12 {
		return fmt.Sprintf("%s...(%d)", v[:12], len(v))
	}
	return v
}

func TestPutAcceptsBoundaryValues(t *testing.T) {
	s, _ := openStore(t)
	r := testRead(strings.Repeat("h", maxHostIDBytes), false, 1)
	r.Reason = strings.Repeat("r", MaxReasonBytes)
	r.Ecosystem = strings.Repeat("e", maxEcosystemBytes)
	r.Kernel.Version = strings.Repeat("k", maxKernelVersionBytes)
	r.Dropped = MaxDropped
	r.Components[0].Binaries[0].Arch = ""
	r.Components[0].Binaries[0].Name = "n" + strings.Repeat("n", maxNameBytes-1)
	if _, err := s.Put(context.Background(), r); err != nil {
		t.Fatalf("boundary read refused: %v", err)
	}
}

// TestPutRefusesReadTimeFarInTheFuture checks the upper bound of ReadAt. A read
// stamped more than MaxReadSkew after the store's clock would stay the newest
// read of its host, and so protected, for as long as the clock stays behind it.
// Put refuses it; a read at the bound or in the past is accepted.
func TestPutRefusesReadTimeFarInTheFuture(t *testing.T) {
	c := useClock(t)
	now := c.t
	cases := []struct {
		name    string
		readAt  time.Time
		wantErr bool
	}{
		{"now", now, false},
		{"in the past", now.Add(-time.Hour), false},
		{"exactly MaxReadSkew ahead", now.Add(MaxReadSkew), false},
		{"one second over MaxReadSkew", now.Add(MaxReadSkew + time.Second), true},
		{"one year ahead", now.AddDate(1, 0, 0), true},
	}
	s, db := openStore(t)
	ctx := context.Background()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := rowCount(t, db)
			r := testRead("host-future", true, 0)
			r.ReadAt = tc.readAt
			_, err := s.Put(ctx, r)
			if (err != nil) != tc.wantErr {
				t.Fatalf("Put err = %v, wantErr %v", err, tc.wantErr)
			}
			if tc.wantErr && !errors.Is(err, ErrInvalidRead) {
				t.Errorf("Put err = %v, want ErrInvalidRead", err)
			}
			want := before
			if !tc.wantErr {
				want++
			}
			if n := rowCount(t, db); n != want {
				t.Errorf("rows = %d, want %d", n, want)
			}
		})
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

// TestBodyColumnCheckMatchesMaxBodyBytes checks the length CHECK on the body
// column against the Go constant, using zeroblob so no large value is built.
func TestBodyColumnCheckMatchesMaxBodyBytes(t *testing.T) {
	_, db := openStore(t)
	insert := func(n int) error {
		_, err := db.Exec(`INSERT INTO vuln_inventory_reads (host_id, execution_id, read_at, complete, reason,
			dropped, ecosystem, kernel_release, kernel_state, kernel_source, kernel_version, binaries, sources, body)
			VALUES ('h', 'e', 1, 1, '', 0, '', '', '', '', '', 0, 0, zeroblob(?))`, n)
		return err
	}
	if err := insert(MaxBodyBytes); err != nil {
		t.Errorf("body of MaxBodyBytes refused by the column: %v", err)
	}
	if err := insert(MaxBodyBytes + 1); err == nil {
		t.Errorf("body of MaxBodyBytes+1 accepted by the column")
	}
	if err := insert(1); err == nil {
		t.Errorf("body of 1 byte accepted by the column")
	}
}

// TestStoredBodyIsCheckedOnRead writes rows the Go store would refuse, directly
// through SQL, and checks that reading them fails instead of returning them.
func TestStoredBodyIsCheckedOnRead(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"not canonical: components out of order",
			`[{"source":"zlib","source_version":"1","binaries":[]},{"source":"bash","source_version":"5","binaries":[]}]`},
		{"not canonical: whitespace", `[ ]`},
		{"field outside the export pattern", `[{"source":"<script>","source_version":"1","binaries":[]}]`},
		{"duplicate component", `[{"source":"bash","source_version":"5","binaries":[]},{"source":"bash","source_version":"5","binaries":[]}]`},
		{"not JSON", `[{"source":`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, db := openStore(t)
			ctx := context.Background()
			// The fixture is written by SQL, which skips the Go checks. The
			// immutability trigger only blocks UPDATE, so an INSERT is the way in.
			if _, err := db.Exec(`INSERT INTO vuln_inventory_reads (host_id, execution_id, read_at, complete, reason,
				dropped, ecosystem, kernel_release, kernel_state, kernel_source, kernel_version, binaries, sources, body)
				VALUES ('host-bad', 'e', 1, 1, '', 0, '', '', '', '', '', 0, 0, CAST(? AS BLOB))`, c.body); err != nil {
				t.Fatalf("insert fixture: %v", err)
			}
			var badID int64
			if err := db.QueryRow(`SELECT MAX(id) FROM vuln_inventory_reads`).Scan(&badID); err != nil {
				t.Fatal(err)
			}
			if _, err := s.Get(ctx, badID); err == nil || errors.Is(err, ErrNoRead) {
				t.Errorf("Get of a stored bad body err = %v; want a decode error", err)
			}
			if _, err := s.Latest(ctx, "host-bad"); err == nil {
				t.Errorf("Latest of a stored bad body returned no error")
			}
		})
	}
}

func TestDecodeBodyRejectsWhatPutWouldRefuse(t *testing.T) {
	huge := []byte("[" + strings.Repeat(" ", MaxBodyBytes) + "]")
	cases := []struct {
		name    string
		body    string
		raw     []byte
		wantErr error
	}{
		{"canonical empty list", "[]", nil, nil},
		{"over the body limit", "", huge, ErrLimit},
		{"escaped character in a name", `[{"source":"a<b","source_version":"1","binaries":[]}]`, nil, ErrInvalidRead},
		{"empty source", `[{"source":"","source_version":"1","binaries":[]}]`, nil, ErrInvalidRead},
		{"binary without version", `[{"source":"bash","source_version":"5","binaries":[{"name":"aa","version":"","arch":""}]}]`, nil, ErrInvalidRead},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			body := c.raw
			if body == nil {
				body = []byte(c.body)
			}
			_, err := decodeBody(body)
			if c.wantErr == nil {
				if err != nil {
					t.Fatalf("decodeBody: %v", err)
				}
				return
			}
			if !errors.Is(err, c.wantErr) {
				t.Fatalf("decodeBody err = %v, want %v", err, c.wantErr)
			}
		})
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
	got, truncated, err := s.LatestAll(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if truncated {
		t.Error("truncated = true for two hosts")
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

// insertHostReads stores one read for each of n hosts, host-00000 upwards, in
// one transaction. It writes rows directly, so a test with thousands of hosts
// stays fast; the body is the empty list, which LatestAll does not decode.
func insertHostReads(t *testing.T, db *sql.DB, n int) {
	t.Helper()
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	stmt, err := tx.Prepare(`INSERT INTO vuln_inventory_reads (host_id, execution_id, read_at, complete, reason,
		dropped, ecosystem, kernel_release, kernel_state, kernel_source, kernel_version, binaries, sources, body)
		VALUES (?, 'exec-1', ?, 1, '', 0, '', '', '', '', '', 0, 0, x'5b5d')`)
	if err != nil {
		t.Fatal(err)
	}
	defer stmt.Close()
	for i := range n {
		if _, err := stmt.Exec(fmt.Sprintf("host-%05d", i), base.Unix()); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

// TestLatestAllStopsAtMaxLatestAllHosts checks the result limit. A store with
// more hosts than the limit returns the first MaxLatestAllHosts in host-ID order
// and says the result was truncated, so a caller cannot take a partial list for
// the whole fleet.
func TestLatestAllStopsAtMaxLatestAllHosts(t *testing.T) {
	s, db := openStore(t)
	insertHostReads(t, db, MaxLatestAllHosts+1)
	got, truncated, err := s.LatestAll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !truncated {
		t.Error("truncated = false with MaxLatestAllHosts+1 hosts")
	}
	if len(got) != MaxLatestAllHosts {
		t.Fatalf("LatestAll returned %d reads, want %d", len(got), MaxLatestAllHosts)
	}
	if first := got[0].HostID; first != "host-00000" {
		t.Errorf("first host = %s, want host-00000", first)
	}
	if last, want := got[len(got)-1].HostID, fmt.Sprintf("host-%05d", MaxLatestAllHosts-1); last != want {
		t.Errorf("last host = %s, want %s", last, want)
	}
}

// TestLatestAllAtTheLimitIsNotTruncated checks that exactly MaxLatestAllHosts
// hosts are all returned and not reported as truncated.
func TestLatestAllAtTheLimitIsNotTruncated(t *testing.T) {
	s, db := openStore(t)
	insertHostReads(t, db, MaxLatestAllHosts)
	got, truncated, err := s.LatestAll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if truncated {
		t.Error("truncated = true with exactly MaxLatestAllHosts hosts")
	}
	if len(got) != MaxLatestAllHosts {
		t.Errorf("LatestAll returned %d reads, want %d", len(got), MaxLatestAllHosts)
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

// queryPlan returns the EXPLAIN QUERY PLAN detail lines of query, one per line.
func queryPlan(t *testing.T, db *sql.DB, query string, args ...any) string {
	t.Helper()
	rows, err := db.Query("EXPLAIN QUERY PLAN "+query, args...)
	if err != nil {
		t.Fatalf("explain: %v", err)
	}
	defer rows.Close()
	var b strings.Builder
	for rows.Next() {
		var id, parent, unused int
		var detail string
		if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
			t.Fatal(err)
		}
		b.WriteString(detail + "\n")
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

// TestReadQueriesUseIndexesWithoutSorting checks the plans of the read path.
// Each query must use an index on the host's reads and must not sort a
// temporary B-tree, so a lookup costs the index seek and not a sort of every
// read of the host (or of the table, for LatestAll).
func TestReadQueriesUseIndexesWithoutSorting(t *testing.T) {
	s, db := openStore(t)
	mustPut(t, s, testRead("host-a", true, 1))
	mustPut(t, s, testRead("host-a", false, 2))
	mustPut(t, s, testRead("host-b", false, 3))
	cases := []struct {
		name  string
		query string
		args  []any
		index string
	}{
		{"latest", latestQuery, []any{"host-a"}, "vuln_inventory_reads_host_read"},
		{"last complete", lastCompleteQuery, []any{"host-a"}, "vuln_inventory_reads_host_complete"},
		{"latest all: per-host subquery", latestAllQuery, nil, "vuln_inventory_reads_host_read"},
		{"latest all: limited host list", latestAllLimitedQuery, []any{MaxLatestAllHosts + 1}, "vuln_inventory_reads_host_read"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			plan := queryPlan(t, db, c.query, c.args...)
			if strings.Contains(plan, "TEMP B-TREE") {
				t.Errorf("query sorts a temporary B-tree:\n%s", plan)
			}
			if !strings.Contains(plan, c.index) {
				t.Errorf("query does not use %s:\n%s", c.index, plan)
			}
		})
	}
}

// TestLatestAllAgreesWithLatestPerHost checks the set-based LatestAll against
// the single-host Latest, with hosts whose newest read is not their last
// inserted one and whose last complete read is not their newest.
func TestLatestAllAgreesWithLatestPerHost(t *testing.T) {
	s, _ := openStore(t)
	ctx := context.Background()
	mustPut(t, s, testRead("host-c", true, 9))
	mustPut(t, s, testRead("host-c", false, 4))
	mustPut(t, s, testRead("host-a", false, 2))
	mustPut(t, s, testRead("host-a", true, 2))
	mustPut(t, s, testRead("host-b", true, 1))
	mustPut(t, s, testRead("host-b", false, 1))
	got, _, err := s.LatestAll(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("LatestAll returned %d hosts, want 3", len(got))
	}
	for i, r := range got {
		if i > 0 && got[i-1].HostID >= r.HostID {
			t.Errorf("LatestAll not ordered by host: %s before %s", got[i-1].HostID, r.HostID)
		}
		want, err := s.Latest(ctx, r.HostID)
		if err != nil {
			t.Fatal(err)
		}
		if r.ID != want.ID || !r.ReadAt.Equal(want.ReadAt) || r.Complete != want.Complete {
			t.Errorf("LatestAll %s = id %d, Latest = id %d", r.HostID, r.ID, want.ID)
		}
	}
}

// countBody returns the binary and source counts of a stored body, computed
// from the body itself and not from the columns.
func countBody(t *testing.T, body []byte) (int, int) {
	t.Helper()
	comps, err := decodeBody(body)
	if err != nil {
		t.Fatalf("decode stored body: %v", err)
	}
	bins := 0
	for _, c := range comps {
		bins += len(c.Binaries)
	}
	return bins, len(comps)
}

// TestDerivedCountsMatchBody checks the binaries and sources columns against
// the body they were written with. Each case has a different shape, so an
// implementation that counts only the first component fails one of them.
func TestDerivedCountsMatchBody(t *testing.T) {
	binaries := func(prefix string, n int) []Binary {
		bs := make([]Binary, n)
		for i := range bs {
			bs[i] = Binary{Name: fmt.Sprintf("%s%d", prefix, i), Version: "1", Arch: "amd64"}
		}
		return bs
	}
	cases := []struct {
		name     string
		comps    []Component
		wantBins int
		wantSrcs int
	}{
		{"no components", nil, 0, 0},
		{"one component, no binaries", []Component{{Source: "src-a", SourceVersion: "1"}}, 0, 1},
		{"first component has one binary", []Component{
			{Source: "src-a", SourceVersion: "1", Binaries: binaries("x", 1)},
			{Source: "src-b", SourceVersion: "1", Binaries: binaries("y", 3)},
			{Source: "src-c", SourceVersion: "1", Binaries: binaries("z", 2)},
		}, 6, 3},
		{"first component has none", []Component{
			{Source: "src-a", SourceVersion: "1"},
			{Source: "src-b", SourceVersion: "1", Binaries: binaries("y", 2)},
		}, 2, 2},
		{"one component, many binaries", []Component{
			{Source: "src-a", SourceVersion: "1", Binaries: binaries("x", 7)},
		}, 7, 1},
	}
	s, db := openStore(t)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := testRead("host-counts", true, 1)
			r.Components = c.comps
			id := mustPut(t, s, r)
			var bins, srcs int
			var body []byte
			if err := db.QueryRow(`SELECT binaries, sources, body FROM vuln_inventory_reads WHERE id = ?`, id).Scan(&bins, &srcs, &body); err != nil {
				t.Fatal(err)
			}
			if bins != c.wantBins || srcs != c.wantSrcs {
				t.Errorf("columns binaries=%d sources=%d, want %d and %d", bins, srcs, c.wantBins, c.wantSrcs)
			}
			gotBins, gotSrcs := countBody(t, body)
			if gotBins != bins || gotSrcs != srcs {
				t.Errorf("body holds %d binaries and %d sources, columns say %d and %d", gotBins, gotSrcs, bins, srcs)
			}
		})
	}
}

// rawColumns are the columns of a read in the order rawInsert writes them.
var rawColumns = []string{"host_id", "execution_id", "read_at", "complete", "reason", "dropped",
	"ecosystem", "kernel_release", "kernel_state", "kernel_source", "kernel_version", "binaries", "sources", "body"}

// rawInsert inserts a row through SQL, skipping the Go checks, with every
// column valid except column, which takes value.
func rawInsert(db *sql.DB, column string, value any) error {
	vals := map[string]any{
		"host_id": "h", "execution_id": "e", "read_at": 1, "complete": 1, "reason": "", "dropped": 0,
		"ecosystem": "", "kernel_release": "", "kernel_state": "", "kernel_source": "", "kernel_version": "",
		"binaries": 0, "sources": 0, "body": []byte("[]"),
	}
	vals[column] = value
	args := make([]any, len(rawColumns))
	marks := make([]string, len(rawColumns))
	for i, c := range rawColumns {
		args[i] = vals[c]
		marks[i] = "?"
	}
	_, err := db.Exec(`INSERT INTO vuln_inventory_reads (`+strings.Join(rawColumns, ", ")+`) VALUES (`+strings.Join(marks, ", ")+`)`, args...)
	return err
}

// bytesOf returns a string of exactly n bytes: "ä" (two bytes) repeated, with
// one "x" when n is odd. Multibyte characters make a byte limit differ from a
// character limit.
func bytesOf(n int) string {
	return strings.Repeat("ä", n/2) + strings.Repeat("x", n%2)
}

// TestSQLTextLimitsMatchGoConstants checks each byte CHECK of the migration
// against the Go constant that names the same limit. The migration cannot
// import Go, so the two are compared here: a value of exactly the constant's
// bytes is stored and one byte more is refused.
func TestSQLTextLimitsMatchGoConstants(t *testing.T) {
	cases := []struct {
		column string
		limit  int
		min    int
	}{
		{"host_id", maxHostIDBytes, 1},
		{"execution_id", maxExecutionIDBytes, 1},
		{"reason", MaxReasonBytes, 0},
		{"ecosystem", maxEcosystemBytes, 0},
		{"kernel_release", maxKernelReleaseBytes, 0},
		{"kernel_state", maxKernelStateBytes, 0},
		{"kernel_source", maxKernelSourceBytes, 0},
		{"kernel_version", maxKernelVersionBytes, 0},
	}
	_, db := openStore(t)
	for _, c := range cases {
		t.Run(c.column, func(t *testing.T) {
			if err := rawInsert(db, c.column, bytesOf(c.limit)); err != nil {
				t.Errorf("%d bytes refused by the column: %v", c.limit, err)
			}
			if err := rawInsert(db, c.column, bytesOf(c.limit+1)); err == nil {
				t.Errorf("%d bytes accepted by the column, limit %d", c.limit+1, c.limit)
			}
			if c.min == 1 {
				if err := rawInsert(db, c.column, ""); err == nil {
					t.Errorf("empty value accepted by the column")
				}
			}
		})
	}
}

// TestSQLCountLimitsMatchGoConstants checks the count CHECKs of the migration
// against the Go constants: dropped <= MaxDropped, binaries <= MaxBinaries and
// sources <= MaxComponents.
func TestSQLCountLimitsMatchGoConstants(t *testing.T) {
	cases := []struct {
		column string
		limit  int
	}{
		{"dropped", MaxDropped},
		{"binaries", MaxBinaries},
		{"sources", MaxComponents},
	}
	_, db := openStore(t)
	for _, c := range cases {
		t.Run(c.column, func(t *testing.T) {
			if err := rawInsert(db, c.column, c.limit); err != nil {
				t.Errorf("%s = %d refused by the column: %v", c.column, c.limit, err)
			}
			if err := rawInsert(db, c.column, c.limit+1); err == nil {
				t.Errorf("%s = %d accepted by the column, limit %d", c.column, c.limit+1, c.limit)
			}
		})
	}
}

// TestStoredReadCannotBeDeletedWhenPinnedNewestOrLastComplete checks the delete
// rule of migration 0052. A read is protected while a snapshot pins it, while
// it is the newest read of its host, and while it is the last complete read of
// its host. Any other read can be deleted.
func TestStoredReadCannotBeDeletedWhenPinnedNewestOrLastComplete(t *testing.T) {
	s, db := openStore(t)
	ctx := context.Background()
	// host-d: last complete at 1, unpinned incomplete at 2, newest incomplete at 3.
	lastComplete := mustPut(t, s, testRead("host-d", true, 1))
	middle := mustPut(t, s, testRead("host-d", false, 2))
	newest := mustPut(t, s, testRead("host-d", false, 3))
	// host-p: a pinned incomplete read at 1, under a complete read at 2 and a newer incomplete read at 3.
	pinned := mustPut(t, s, testRead("host-p", false, 1))
	mustPut(t, s, testRead("host-p", true, 2))
	mustPut(t, s, testRead("host-p", false, 3))
	if _, err := db.Exec(`INSERT INTO vuln_inventory_snapshots (id, generation, taken_at) VALUES ('s-pin', 1, 1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO vuln_inventory_snapshot_reads (snapshot_id, read_id) VALUES ('s-pin', ?)`, pinned); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name    string
		id      int64
		wantErr bool
	}{
		{"pinned read", pinned, true},
		{"newest read", newest, true},
		{"last complete read", lastComplete, true},
		{"unpinned incomplete read", middle, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := db.Exec(`DELETE FROM vuln_inventory_reads WHERE id = ?`, c.id)
			if (err != nil) != c.wantErr {
				t.Fatalf("DELETE err = %v, wantErr %v", err, c.wantErr)
			}
			if _, err := s.Get(ctx, c.id); (err != nil) == c.wantErr {
				t.Errorf("read %d present = %v after DELETE, wantErr %v", c.id, err == nil, c.wantErr)
			}
		})
	}
}

// TestMultiRowDeleteIsRefusedAsAWhole checks that a DELETE which would remove
// a protected read along with unprotected ones changes nothing.
func TestMultiRowDeleteIsRefusedAsAWhole(t *testing.T) {
	s, db := openStore(t)
	mustPut(t, s, testRead("host-m", true, 1))
	mustPut(t, s, testRead("host-m", false, 2))
	mustPut(t, s, testRead("host-m", false, 3))
	before := rowCount(t, db)
	if _, err := db.Exec(`DELETE FROM vuln_inventory_reads WHERE host_id = 'host-m'`); err == nil {
		t.Fatal("DELETE of every read of a host succeeded")
	}
	if n := rowCount(t, db); n != before {
		t.Errorf("rows = %d after refused DELETE, want %d", n, before)
	}
}

// ruleCase is one read a delete-rule test tries to delete. protected says
// whether the rule must refuse the DELETE and keep the read.
type ruleCase struct {
	name      string
	id        int64
	protected bool
}

// checkDeleteRule runs a DELETE of each case's read and checks the outcome. The
// cases are chosen so that a DELETE of an unprotected read never changes which
// reads are protected, so they can share one store.
func checkDeleteRule(t *testing.T, s *Store, db *sql.DB, cases []ruleCase) {
	t.Helper()
	ctx := context.Background()
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := db.Exec(`DELETE FROM vuln_inventory_reads WHERE id = ?`, c.id)
			if refused := err != nil; refused != c.protected {
				t.Fatalf("DELETE of read %d: refused = %v, want %v (err %v)", c.id, refused, c.protected, err)
			}
			if _, err := s.Get(ctx, c.id); (err == nil) != c.protected {
				t.Errorf("read %d present = %v after DELETE, want %v", c.id, err == nil, c.protected)
			}
		})
	}
}

// TestDeleteRuleFollowsReadTimeNotInsertOrder inserts reads out of read_at
// order, so the highest id is not the newest read. A rule that picks "newest"
// by id alone would protect the wrong read.
func TestDeleteRuleFollowsReadTimeNotInsertOrder(t *testing.T) {
	s, db := openStore(t)
	newestByTime := mustPut(t, s, testRead("host-o", false, 5)) // lowest id, newest read_at
	lastComplete := mustPut(t, s, testRead("host-o", true, 1))  // only complete read
	middle := mustPut(t, s, testRead("host-o", false, 3))       // highest id, middle read_at
	checkDeleteRule(t, s, db, []ruleCase{
		{"newest by read_at with the lowest id", newestByTime, true},
		{"last complete with the middle id", lastComplete, true},
		{"middle read_at with the highest id", middle, false},
	})
}

// TestLastCompleteFollowsReadTimeNotInsertOrder inserts two complete reads with
// the higher id on the older read. The last complete read is the newer one.
func TestLastCompleteFollowsReadTimeNotInsertOrder(t *testing.T) {
	s, db := openStore(t)
	lastComplete := mustPut(t, s, testRead("host-l", true, 5))  // complete, newer, lower id
	olderComplete := mustPut(t, s, testRead("host-l", true, 2)) // complete, older, higher id
	newest := mustPut(t, s, testRead("host-l", false, 9))       // incomplete, newest read_at
	checkDeleteRule(t, s, db, []ruleCase{
		{"newer complete read with the lower id", lastComplete, true},
		{"older complete read with the higher id", olderComplete, false},
		{"newest incomplete read", newest, true},
	})
}

// TestDeleteRuleBreaksEqualReadTimeByID gives reads the same read_at. The
// newest read is the highest id, and so is the last complete read, the same
// order the read queries use (read_at DESC, id DESC).
func TestDeleteRuleBreaksEqualReadTimeByID(t *testing.T) {
	s, db := openStore(t)
	// host-e: two complete reads and one incomplete, all at read_at 4.
	olderComplete := mustPut(t, s, testRead("host-e", true, 4)) // id 1
	lastComplete := mustPut(t, s, testRead("host-e", true, 4))  // id 2, last complete by id
	newestE := mustPut(t, s, testRead("host-e", false, 4))      // id 3, newest by id
	// host-f: two incomplete reads at read_at 4; only the higher id is newest.
	olderIncomplete := mustPut(t, s, testRead("host-f", false, 4)) // id 4
	newestF := mustPut(t, s, testRead("host-f", false, 4))         // id 5, newest by id
	checkDeleteRule(t, s, db, []ruleCase{
		{"newest at equal read_at, highest id", newestE, true},
		{"last complete at equal read_at, highest id", lastComplete, true},
		{"complete at equal read_at, lower id", olderComplete, false},
		{"newest incomplete at equal read_at", newestF, true},
		{"incomplete at equal read_at, lower id", olderIncomplete, false},
	})
}

// TestMultiRowDeleteRollsBackEarlierRowsOfTheStatement checks what the rule
// does for a DELETE that removes an unprotected row before it reaches the
// newest one. The BEFORE DELETE check runs per row, so the earlier row is
// already gone when the newest row is checked; RAISE(ABORT) then rolls the
// whole statement back, so the earlier row must still be there.
func TestMultiRowDeleteRollsBackEarlierRowsOfTheStatement(t *testing.T) {
	s, db := openStore(t)
	deletable := mustPut(t, s, testRead("host-x", false, 1)) // lower id, not protected
	mustPut(t, s, testRead("host-x", false, 2))              // newest, protected
	before := rowCount(t, db)
	if _, err := db.Exec(`DELETE FROM vuln_inventory_reads WHERE host_id = 'host-x'`); err == nil {
		t.Fatal("DELETE of every read of a host succeeded")
	}
	if n := rowCount(t, db); n != before {
		t.Errorf("rows = %d after refused DELETE, want %d", n, before)
	}
	if _, err := s.Get(context.Background(), deletable); err != nil {
		t.Errorf("unprotected read %d lost after refused DELETE: %v", deletable, err)
	}
}

// TestInsertOrReplaceCannotSwapARead checks that no insert reuses the id of a
// stored read. INSERT OR REPLACE deletes the old row without a DELETE trigger,
// so it is refused by the insert trigger; a plain INSERT with a used id is
// refused by the primary key. The protected and the unprotected reads are both
// tried.
func TestInsertOrReplaceCannotSwapARead(t *testing.T) {
	s, db := openStore(t)
	ctx := context.Background()
	lastComplete := mustPut(t, s, testRead("host-r", true, 1))
	middle := mustPut(t, s, testRead("host-r", false, 2))
	newest := mustPut(t, s, testRead("host-r", false, 3))
	for _, c := range []struct {
		name string
		id   int64
	}{
		{"last complete read", lastComplete},
		{"unprotected middle read", middle},
		{"newest read", newest},
	} {
		t.Run(c.name, func(t *testing.T) {
			before, err := s.Get(ctx, c.id)
			if err != nil {
				t.Fatal(err)
			}
			n := rowCount(t, db)
			const swap = `INSERT OR REPLACE INTO vuln_inventory_reads (id, host_id, execution_id, read_at, complete, reason,
				dropped, ecosystem, kernel_release, kernel_state, kernel_source, kernel_version, binaries, sources, body)
				VALUES (?, 'host-r', 'evil', 9, 1, 'swapped', 0, '', '', '', '', '', 0, 0, x'5b5d')`
			if _, err := db.Exec(swap, c.id); err == nil {
				t.Fatal("INSERT OR REPLACE of a stored read succeeded")
			}
			if _, err := db.Exec(`INSERT INTO vuln_inventory_reads (id, host_id, execution_id, read_at, complete, reason,
				dropped, ecosystem, kernel_release, kernel_state, kernel_source, kernel_version, binaries, sources, body)
				VALUES (?, 'host-r', 'evil', 9, 1, 'swapped', 0, '', '', '', '', '', 0, 0, x'5b5d')`, c.id); err == nil {
				t.Fatal("plain INSERT with a stored id succeeded")
			}
			after, err := s.Get(ctx, c.id)
			if err != nil {
				t.Fatal(err)
			}
			if after.Reason != before.Reason || after.ExecutionID != before.ExecutionID || !after.ReadAt.Equal(before.ReadAt) {
				t.Errorf("stored read changed: %+v, was %+v", after, before)
			}
			if rowCount(t, db) != n {
				t.Errorf("row count changed by a refused insert")
			}
		})
	}
}

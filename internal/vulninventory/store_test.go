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

// TestWorstCaseReadsFitEveryLimit stores the largest reads the limits allow
// and checks the exact body size, so the derivation of MaxBodyBytes is tested
// against real bytes, not only against the constant.
func TestWorstCaseReadsFitEveryLimit(t *testing.T) {
	// One component with 1 binary, all fields at maximum:
	// component 303 + binary 322 = 625 bytes; MaxComponents of them joined
	// by commas inside the "[]" envelope.
	const perComponent = 303 + 322
	// One source package with MaxBinaries binaries at maximum length:
	// component 303 (its empty binaries list included), each binary 322,
	// commas between binaries, inside the envelope.
	const perBinary = 322

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
			"one component with MaxBinaries maximal-length binaries",
			func() []Component {
				bs := make([]Binary, MaxBinaries)
				for i := range bs {
					// 128 distinct digits; a digit is a valid first character.
					bs[i] = Binary{Name: fmt.Sprintf("%0128d", i), Version: "v" + strings.Repeat("v", maxVersionBytes-1), Arch: strings.Repeat("a", maxArchBytes)}
				}
				return []Component{{
					Source:        "s" + strings.Repeat("s", maxNameBytes-1),
					SourceVersion: "v" + strings.Repeat("v", maxVersionBytes-1),
					Binaries:      bs,
				}}
			},
			303 + MaxBinaries*perBinary + (MaxBinaries - 1) + 2,
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

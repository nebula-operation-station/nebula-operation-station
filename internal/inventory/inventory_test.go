// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Tests for the host inventory model (A06): validation listing every
// problem, explicit endpoint ordering, CRUD with duplicate-ID rejection,
// the Proxmox criticality default, and persistence round trips. All
// tests use t.TempDir() and an in-memory-free SQLite file database.

package inventory

import (
	"context"
	"errors"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
)

var fixedNow = func() time.Time { return time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC) }

// openStore opens a fresh server database in a temp dir and returns an
// inventory store over it. The database path is returned so tests can
// close and reopen it.
func openStore(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "nebula.db")
	db, err := serverdb.Open(path)
	if err != nil {
		t.Fatalf("serverdb.Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return NewWithNow(db, fixedNow), path
}

// validHost returns a host that passes Validate.
func validHost() Host {
	return Host{
		ID:            "web-01",
		DisplayName:   "Web one",
		Environment:   EnvProd,
		Criticality:   CriticalityMedium,
		Endpoints:     []Endpoint{{Address: "10.0.0.11", Port: 22}, {Address: "vpn.example.org", Port: 2222}},
		Groups:        []string{"web", "rack-1"},
		Tags:          map[string]string{"role": "web", "gpu": "a2000"},
		CredentialRef: "nebula-default",
	}
}

// --- Acceptance criterion 1: the host model and its validation. ---

func TestValidateAcceptsValidHost(t *testing.T) {
	if err := Validate(validHost()); err != nil {
		t.Fatalf("Validate rejected a valid host: %v", err)
	}
}

// TestValidateListsEveryProblem feeds a host with eight distinct defects
// and requires the error to name all of them, not just the first.
func TestValidateListsEveryProblem(t *testing.T) {
	h := Host{
		ID:          "Bad ID!", // fails the ID pattern
		DisplayName: strings.Repeat("x", maxDisplayNameLen+1),
		Environment: "STAGING",
		Criticality: "URGENT",
		Endpoints: []Endpoint{
			{Address: "10.0.0.1"},
			{Address: "10.0.0.1"},         // duplicate of the first
			{Address: "not a host name!"}, // neither IP nor hostname
			{Address: "10.0.0.2", Port: 70000},
		},
		Groups:        []string{"web", "web", "Bad Group"},
		Tags:          map[string]string{"bad key!": "v", "empty": ""},
		CredentialRef: "UPPER_CASE",
	}
	err := Validate(h)
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("Validate returned %T, want *ValidationError", err)
	}
	want := []string{
		`id "Bad ID!"`,
		"display_name is longer",
		`environment "STAGING"`,
		`criticality "URGENT"`,
		`endpoint 1: "10.0.0.1" is duplicated`,
		`endpoint 2: "not a host name!" is neither an IP address nor a hostname`,
		"endpoint 3: port 70000 out of range",
		`group "web" is duplicated`,
		`group "Bad Group" is malformed`,
		`tag key "bad key!" is malformed`,
		`tag value for "empty" is empty`,
		`credential_ref "UPPER_CASE" is malformed`,
	}
	if len(ve.Problems) != len(want) {
		t.Fatalf("got %d problems, want %d:\n%s", len(ve.Problems), len(want), strings.Join(ve.Problems, "\n"))
	}
	for _, w := range want {
		if !contains(ve.Problems, w) {
			t.Errorf("problems do not mention %q:\n%s", w, strings.Join(ve.Problems, "\n"))
		}
	}
}

func TestValidateRequiresAtLeastOneEndpoint(t *testing.T) {
	h := validHost()
	h.Endpoints = nil
	err := Validate(h)
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("Validate returned %T, want *ValidationError", err)
	}
	if !contains(ve.Problems, "at least one endpoint is required") {
		t.Errorf("problems do not mention the missing endpoint: %v", ve.Problems)
	}
}

// TestValidateDuplicateEndpoints checks that the duplicate endpoint check
// compares the lowercased address together with the effective port (0
// means 22).
func TestValidateDuplicateEndpoints(t *testing.T) {
	cases := []struct {
		name      string
		endpoints []Endpoint
		wantDup   bool
	}{
		{
			"case-insensitive, default vs explicit 22",
			[]Endpoint{{Address: "Srv1.lan"}, {Address: "srv1.lan", Port: 22}},
			true,
		},
		{
			"case-insensitive, both default",
			[]Endpoint{{Address: "Srv1.lan"}, {Address: "SRV1.LAN"}},
			true,
		},
		{
			"ipv6 case-insensitive",
			[]Endpoint{{Address: "FD00::1"}, {Address: "fd00::1"}},
			true,
		},
		{
			"different ports are not duplicates",
			[]Endpoint{{Address: "srv1.lan", Port: 22}, {Address: "srv1.lan", Port: 2222}},
			false,
		},
		{
			"default port vs 2222 are not duplicates",
			[]Endpoint{{Address: "srv1.lan"}, {Address: "srv1.lan", Port: 2222}},
			false,
		},
		{
			"different addresses are not duplicates",
			[]Endpoint{{Address: "a.lan", Port: 22}, {Address: "b.lan", Port: 22}},
			false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := validHost()
			h.Endpoints = tc.endpoints
			err := Validate(h)
			var ve *ValidationError
			if !errors.As(err, &ve) {
				if tc.wantDup {
					t.Fatalf("Validate = %v, want a duplicate endpoint problem", err)
				}
				return
			}
			gotDup := contains(ve.Problems, `is duplicated (first at`)
			if gotDup != tc.wantDup {
				t.Fatalf("duplicate endpoint problem = %v, want %v (problems: %v)", gotDup, tc.wantDup, ve.Problems)
			}
		})
	}
}

func contains(problems []string, sub string) bool {
	for _, p := range problems {
		if strings.Contains(p, sub) {
			return true
		}
	}
	return false
}

// --- Acceptance criterion 2: endpoint order is explicit and stable. ---

// TestEndpointOrderStoredExplicitly creates a host whose endpoints are in
// a deliberately unsorted order and checks that the stored order is
// exactly the given order, on read-back and after an update.
func TestEndpointOrderStoredExplicitly(t *testing.T) {
	s, _ := openStore(t)
	ctx := context.Background()

	in := validHost()
	in.Endpoints = []Endpoint{
		{Address: "10.0.0.99", Port: 2200},
		{Address: "10.0.0.10", Port: 22},
		{Address: "mgmt.example.org", Port: 22},
	}
	if _, err := s.Create(ctx, in, CreateOptions{}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	got, err := s.Get(ctx, in.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !endpointsEqual(got.Endpoints, in.Endpoints) {
		t.Fatalf("stored endpoints %v, want the given order %v", got.Endpoints, in.Endpoints)
	}

	// An update that reorders the endpoints must store the new order, not
	// restore or sort anything.
	got.Endpoints = []Endpoint{{Address: "mgmt.example.org", Port: 22}, {Address: "10.0.0.10", Port: 22}, {Address: "10.0.0.99", Port: 2200}}
	if _, err := s.Update(ctx, got); err != nil {
		t.Fatalf("Update: %v", err)
	}
	again, err := s.Get(ctx, in.ID)
	if err != nil {
		t.Fatalf("Get after update: %v", err)
	}
	if !endpointsEqual(again.Endpoints, got.Endpoints) {
		t.Fatalf("endpoints after update %v, want %v", again.Endpoints, got.Endpoints)
	}
}

// TestDefaultPortApplied stores endpoints with port 0 and checks that the
// default port 22 is what is persisted and read back.
func TestDefaultPortApplied(t *testing.T) {
	s, _ := openStore(t)
	ctx := context.Background()

	h := validHost()
	h.Endpoints = []Endpoint{{Address: "10.0.0.11"}, {Address: "10.0.0.12", Port: 2222}}
	if _, err := s.Create(ctx, h, CreateOptions{}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	got, err := s.Get(ctx, h.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Endpoints[0].Port != 22 {
		t.Errorf("default port = %d, want 22", got.Endpoints[0].Port)
	}
	if got.Endpoints[1].Port != 2222 {
		t.Errorf("explicit port = %d, want 2222", got.Endpoints[1].Port)
	}
}

// --- Acceptance criterion 3: CRUD, duplicate IDs, validation errors. ---

func TestDuplicateHostIDRejected(t *testing.T) {
	s, _ := openStore(t)
	ctx := context.Background()

	if _, err := s.Create(ctx, validHost(), CreateOptions{}); err != nil {
		t.Fatalf("first Create: %v", err)
	}
	_, err := s.Create(ctx, validHost(), CreateOptions{})
	if !errors.Is(err, ErrHostExists) {
		t.Fatalf("second Create error = %v, want ErrHostExists", err)
	}
}

func TestCreateWithInvalidHostStoresNothing(t *testing.T) {
	s, _ := openStore(t)
	ctx := context.Background()

	h := validHost()
	h.ID = "Bad ID"
	h.Environment = "NOPE"
	_, err := s.Create(ctx, h, CreateOptions{})
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("Create error = %v, want *ValidationError", err)
	}
	if len(ve.Problems) < 2 {
		t.Errorf("expected at least two problems, got %v", ve.Problems)
	}
	if _, err := s.Get(ctx, "bad id"); err == nil {
		t.Error("invalid host was stored")
	}
}

func TestCRUDRoundTrip(t *testing.T) {
	s, _ := openStore(t)
	ctx := context.Background()

	in := validHost()
	created, err := s.Create(ctx, in, CreateOptions{})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if created.Environment != EnvProd || created.Criticality != CriticalityMedium {
		t.Errorf("created = %+v, want environment PROD and criticality MEDIUM", created)
	}

	got, err := s.Get(ctx, in.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !hostsEqual(got, in) {
		t.Errorf("Get = %+v, want %+v", got, in)
	}

	// Update: rename, drop one endpoint and one group, change a tag,
	// change the credential reference.
	got.DisplayName = "Web one (renamed)"
	got.Environment = EnvDev
	got.Endpoints = got.Endpoints[:1]
	got.Groups = []string{"web"}
	got.Tags = map[string]string{"role": "web"}
	got.CredentialRef = "nebula-prod"
	if _, err := s.Update(ctx, got); err != nil {
		t.Fatalf("Update: %v", err)
	}
	got2, err := s.Get(ctx, in.ID)
	if err != nil {
		t.Fatalf("Get after update: %v", err)
	}
	if !hostsEqual(got2, got) {
		t.Errorf("Get after update = %+v, want %+v", got2, got)
	}

	if err := s.Delete(ctx, in.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := s.Get(ctx, in.ID); !errors.Is(err, ErrHostNotFound) {
		t.Errorf("Get after delete = %v, want ErrHostNotFound", err)
	}
	if err := s.Delete(ctx, in.ID); !errors.Is(err, ErrHostNotFound) {
		t.Errorf("second Delete = %v, want ErrHostNotFound", err)
	}
}

func TestUpdateMissingHost(t *testing.T) {
	s, _ := openStore(t)
	if _, err := s.Update(context.Background(), validHost()); !errors.Is(err, ErrHostNotFound) {
		t.Errorf("Update of missing host = %v, want ErrHostNotFound", err)
	}
}

func TestListReturnsAllHostsOrderedByID(t *testing.T) {
	s, _ := openStore(t)
	ctx := context.Background()

	for _, id := range []string{"zeta", "alpha", "mid-1"} {
		h := validHost()
		h.ID = id
		if _, err := s.Create(ctx, h, CreateOptions{}); err != nil {
			t.Fatalf("Create %s: %v", id, err)
		}
	}
	list, err := s.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 3 {
		t.Fatalf("List returned %d hosts, want 3", len(list))
	}
	var ids []string
	for _, h := range list {
		ids = append(ids, h.ID)
	}
	sort.Strings(ids)
	for i, want := range []string{"alpha", "mid-1", "zeta"} {
		if list[i].ID != want {
			t.Errorf("List order = %v, want sorted by ID %v", ids, want)
		}
	}
}

// --- Acceptance criterion 4: Proxmox hosts default to criticality HIGH. ---

func TestProxmoxDefaultCriticality(t *testing.T) {
	s, _ := openStore(t)
	ctx := context.Background()

	cases := []struct {
		name    string
		hint    string
		setCrit Criticality
		want    Criticality
	}{
		{"proxmox hint, unset", "proxmox", "", CriticalityHigh},
		{"proxmox hint case-insensitive", "PROXMOX", "", CriticalityHigh},
		{"no hint, unset", "", "", CriticalityLow},
		{"other hint, unset", "debian", "", CriticalityLow},
		{"proxmox hint, explicit wins", "proxmox", CriticalityCritical, CriticalityCritical},
		{"proxmox hint, explicit low wins", "proxmox", CriticalityLow, CriticalityLow},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := validHost()
			h.ID = "pve-" + string(rune('a'+i))
			h.Criticality = tc.setCrit
			created, err := s.Create(ctx, h, CreateOptions{OSHint: tc.hint})
			if err != nil {
				t.Fatalf("Create: %v", err)
			}
			if created.Criticality != tc.want {
				t.Errorf("criticality = %s, want %s", created.Criticality, tc.want)
			}
			got, err := s.Get(ctx, h.ID)
			if err != nil {
				t.Fatalf("Get: %v", err)
			}
			if got.Criticality != tc.want {
				t.Errorf("stored criticality = %s, want %s", got.Criticality, tc.want)
			}
		})
	}
}

// --- Acceptance criterion 5: persistence round trips. ---

// TestPersistenceRoundTrip closes the database, reopens it, and checks
// that the host (including endpoint order, groups and tags) survives.
func TestPersistenceRoundTrip(t *testing.T) {
	s, path := openStore(t)
	ctx := context.Background()

	in := validHost()
	if _, err := s.Create(ctx, in, CreateOptions{}); err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Close everything and reopen from disk. (openStore's cleanup closes
	// the DB again; sql.DB.Close is idempotent.)
	if err := s.db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	db, err := serverdb.Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	s = NewWithNow(db, fixedNow)

	got, err := s.Get(ctx, in.ID)
	if err != nil {
		t.Fatalf("Get after reopen: %v", err)
	}
	if !hostsEqual(got, in) {
		t.Errorf("after reopen = %+v, want %+v", got, in)
	}
}

// TestMigrationAddsInventoryColumns checks that a fresh database (i.e.
// migrations 0001 and 0002 both applied) has the inventory columns and
// the key=value tag table.
func TestMigrationAddsInventoryColumns(t *testing.T) {
	s, _ := openStore(t)
	defer s.db.Close()

	columns := map[string]bool{}
	rows, err := s.db.Query(`PRAGMA table_info(hosts)`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var cid, notnull, pk int
		var name, colType string
		var dflt any
		if err := rows.Scan(&cid, &name, &colType, &notnull, &dflt, &pk); err != nil {
			t.Fatal(err)
		}
		columns[name] = true
	}
	rows.Close()
	for _, col := range []string{"display_name", "environment", "criticality"} {
		if !columns[col] {
			t.Errorf("hosts.%s missing after migration", col)
		}
	}

	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='host_tag_kv'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Error("host_tag_kv table missing after migration")
	}
}

// --- helpers ---

func endpointsEqual(a, b []Endpoint) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Address != b[i].Address || a[i].Port != b[i].Port {
			return false
		}
	}
	return true
}

func hostsEqual(a, b Host) bool {
	if a.ID != b.ID || a.DisplayName != b.DisplayName || a.Environment != b.Environment ||
		a.Criticality != b.Criticality || a.CredentialRef != b.CredentialRef {
		return false
	}
	if !endpointsEqual(a.Endpoints, b.Endpoints) {
		return false
	}
	if len(a.Groups) != len(b.Groups) {
		return false
	}
	ag, bg := append([]string(nil), a.Groups...), append([]string(nil), b.Groups...)
	sort.Strings(ag)
	sort.Strings(bg)
	for i := range ag {
		if ag[i] != bg[i] {
			return false
		}
	}
	if len(a.Tags) != len(b.Tags) {
		return false
	}
	for k, v := range a.Tags {
		if b.Tags[k] != v {
			return false
		}
	}
	return true
}

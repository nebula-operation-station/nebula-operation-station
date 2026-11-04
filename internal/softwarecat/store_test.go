// SPDX-License-Identifier: AGPL-3.0-or-later

package softwarecat

import (
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
)

var t0 = time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func newTestStore(t *testing.T) (*Store, *sql.DB, *clock) {
	t.Helper()
	db, err := serverdb.Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	c := &clock{t: t0}
	s, err := NewStore(db, Options{Now: c.now})
	if err != nil {
		t.Fatal(err)
	}
	return s, db, c
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func factsDoc(osRelease string, proxmox bool) []byte {
	return []byte(fmt.Sprintf(`{"os_release":%q,"uname":"","hostname":"","uptime":"","proxmox":%t}`, b64(osRelease), proxmox))
}

// fullID returns a valid 64-digit container ID ending in n.
func fullID(n int) string { return fmt.Sprintf("%064x", n+1) }

// dockerDoc builds a docker.list result with one container per image.
func dockerDoc(version string, images ...string) []byte {
	var lines []string
	for i, img := range images {
		lines = append(lines, strings.Join([]string{fullID(i), fmt.Sprintf("c%d", i), img, "running", "Up 1 hour", "", "", "", "", ""}, "\t"))
	}
	return []byte(fmt.Sprintf(`{"format":"docker-ps-v1","phase":"done","present":true,"version":%q,"containers":%q}`,
		b64(version), b64(strings.Join(lines, "\n"))))
}

// unitsDoc builds a service.list result; each unit is "name load".
func unitsDoc(units ...string) []byte {
	var lines []string
	for _, u := range units {
		name, load, _ := strings.Cut(u, " ")
		lines = append(lines, fmt.Sprintf("%s %s active running Some unit", name, load))
	}
	return []byte(fmt.Sprintf(`{"format":"systemd-units-v1","units":%q}`, b64(strings.Join(lines, "\n"))))
}

func gpuDoc(names ...string) []byte {
	var lines []string
	for i, n := range names {
		lines = append(lines, fmt.Sprintf("%d, GPU-12345678-1234-1234-1234-1234567890a%d, 00000000:65:00.%d, %s, 1, 2, 3, 40, 50.5", i, i, i, n))
	}
	return []byte(fmt.Sprintf(`{"format":"gpu-status-v1","phase":"done","present":true,"gpus":%q}`, b64(strings.Join(lines, "\n"))))
}

var host1 = Target{Kind: TargetHost, HostID: "h1"}

func mustEntry(t *testing.T, s *Store, key Key) Entry {
	t.Helper()
	e, err := s.Entry(context.Background(), key)
	if err != nil {
		t.Fatalf("entry %s: %v", key, err)
	}
	return e
}

func queueKeys(t *testing.T, s *Store) []string {
	t.Helper()
	q, err := s.UnknownQueue(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range q {
		out = append(out, string(e.Key))
	}
	return out
}

func countRows(t *testing.T, db *sql.DB, table string) int {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestUnknownImageCreatesObservedEntryInQueue(t *testing.T) {
	s, _, _ := newTestStore(t)
	ctx := context.Background()
	rep, err := s.IngestDockerList(ctx, host1, dockerDoc("27.1.1", "docker.io/library/postgres:16", "ghcr.io/acme/widgetd:1.2@sha256:"+strings.Repeat("a", 64)), t0)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Observed != 3 || rep.Created != 3 || rep.Limited != 0 {
		t.Fatalf("report %+v", rep)
	}
	if e := mustEntry(t, s, "postgres"); e.State != StateKnown || e.Display == "" {
		t.Errorf("postgres entry %+v", e)
	}
	if e := mustEntry(t, s, "docker"); e.State != StateKnown {
		t.Errorf("docker entry %+v", e)
	}
	w := mustEntry(t, s, "widgetd")
	if w.State != StateObserved || w.Display != "" || w.FirstHost != "h1" || w.IconSHA != "" {
		t.Errorf("widgetd entry %+v", w)
	}
	q, err := s.UnknownQueue(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(q) != 1 || q[0].Key != "widgetd" || q[0].Observations != 1 || q[0].Hosts != 1 || !q[0].LastSeen.Equal(t0) {
		t.Fatalf("queue %+v", q)
	}
	obs, err := s.Observations(ctx, "h1")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]Observation{
		"docker":   {Target: host1, Version: "27.1.1", Identifier: "docker"},
		"postgres": {Target: Target{Kind: TargetContainer, HostID: "h1", Ref: fullID(0)}, Version: "16", Identifier: "docker.io/library/postgres:16"},
		"widgetd":  {Target: Target{Kind: TargetContainer, HostID: "h1", Ref: fullID(1)}, Version: "1.2"},
	}
	if len(obs) != len(want) {
		t.Fatalf("observations %+v", obs)
	}
	for _, o := range obs {
		w, ok := want[string(o.Key)]
		if !ok || o.Target != w.Target || o.Version != w.Version || o.Source != SourceDockerList ||
			(w.Identifier != "" && o.Identifier != w.Identifier) || !o.FirstSeen.Equal(t0) || !o.LastSeen.Equal(t0) {
			t.Errorf("observation %+v, want %+v", o, w)
		}
	}
}

func TestObservationsNeverCreatePlacements(t *testing.T) {
	s, db, _ := newTestStore(t)
	ctx := context.Background()
	tables := []string{"pve_service_placements", "assets", "hosts", "ip_entries", "net_endpoints"}
	before := map[string]int{}
	for _, tb := range tables {
		before[tb] = countRows(t, db, tb)
	}
	if _, err := s.IngestCoreFacts(ctx, host1, factsDoc("ID=debian\nVERSION_ID=\"12\"\n", false), t0); err != nil {
		t.Fatal(err)
	}
	if _, err := s.IngestDockerList(ctx, host1, dockerDoc("27", "nginx:1", "acme/thing"), t0); err != nil {
		t.Fatal(err)
	}
	if _, err := s.IngestServiceList(ctx, host1, unitsDoc("nginx.service loaded", "acme-agent.service loaded"), t0); err != nil {
		t.Fatal(err)
	}
	if _, err := s.IngestGPUStatus(ctx, host1, gpuDoc("NVIDIA RTX A6000"), t0); err != nil {
		t.Fatal(err)
	}
	for _, tb := range tables {
		if n := countRows(t, db, tb); n != before[tb] {
			t.Errorf("%s rows %d -> %d", tb, before[tb], n)
		}
	}
	if n := countRows(t, db, "software_observations"); n == 0 {
		t.Error("no observations recorded")
	}
}

func TestCoreFactsRecordsOperatingSystem(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name, osr   string
		proxmox     bool
		key, ver    string
		wantNothing bool
	}{
		{name: "debian", osr: "PRETTY_NAME=\"Debian GNU/Linux 12\"\nID=debian\nVERSION_ID=\"12\"\n", key: "debian", ver: "12"},
		{name: "ubuntu quoted", osr: "ID='ubuntu'\nVERSION_ID=24.04\n", key: "ubuntu", ver: "24.04"},
		{name: "proxmox drops debian version", osr: "ID=debian\nVERSION_ID=\"12\"\n", proxmox: true, key: "proxmox-ve"},
		{name: "unknown os is observed", osr: "ID=acmeos\nVERSION_ID=3\n", key: "acmeos", ver: "3"},
		{name: "no ID", osr: "NAME=x\n", wantNothing: true},
		{name: "empty", osr: "", wantNothing: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, _, _ := newTestStore(t)
			rep, err := s.IngestCoreFacts(ctx, host1, factsDoc(tc.osr, tc.proxmox), t0)
			if err != nil {
				t.Fatal(err)
			}
			obs, err := s.Observations(ctx, "h1")
			if err != nil {
				t.Fatal(err)
			}
			if tc.wantNothing {
				if len(obs) != 0 || rep.Observed != 0 {
					t.Fatalf("observations %+v", obs)
				}
				return
			}
			if len(obs) != 1 || string(obs[0].Key) != tc.key || obs[0].Version != tc.ver || obs[0].Source != SourceCoreFacts {
				t.Fatalf("observations %+v", obs)
			}
		})
	}
}

func TestServiceListSkipsUnitsThatAreNotLoaded(t *testing.T) {
	s, _, _ := newTestStore(t)
	ctx := context.Background()
	rep, err := s.IngestServiceList(ctx, host1, unitsDoc(
		"postgresql@16-main.service loaded", "postgresql.service loaded",
		"ghost.service not-found", "acme-agent.service loaded"), t0)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Observed != 3 || rep.Skipped != 1 {
		t.Fatalf("report %+v", rep)
	}
	obs, err := s.Observations(ctx, "h1")
	if err != nil {
		t.Fatal(err)
	}
	keys := map[Key]bool{}
	for _, o := range obs {
		keys[o.Key] = true
	}
	if len(obs) != 2 || !keys["postgres"] || !keys["acme-agent"] || keys["ghost"] {
		t.Fatalf("observations %+v", obs)
	}
	if got := queueKeys(t, s); len(got) != 1 || got[0] != "acme-agent" {
		t.Fatalf("queue %v", got)
	}
}

func TestGPUStatusRecordsNVIDIA(t *testing.T) {
	ctx := context.Background()
	s, _, _ := newTestStore(t)
	if _, err := s.IngestGPUStatus(ctx, host1, gpuDoc("NVIDIA RTX A6000", "NVIDIA RTX A6000"), t0); err != nil {
		t.Fatal(err)
	}
	obs, err := s.Observations(ctx, "h1")
	if err != nil {
		t.Fatal(err)
	}
	if len(obs) != 1 || obs[0].Key != "nvidia" || obs[0].Identifier != "NVIDIA RTX A6000" || obs[0].Source != SourceGPUStatus {
		t.Fatalf("observations %+v", obs)
	}
	for _, doc := range []string{
		`{"format":"gpu-status-v1","phase":"done","present":false}`,
		`{"format":"gpu-status-v1","phase":"precheck","reason":"no driver"}`,
	} {
		s2, _, _ := newTestStore(t)
		rep, err := s2.IngestGPUStatus(ctx, host1, []byte(doc), t0)
		if err != nil || rep != (IngestReport{}) {
			t.Errorf("%s: %+v %v", doc, rep, err)
		}
	}
}

func TestDockerWithoutDaemonRecordsNothing(t *testing.T) {
	s, db, _ := newTestStore(t)
	ctx := context.Background()
	for _, doc := range []string{
		`{"format":"docker-ps-v1","phase":"done","present":false}`,
		`{"format":"docker-ps-v1","phase":"precheck","reason":"daemon down"}`,
	} {
		if _, err := s.IngestDockerList(ctx, host1, []byte(doc), t0); err != nil {
			t.Fatal(err)
		}
	}
	if n := countRows(t, db, "software_catalog"); n != 0 {
		t.Fatalf("catalog rows %d", n)
	}
}

func TestMalformedResultsAreRejected(t *testing.T) {
	s, db, _ := newTestStore(t)
	ctx := context.Background()
	huge := make([]byte, MaxResultSize+1)
	bigOSR := fmt.Sprintf(`{"os_release":%q,"proxmox":false}`, b64(strings.Repeat("A", maxOSReleaseSize+10)))
	for _, tc := range []struct {
		name   string
		ingest func(context.Context, Target, []byte, time.Time) (IngestReport, error)
		doc    []byte
	}{
		{"facts not json", s.IngestCoreFacts, []byte(`{`)},
		{"facts bad base64", s.IngestCoreFacts, []byte(`{"os_release":"!!!"}`)},
		{"facts invalid utf8", s.IngestCoreFacts, []byte(fmt.Sprintf(`{"os_release":%q}`, base64.StdEncoding.EncodeToString([]byte{'I', 'D', '=', 0xff})))},
		{"facts os-release too large", s.IngestCoreFacts, []byte(bigOSR)},
		{"facts oversize", s.IngestCoreFacts, huge},
		{"docker wrong format", s.IngestDockerList, []byte(`{"format":"docker-ps-v2","phase":"done"}`)},
		{"docker bad base64", s.IngestDockerList, []byte(`{"format":"docker-ps-v1","phase":"done","present":true,"containers":"%%"}`)},
		{"docker oversize", s.IngestDockerList, huge},
		{"units wrong format", s.IngestServiceList, []byte(`{"format":"x","units":""}`)},
		{"units oversize", s.IngestServiceList, huge},
		{"gpu wrong format", s.IngestGPUStatus, []byte(`{"format":"gpu-status-v0","phase":"done"}`)},
		{"gpu oversize", s.IngestGPUStatus, huge},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.ingest(ctx, host1, tc.doc, t0)
			if !errors.Is(err, ErrInvalidResult) {
				t.Fatalf("err %v, want ErrInvalidResult", err)
			}
		})
	}
	if n := countRows(t, db, "software_catalog"); n != 0 {
		t.Fatalf("catalog rows %d after malformed input", n)
	}
}

func TestInvalidTargetsAreRejected(t *testing.T) {
	s, _, _ := newTestStore(t)
	ctx := context.Background()
	doc := factsDoc("ID=debian\n", false)
	for _, tc := range []struct {
		name string
		t    Target
	}{
		{"empty host", Target{Kind: TargetHost}},
		{"host with ref", Target{Kind: TargetHost, HostID: "h1", Ref: "x"}},
		{"long host", Target{Kind: TargetHost, HostID: strings.Repeat("h", 64)}},
		{"host with space", Target{Kind: TargetHost, HostID: "h 1"}},
		{"guest without ref", Target{Kind: TargetGuest, HostID: "h1"}},
		{"guest ref control", Target{Kind: TargetGuest, HostID: "h1", Ref: "pve/1\n"}},
		{"container target for facts", Target{Kind: TargetContainer, HostID: "h1", Ref: fullID(1)}},
		{"bad kind", Target{Kind: "vm", HostID: "h1"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := s.IngestCoreFacts(ctx, tc.t, doc, t0); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("err %v", err)
			}
		})
	}
	if _, err := s.IngestCoreFacts(ctx, Target{Kind: TargetGuest, HostID: "h1", Ref: "pve-a/101"}, doc, t0); err != nil {
		t.Fatalf("guest target: %v", err)
	}
	if _, err := s.IngestCoreFacts(ctx, host1, doc, time.Time{}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("zero time: %v", err)
	}
}

func TestHostileIdentifierIsStoredAsCleanText(t *testing.T) {
	s, _, _ := newTestStore(t)
	ctx := context.Background()
	id := "\u202eevil\u0007os" + strings.Repeat("x", 400)
	if _, err := s.IngestCoreFacts(ctx, host1, factsDoc("ID="+id+"\nVERSION_ID=1\u200f\n", false), t0); err != nil {
		t.Fatal(err)
	}
	obs, err := s.Observations(ctx, "h1")
	if err != nil || len(obs) != 1 {
		t.Fatalf("%+v %v", obs, err)
	}
	o := obs[0]
	if _, err := NewKey(string(o.Key)); err != nil {
		t.Errorf("key %q: %v", o.Key, err)
	}
	if len(o.Identifier) > maxIdentifierLen || strings.ContainsAny(o.Identifier, "\u202e\u0007") || strings.ContainsRune(o.Version, '\u200f') {
		t.Errorf("identifier %q version %q not cleaned", o.Identifier, o.Version)
	}
}

func TestCleanText(t *testing.T) {
	for _, tc := range []struct {
		in    string
		limit int
		want  string
	}{
		{"plain", 64, "plain"},
		{" padded ", 64, "padded"},
		{"a\x00b", 64, "a�b"},
		{"bad\xffutf8", 64, "bad�utf8"},
		{"rtl\u202eoverride", 64, "rtl�override"},
		{strings.Repeat("ä", 10), 7, strings.Repeat("ä", 3)}, // cut at a rune boundary
		{strings.Repeat("x", 10_000), 8, "xxxxxxxx"},
	} {
		if got := cleanText(tc.in, tc.limit); got != tc.want {
			t.Errorf("cleanText(%q, %d) = %q, want %q", tc.in, tc.limit, got, tc.want)
		}
	}
}

func TestQueueEntriesArePerHostCapped(t *testing.T) {
	s, _, _ := newTestStore(t)
	s.maxQueuePerHost = 2
	ctx := context.Background()
	rep, err := s.IngestServiceList(ctx, host1, unitsDoc("a1.service loaded", "a2.service loaded", "a3.service loaded", "nginx.service loaded"), t0)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Created != 3 || rep.Limited != 1 || rep.Observed != 3 {
		t.Fatalf("report %+v", rep)
	}
	// Another host still gets its own share, and may observe existing
	// entries without limit.
	rep, err = s.IngestServiceList(ctx, Target{Kind: TargetHost, HostID: "h2"}, unitsDoc("a3.service loaded", "a1.service loaded"), t0)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Created != 1 || rep.Limited != 0 || rep.Observed != 2 {
		t.Fatalf("second host report %+v", rep)
	}
}

func TestObservationAndCatalogCaps(t *testing.T) {
	ctx := context.Background()
	s, _, _ := newTestStore(t)
	s.maxObsPerHost = 2
	rep, err := s.IngestDockerList(ctx, host1, dockerDoc("27", "nginx", "redis"), t0)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Observed != 2 || rep.Limited != 1 {
		t.Fatalf("observation cap report %+v", rep)
	}
	// Refreshing existing rows is not limited.
	rep, err = s.IngestDockerList(ctx, host1, dockerDoc("28", "nginx"), t0.Add(time.Hour))
	if err != nil || rep.Observed != 2 || rep.Limited != 0 {
		t.Fatalf("refresh report %+v %v", rep, err)
	}

	s2, db2, _ := newTestStore(t)
	s2.maxCatalog = 1
	rep, err = s2.IngestServiceList(ctx, host1, unitsDoc("a1.service loaded", "nginx.service loaded"), t0)
	if err != nil || rep.Created != 1 || rep.Limited != 1 {
		t.Fatalf("catalog cap report %+v %v", rep, err)
	}
	if n := countRows(t, db2, "software_catalog"); n != 1 {
		t.Fatalf("catalog rows %d", n)
	}
}

func TestOlderResultDoesNotOverwriteNewer(t *testing.T) {
	s, _, _ := newTestStore(t)
	ctx := context.Background()
	if _, err := s.IngestCoreFacts(ctx, host1, factsDoc("ID=debian\nVERSION_ID=12\n", false), t0); err != nil {
		t.Fatal(err)
	}
	if _, err := s.IngestCoreFacts(ctx, host1, factsDoc("ID=debian\nVERSION_ID=13\n", false), t0.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.IngestCoreFacts(ctx, host1, factsDoc("ID=debian\nVERSION_ID=11\n", false), t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	obs, _ := s.Observations(ctx, "h1")
	if len(obs) != 1 || obs[0].Version != "13" || !obs[0].FirstSeen.Equal(t0) || !obs[0].LastSeen.Equal(t0.Add(2*time.Hour)) {
		t.Fatalf("observations %+v", obs)
	}
	n, err := s.PruneObservations(ctx, t0.Add(3*time.Hour))
	if err != nil || n != 1 {
		t.Fatalf("prune %d %v", n, err)
	}
	if _, err := s.Entry(ctx, "debian"); err != nil {
		t.Fatalf("prune removed the catalog entry: %v", err)
	}
}

func TestSeedKeyPromotesUntouchedObservedEntry(t *testing.T) {
	s, db, _ := newTestStore(t)
	ctx := context.Background()
	// Entries created before the seed map knew the key.
	for _, k := range []string{"postgres", "nginx"} {
		if _, err := db.Exec(`INSERT INTO software_catalog (key, state, created_at, updated_at) VALUES (?, 'observed', 1, 1)`, k); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Ignore(ctx, "admin", "nginx"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.IngestDockerList(ctx, host1, dockerDoc("27", "postgres:16", "nginx:1"), t0); err != nil {
		t.Fatal(err)
	}
	if e := mustEntry(t, s, "postgres"); e.State != StateKnown || e.Display == "" {
		t.Errorf("postgres %+v", e)
	}
	if e := mustEntry(t, s, "nginx"); e.State != StateIgnored {
		t.Errorf("admin decision overridden: %+v", e)
	}
}

func auditActions(t *testing.T, s *Store) []string {
	t.Helper()
	recs, err := s.AuditTrail(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for i := len(recs) - 1; i >= 0; i-- {
		out = append(out, recs[i].Action+" "+recs[i].Subject+" by "+recs[i].Actor)
	}
	return out
}

func seedUnknown(t *testing.T, s *Store, units ...string) {
	t.Helper()
	var docs []string
	for _, u := range units {
		docs = append(docs, u+".service loaded")
	}
	if _, err := s.IngestServiceList(context.Background(), host1, unitsDoc(docs...), t0); err != nil {
		t.Fatal(err)
	}
}

func TestRenameConfirmsEntryAndIsAudited(t *testing.T) {
	s, _, c := newTestStore(t)
	ctx := context.Background()
	seedUnknown(t, s, "widgetd")
	c.t = t0.Add(time.Minute)
	if err := s.Rename(ctx, "alice", "widgetd", "Widget Daemon"); err != nil {
		t.Fatal(err)
	}
	e := mustEntry(t, s, "widgetd")
	if e.Display != "Widget Daemon" || e.State != StateKnown || e.UpdatedBy != "alice" || !e.UpdatedAt.Equal(c.t) {
		t.Fatalf("entry %+v", e)
	}
	if q := queueKeys(t, s); len(q) != 0 {
		t.Fatalf("queue %v", q)
	}
	if got := auditActions(t, s); len(got) != 1 || got[0] != "rename widgetd by alice" {
		t.Fatalf("audit %v", got)
	}
	for _, tc := range []struct {
		name, actor, display string
		key                  Key
		want                 error
	}{
		{"empty display", "alice", "", "widgetd", ErrInvalidInput},
		{"control char", "alice", "Wid\nget", "widgetd", ErrInvalidInput},
		{"bidi", "alice", "Wid\u202eget", "widgetd", ErrInvalidInput},
		{"too long", "alice", strings.Repeat("w", maxDisplayLen+1), "widgetd", ErrInvalidInput},
		{"empty actor", "", "W", "widgetd", ErrInvalidInput},
		{"bad key", "alice", "W", "Widget", ErrInvalidKey},
		{"missing", "alice", "W", "nope", ErrNotFound},
	} {
		if err := s.Rename(ctx, tc.actor, tc.key, tc.display); !errors.Is(err, tc.want) {
			t.Errorf("%s: err %v, want %v", tc.name, err, tc.want)
		}
	}
	if got := auditActions(t, s); len(got) != 1 {
		t.Fatalf("refused changes were audited: %v", got)
	}
}

func TestMergeResolvesOneLevelAndIsAudited(t *testing.T) {
	s, _, _ := newTestStore(t)
	ctx := context.Background()
	seedUnknown(t, s, "pg-a", "pg-b", "pgsql")
	if err := s.Merge(ctx, "alice", "pg-a", "pg-b"); err != nil {
		t.Fatal(err)
	}
	// Merging pg-b re-points pg-a, so merges stay one level deep.
	if err := s.Merge(ctx, "alice", "pg-b", "pgsql"); err != nil {
		t.Fatal(err)
	}
	for _, k := range []Key{"pg-a", "pg-b"} {
		if e := mustEntry(t, s, k); e.MergedInto != "pgsql" {
			t.Errorf("%s merged into %q", k, e.MergedInto)
		}
		r, err := s.Resolve(ctx, k)
		if err != nil || r.Key != "pgsql" {
			t.Errorf("resolve %s: %+v %v", k, r, err)
		}
	}
	if q := queueKeys(t, s); len(q) != 1 || q[0] != "pgsql" {
		t.Fatalf("queue %v", q)
	}
	for _, tc := range []struct {
		name       string
		from, into Key
		want       error
	}{
		{"self", "pgsql", "pgsql", ErrInvalidMerge},
		{"into merged", "pgsql", "pg-a", ErrInvalidMerge},
		{"missing into", "pgsql", "nope", ErrNotFound},
		{"missing from", "nope", "pgsql", ErrNotFound},
	} {
		if err := s.Merge(ctx, "alice", tc.from, tc.into); !errors.Is(err, tc.want) {
			t.Errorf("%s: err %v, want %v", tc.name, err, tc.want)
		}
	}
	if err := s.Rename(ctx, "alice", "pg-a", "X"); !errors.Is(err, ErrMerged) {
		t.Errorf("rename merged: %v", err)
	}
	if got := auditActions(t, s); len(got) != 2 || got[0] != "merge pg-a by alice" || got[1] != "merge pg-b by alice" {
		t.Fatalf("audit %v", got)
	}
}

func TestIgnoredEntryStaysOutOfQueue(t *testing.T) {
	s, _, _ := newTestStore(t)
	ctx := context.Background()
	seedUnknown(t, s, "noise")
	if err := s.Ignore(ctx, "bob", "noise"); err != nil {
		t.Fatal(err)
	}
	seedUnknown(t, s, "noise")
	if _, err := s.IngestServiceList(ctx, Target{Kind: TargetHost, HostID: "h2"}, unitsDoc("noise.service loaded"), t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if e := mustEntry(t, s, "noise"); e.State != StateIgnored {
		t.Fatalf("entry %+v", e)
	}
	if q := queueKeys(t, s); len(q) != 0 {
		t.Fatalf("queue %v", q)
	}
	if got := auditActions(t, s); len(got) != 1 || got[0] != "ignore noise by bob" {
		t.Fatalf("audit %v", got)
	}
	if err := s.Ignore(ctx, "bob", "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("ignore missing: %v", err)
	}
}

var (
	shaA = strings.Repeat("a", 64)
	shaB = strings.Repeat("b", 64)
)

func TestRegisterIconValidatesSource(t *testing.T) {
	s, _, _ := newTestStore(t)
	ctx := context.Background()
	created, err := s.RegisterIcon(ctx, "alice", shaA, IconURL, "https://upload.wikimedia.org/x.png")
	if err != nil || !created {
		t.Fatalf("register: %v %v", created, err)
	}
	created, err = s.RegisterIcon(ctx, "bob", shaA, IconUpload, "")
	if err != nil || created {
		t.Fatalf("re-register: %v %v", created, err)
	}
	ic, err := s.Icon(ctx, shaA)
	if err != nil || ic.Kind != IconURL || ic.AddedBy != "alice" || ic.SourceURL != "https://upload.wikimedia.org/x.png" {
		t.Fatalf("icon %+v %v", ic, err)
	}
	for _, tc := range []struct {
		name, sha string
		kind      IconSourceKind
		url       string
	}{
		{"upload with url", shaB, IconUpload, "https://example.org/a.png"},
		{"http", shaB, IconURL, "http://example.org/a.png"},
		{"javascript", shaB, IconURL, "javascript:alert(1)"},
		{"userinfo", shaB, IconURL, "https://u:p@example.org/a.png"},
		{"no host", shaB, IconURL, "https:///a.png"},
		{"space", shaB, IconURL, "https://example.org/a b.png"},
		{"control", shaB, IconURL, "https://example.org/\x00"},
		{"empty url", shaB, IconURL, ""},
		{"too long", shaB, IconURL, "https://example.org/" + strings.Repeat("a", maxSourceURLLen)},
		{"bad kind", shaB, "crawler", ""},
		{"upper hex", strings.ToUpper(shaB), IconUpload, ""},
		{"short hash", "abc", IconUpload, ""},
		{"path hash", "../" + shaB[3:], IconUpload, ""},
	} {
		if _, err := s.RegisterIcon(ctx, "alice", tc.sha, tc.kind, tc.url); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("%s: err %v", tc.name, err)
		}
	}
	if got := auditActions(t, s); len(got) != 1 || got[0] != "icon_register "+shaA+" by alice" {
		t.Fatalf("audit %v", got)
	}
}

func TestIconChangesKeepHistoryAndRollBack(t *testing.T) {
	s, _, c := newTestStore(t)
	ctx := context.Background()
	seedUnknown(t, s, "widgetd")
	for _, sha := range []string{shaA, shaB} {
		if _, err := s.RegisterIcon(ctx, "alice", sha, IconUpload, ""); err != nil {
			t.Fatal(err)
		}
	}
	subj := IconSubject{Kind: SubjectCatalog, ID: "widgetd"}
	if err := s.SetIcon(ctx, "alice", subj, shaA); err != nil {
		t.Fatal(err)
	}
	c.t = c.t.Add(time.Minute)
	if err := s.SetIcon(ctx, "bob", subj, shaB); err != nil {
		t.Fatal(err)
	}
	// Setting the current icon again is not a change.
	if err := s.SetIcon(ctx, "bob", subj, shaB); err != nil {
		t.Fatal(err)
	}
	h, err := s.IconHistory(ctx, subj, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(h) != 2 || h[0].SHA != shaB || h[0].PrevSHA != shaA || h[0].ChangedBy != "bob" ||
		h[1].SHA != shaA || h[1].PrevSHA != "" || h[1].ChangedBy != "alice" {
		t.Fatalf("history %+v", h)
	}
	// One-click rollback of the newest change returns to A.
	if err := s.RollbackIcon(ctx, "carol", subj, h[0].ID); err != nil {
		t.Fatal(err)
	}
	if e := mustEntry(t, s, "widgetd"); e.IconSHA != shaA || e.UpdatedBy != "carol" {
		t.Fatalf("after rollback %+v", e)
	}
	h, _ = s.IconHistory(ctx, subj, 0)
	if len(h) != 3 || h[0].SHA != shaA || h[0].PrevSHA != shaB || h[0].RollbackOf != h[1].ID {
		t.Fatalf("history after rollback %+v", h)
	}
	// The rollback can itself be rolled back, and the first change too
	// (back to the generic symbol).
	if err := s.RollbackIcon(ctx, "carol", subj, h[0].ID); err != nil {
		t.Fatal(err)
	}
	if e := mustEntry(t, s, "widgetd"); e.IconSHA != shaB {
		t.Fatalf("after second rollback %+v", e)
	}
	if err := s.RollbackIcon(ctx, "carol", subj, h[2].ID); err != nil {
		t.Fatal(err)
	}
	if e := mustEntry(t, s, "widgetd"); e.IconSHA != "" {
		t.Fatalf("after rollback to generic %+v", e)
	}
	want := []string{
		"icon_register " + shaA + " by alice", "icon_register " + shaB + " by alice",
		"icon_set widgetd by alice", "icon_set widgetd by bob",
		"icon_rollback widgetd by carol", "icon_rollback widgetd by carol", "icon_rollback widgetd by carol",
	}
	if got := auditActions(t, s); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("audit\n got %v\nwant %v", got, want)
	}
}

func TestIconChangesRefuseBadInput(t *testing.T) {
	s, _, _ := newTestStore(t)
	ctx := context.Background()
	seedUnknown(t, s, "widgetd", "other")
	if err := s.Merge(ctx, "alice", "other", "widgetd"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RegisterIcon(ctx, "alice", shaA, IconUpload, ""); err != nil {
		t.Fatal(err)
	}
	cat := IconSubject{Kind: SubjectCatalog, ID: "widgetd"}
	if err := s.SetIcon(ctx, "alice", cat, shaA); err != nil {
		t.Fatal(err)
	}
	h, _ := s.IconHistory(ctx, cat, 0)
	before := len(auditActions(t, s))
	for _, tc := range []struct {
		name string
		err  error
		want error
	}{
		{"unregistered icon", s.SetIcon(ctx, "alice", cat, shaB), ErrNotFound},
		{"bad hash", s.SetIcon(ctx, "alice", cat, "zz"), ErrInvalidInput},
		{"missing key", s.SetIcon(ctx, "alice", IconSubject{Kind: SubjectCatalog, ID: "nope"}, shaA), ErrNotFound},
		{"merged key", s.SetIcon(ctx, "alice", IconSubject{Kind: SubjectCatalog, ID: "other"}, shaA), ErrMerged},
		{"bad subject kind", s.SetIcon(ctx, "alice", IconSubject{Kind: "host", ID: "h1"}, shaA), ErrInvalidInput},
		{"missing asset", s.SetIcon(ctx, "alice", IconSubject{Kind: SubjectAsset, ID: "nas-1"}, shaA), ErrNotFound},
		{"bad asset id", s.SetIcon(ctx, "alice", IconSubject{Kind: SubjectAsset, ID: "nas 1"}, shaA), ErrInvalidInput},
		{"bad actor", s.SetIcon(ctx, "\x1b[31m", cat, ""), ErrInvalidInput},
		{"rollback of other subject", s.RollbackIcon(ctx, "alice", IconSubject{Kind: SubjectCatalog, ID: "other"}, h[0].ID), ErrNotFound},
		{"rollback unknown id", s.RollbackIcon(ctx, "alice", cat, 9999), ErrNotFound},
		{"rollback zero id", s.RollbackIcon(ctx, "alice", cat, 0), ErrInvalidInput},
	} {
		if !errors.Is(tc.err, tc.want) {
			t.Errorf("%s: err %v, want %v", tc.name, tc.err, tc.want)
		}
	}
	if after := len(auditActions(t, s)); after != before {
		t.Fatalf("refused changes were audited: %d -> %d", before, after)
	}
	if e := mustEntry(t, s, "widgetd"); e.IconSHA != shaA {
		t.Fatalf("icon changed by refused calls: %+v", e)
	}
}

func TestAssetIconOverrideHistoryAndRollback(t *testing.T) {
	s, db, _ := newTestStore(t)
	ctx := context.Background()
	if _, err := db.Exec(`INSERT INTO assets (id, name, kind, updated_at) VALUES ('nas-1', 'NAS', 'nas', 1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RegisterIcon(ctx, "alice", shaA, IconUpload, ""); err != nil {
		t.Fatal(err)
	}
	subj := IconSubject{Kind: SubjectAsset, ID: "nas-1"}
	if err := s.SetIcon(ctx, "alice", subj, shaA); err != nil {
		t.Fatal(err)
	}
	if sha, err := s.AssetIcon(ctx, "nas-1"); err != nil || sha != shaA {
		t.Fatalf("override %q %v", sha, err)
	}
	if err := s.SetIcon(ctx, "bob", subj, ""); err != nil {
		t.Fatal(err)
	}
	if sha, err := s.AssetIcon(ctx, "nas-1"); err != nil || sha != "" {
		t.Fatalf("cleared override %q %v", sha, err)
	}
	h, err := s.IconHistory(ctx, subj, 0)
	if err != nil || len(h) != 2 || h[0].SHA != "" || h[0].PrevSHA != shaA {
		t.Fatalf("history %+v %v", h, err)
	}
	if err := s.RollbackIcon(ctx, "carol", subj, h[0].ID); err != nil {
		t.Fatal(err)
	}
	if sha, _ := s.AssetIcon(ctx, "nas-1"); sha != shaA {
		t.Fatalf("override after rollback %q", sha)
	}
	// Rolling back the set (to no override) is audited as a rollback too.
	if err := s.RollbackIcon(ctx, "carol", subj, h[1].ID); err != nil {
		t.Fatal(err)
	}
	if sha, _ := s.AssetIcon(ctx, "nas-1"); sha != "" {
		t.Fatalf("override after rollback to none %q", sha)
	}
	want := []string{
		"icon_register " + shaA + " by alice", "asset_icon_set nas-1 by alice", "asset_icon_clear nas-1 by bob",
		"icon_rollback nas-1 by carol", "icon_rollback nas-1 by carol",
	}
	if got := auditActions(t, s); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("audit %v", got)
	}
	recs, err := s.AuditTrail(ctx, 2)
	if err != nil {
		t.Fatal(err)
	}
	if d := recs[1].Detail; d != fmt.Sprintf("asset: none -> %s (rollback of change %d)", shaA, h[0].ID) {
		t.Fatalf("rollback detail %q", d)
	}
	// A catalog key with the same name is a different subject.
	if h, _ := s.IconHistory(ctx, IconSubject{Kind: SubjectCatalog, ID: "nas-1"}, 0); len(h) != 0 {
		t.Fatalf("catalog history leaked: %+v", h)
	}
}

func TestRollbackToCurrentIconIsStillRecorded(t *testing.T) {
	s, db, c := newTestStore(t)
	ctx := context.Background()
	seedUnknown(t, s, "widgetd")
	if _, err := db.Exec(`INSERT INTO assets (id, name, kind, updated_at) VALUES ('nas-1', 'NAS', 'nas', 1)`); err != nil {
		t.Fatal(err)
	}
	for _, sha := range []string{shaA, shaB} {
		if _, err := s.RegisterIcon(ctx, "alice", sha, IconUpload, ""); err != nil {
			t.Fatal(err)
		}
	}
	for _, subj := range []IconSubject{{Kind: SubjectCatalog, ID: "widgetd"}, {Kind: SubjectAsset, ID: "nas-1"}} {
		t.Run(string(subj.Kind), func(t *testing.T) {
			// A -> B -> A: rolling back the first change (none -> A)
			// would give "none"; rolling back B -> A gives B. Rolling
			// back A -> B gives A, which is the current icon.
			for _, sha := range []string{shaA, shaB, shaA} {
				c.t = c.t.Add(time.Minute)
				if err := s.SetIcon(ctx, "alice", subj, sha); err != nil {
					t.Fatal(err)
				}
			}
			h, err := s.IconHistory(ctx, subj, 0)
			if err != nil || len(h) != 3 {
				t.Fatalf("history %+v %v", h, err)
			}
			before := len(auditActions(t, s))
			if err := s.RollbackIcon(ctx, "carol", subj, h[1].ID); err != nil {
				t.Fatal(err)
			}
			after, err := s.IconHistory(ctx, subj, 0)
			if err != nil || len(after) != 4 {
				t.Fatalf("no-op rollback not in history: %+v %v", after, err)
			}
			if r := after[0]; r.SHA != shaA || r.PrevSHA != shaA || r.RollbackOf != h[1].ID || r.ChangedBy != "carol" {
				t.Fatalf("no-op rollback row %+v", r)
			}
			recs, err := s.AuditTrail(ctx, 1)
			if err != nil {
				t.Fatal(err)
			}
			if got := len(auditActions(t, s)); got != before+1 {
				t.Fatalf("audit rows %d -> %d", before, got)
			}
			want := fmt.Sprintf("%s: %s -> %s (rollback of change %d, no change)", subj.Kind, shaA, shaA, h[1].ID)
			if a := recs[0]; a.Action != "icon_rollback" || a.Subject != subj.ID || a.Actor != "carol" || a.Detail != want {
				t.Fatalf("audit %+v, want detail %q", a, want)
			}
			// The icon itself did not change.
			var cur string
			if subj.Kind == SubjectCatalog {
				cur = mustEntry(t, s, "widgetd").IconSHA
			} else {
				cur, _ = s.AssetIcon(ctx, "nas-1")
			}
			if cur != shaA {
				t.Fatalf("icon %q after no-op rollback", cur)
			}
		})
	}
	// SetIcon to the current icon stays a non-event.
	before := len(auditActions(t, s))
	if err := s.SetIcon(ctx, "alice", IconSubject{Kind: SubjectCatalog, ID: "widgetd"}, shaA); err != nil {
		t.Fatal(err)
	}
	if got := len(auditActions(t, s)); got != before {
		t.Fatalf("no-op SetIcon audited: %d -> %d", before, got)
	}
}

func TestAssetDeleteClearsIconOverride(t *testing.T) {
	s, db, _ := newTestStore(t)
	ctx := context.Background()
	if _, err := db.Exec(`INSERT INTO assets (id, name, kind, updated_at) VALUES ('nas-1', 'NAS', 'nas', 1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RegisterIcon(ctx, "alice", shaA, IconUpload, ""); err != nil {
		t.Fatal(err)
	}
	subj := IconSubject{Kind: SubjectAsset, ID: "nas-1"}
	if err := s.SetIcon(ctx, "alice", subj, shaA); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`DELETE FROM assets WHERE id = 'nas-1'`); err != nil {
		t.Fatal(err)
	}
	if sha, err := s.AssetIcon(ctx, "nas-1"); err != nil || sha != "" {
		t.Fatalf("override survived asset delete: %q %v", sha, err)
	}
	// A new asset that reuses the ID does not inherit the override.
	if _, err := db.Exec(`INSERT INTO assets (id, name, kind, updated_at) VALUES ('nas-1', 'Other', 'nas', 2)`); err != nil {
		t.Fatal(err)
	}
	if sha, err := s.AssetIcon(ctx, "nas-1"); err != nil || sha != "" {
		t.Fatalf("reused asset ID inherited override %q %v", sha, err)
	}
	// The history is kept.
	if h, err := s.IconHistory(ctx, subj, 0); err != nil || len(h) != 1 {
		t.Fatalf("history %+v %v", h, err)
	}
}

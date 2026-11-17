// SPDX-License-Identifier: AGPL-3.0-or-later

package discovery

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/nebula-operation-station/nebula-operation-station/internal/discoveryjob"
	"github.com/nebula-operation-station/nebula-operation-station/internal/ipam"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
)

type fixture struct {
	s    *Store
	ip   *ipam.Store
	now  time.Time
	pool discoveryjob.Spool
}

func setup(t *testing.T, hosts map[netip.Addr][]string) *fixture {
	t.Helper()
	db, err := serverdb.Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	sp := discoveryjob.Spool{Dir: t.TempDir()}
	for _, d := range []string{sp.JobsDir(), sp.ResultsDir()} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	h := func(context.Context) (map[netip.Addr][]string, error) { return hosts, nil }
	ip := ipam.New(db, h)
	f := &fixture{ip: ip, now: time.Unix(1_800_000_000, 0), pool: sp}
	f.s = New(db, sp, ip, h, slog.New(slog.NewTextHandler(io.Discard, nil)))
	f.s.now = func() time.Time { return f.now }
	if err := ip.SaveNetwork(context.Background(), ipam.Network{ID: "lan", Name: "LAN", Prefix: netip.MustParsePrefix("192.168.10.0/24")}); err != nil {
		t.Fatal(err)
	}
	return f
}

// answer writes the result discovery would write for the queued job.
func (f *fixture) answer(t *testing.T, id string, ok bool, hosts ...discoveryjob.Host) {
	t.Helper()
	if err := f.pool.WriteResult(discoveryjob.Result{Format: discoveryjob.ResultFormat, Job: id, StartedAt: f.now.Unix(), FinishedAt: f.now.Unix(),
		OK: ok, Error: map[bool]string{false: "nmap failed: boom"}[ok], Hosts: hosts}); err != nil {
		t.Fatal(err)
	}
}

func TestSubmitChecksTargets(t *testing.T) {
	ctx := context.Background()
	f := setup(t, nil)
	for _, req := range []Request{
		{Mode: discoveryjob.ModePing, Targets: []string{"10.0.0.0/24"}},           // unknown network
		{Mode: discoveryjob.ModePing, Targets: []string{"192.168.0.0/16"}},        // larger than the known one
		{Mode: discoveryjob.ModePorts, Targets: []string{"192.168.10.5"}},         // no ports
		{Mode: discoveryjob.ModeCustom, Targets: []string{"192.168.10.5"}},        // no options
		{Mode: "--script", Targets: []string{"192.168.10.5"}},                     // unknown mode
		{Mode: discoveryjob.ModePing, Targets: []string{"-iL", "/etc/shadow"}},    // not targets
		{Mode: discoveryjob.ModePing, Targets: []string{"192.168.10.0/24 -oN x"}}, // not a target
	} {
		var ve *ValidationError
		if _, err := f.s.Submit(ctx, "admin", req); !errors.As(err, &ve) {
			t.Errorf("%+v: %v", req, err)
		}
	}
	j, err := f.s.Submit(ctx, "admin", Request{Mode: discoveryjob.ModePorts, Targets: []string{"192.168.10.0/25", "192.168.10.200"}, Ports: "443, 22"})
	if err != nil {
		t.Fatal(err)
	}
	jobs, _, _ := f.pool.PendingJobs()
	if len(jobs) != 1 || jobs[0].ID != j.ID || jobs[0].Ports != "22,443" || jobs[0].Targets[1] != "192.168.10.200" {
		t.Fatalf("%+v", jobs)
	}
	if err := f.s.Cancel(ctx, j.ID); err != nil {
		t.Fatal(err)
	}
	if jobs, _, _ := f.pool.PendingJobs(); len(jobs) != 0 {
		t.Fatal("cancelled job still in the spool")
	}
	if err := f.s.Cancel(ctx, j.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	// At most MaxQueued scans wait.
	for i := 0; i < MaxQueued; i++ {
		if _, err := f.s.Submit(ctx, "admin", Request{Mode: discoveryjob.ModePing, Targets: []string{"192.168.10.1"}}); err != nil {
			t.Fatal(i, err)
		}
	}
	var ve *ValidationError
	if _, err := f.s.Submit(ctx, "admin", Request{Mode: discoveryjob.ModePing, Targets: []string{"192.168.10.1"}}); !errors.As(err, &ve) {
		t.Fatal("queue not bounded", err)
	}
	// Without the spool, discovery is not installed.
	_ = os.RemoveAll(f.pool.JobsDir())
	if _, err := f.s.Submit(ctx, "admin", Request{Mode: discoveryjob.ModePing, Targets: []string{"192.168.10.0/24"}}); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
}

func TestPollClassifyImport(t *testing.T) {
	ctx := context.Background()
	f := setup(t, map[netip.Addr][]string{netip.MustParseAddr("192.168.10.50"): {"web1"}})
	a := func(s string) netip.Addr { return netip.MustParseAddr(s) }
	for _, as := range []ipam.Asset{
		{ID: "nas", Name: "NAS", Kind: ipam.KindNAS, MAC: "aa:aa:aa:aa:aa:01", Addresses: []netip.Addr{a("192.168.10.21")}},
		{ID: "printer", Name: "Printer", Kind: ipam.KindPrinter, Addresses: []netip.Addr{a("192.168.10.30")}},
		{ID: "cam", Name: "Cam", Kind: ipam.KindIoT, MAC: "aa:aa:aa:aa:aa:03", Addresses: []netip.Addr{a("192.168.10.31")}},
	} {
		if err := f.ip.SaveAsset(ctx, as); err != nil {
			t.Fatal(err)
		}
	}
	j, err := f.s.Submit(ctx, "admin", Request{Mode: discoveryjob.ModePing, Targets: []string{"192.168.10.0/24"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.s.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	if row, _, _ := f.s.Job(ctx, j.ID); row.State != StateQueued {
		t.Fatal(row.State)
	}
	f.answer(t, j.ID, true,
		discoveryjob.Host{Address: "192.168.10.21", MAC: "AA:AA:AA:AA:AA:01", Hostname: "nas.lan"},                                                                // EXISTING, adds hostname
		discoveryjob.Host{Address: "192.168.10.22", MAC: "aa:aa:aa:aa:aa:01"},                                                                                     // EXISTING, new address
		discoveryjob.Host{Address: "192.168.10.30", MAC: "aa:aa:aa:aa:aa:02"},                                                                                     // POSSIBLE MATCH (asset w/o MAC)
		discoveryjob.Host{Address: "192.168.10.31", MAC: "aa:aa:aa:aa:aa:09"},                                                                                     // CONFLICT (other MAC)
		discoveryjob.Host{Address: "192.168.10.21", MAC: "aa:aa:aa:aa:aa:03"},                                                                                     // dropped duplicate address
		discoveryjob.Host{Address: "192.168.10.40", Hostname: "Box.lan.", Vendor: "ACME", Ports: []discoveryjob.Port{{Port: 22, Protocol: "tcp", State: "open"}}}, // NEW
		discoveryjob.Host{Address: "192.168.10.41"},                                                                                                               // NEW without name
		discoveryjob.Host{Address: "192.168.10.50"},                                                                                                               // POSSIBLE MATCH with host web1
	)
	if err := f.s.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	row, rows, err := f.s.Job(ctx, j.ID)
	if err != nil || row.State != StateDone || row.Hosts != 7 || len(rows) != 7 {
		t.Fatalf("%+v %d %v", row, len(rows), err)
	}
	want := map[string]Class{"192.168.10.21": ClassExisting, "192.168.10.22": ClassExisting, "192.168.10.30": ClassPossible,
		"192.168.10.31": ClassConflict, "192.168.10.40": ClassNew, "192.168.10.41": ClassNew, "192.168.10.50": ClassPossible}
	for _, r := range rows {
		if r.Class != want[r.Address] {
			t.Errorf("%s: %s (%s)", r.Address, r.Class, r.Reason)
		}
	}
	if jobs, _, _ := f.pool.PendingJobs(); len(jobs) != 0 {
		t.Fatal("job file kept after the result was read")
	}
	// The sightings feed IPAM.
	views, _, _ := f.ip.Status(ctx, "lan")
	st := map[string]ipam.Status{}
	for _, v := range views {
		st[v.Address.String()] = v.Status
	}
	if st["192.168.10.40"] != ipam.Discovered || st["192.168.10.31"] != ipam.Conflict {
		t.Fatalf("ipam %s %s", st["192.168.10.40"], st["192.168.10.31"])
	}
	// A conflict is never imported; the rest is.
	rep, err := f.s.Import(ctx, "admin", j.ID, []string{"192.168.10.31", "10.9.9.9"}, false)
	if err != nil || len(rep.Created)+len(rep.Updated) != 0 || rep.Skipped["192.168.10.31"] == "" || rep.Skipped["10.9.9.9"] == "" {
		t.Fatalf("%+v %v", rep, err)
	}
	rep, err = f.s.Import(ctx, "admin", j.ID, nil, true)
	if err != nil || len(rep.Created) != 3 || len(rep.Updated) != 3 {
		t.Fatalf("%+v %v", rep, err)
	}
	nas, _ := f.ip.Asset(ctx, "nas")
	if nas.Hostname != "nas.lan" || len(nas.Addresses) != 2 {
		t.Fatalf("%+v", nas)
	}
	pr, _ := f.ip.Asset(ctx, "printer")
	if pr.MAC != "aa:aa:aa:aa:aa:02" {
		t.Fatalf("%+v", pr)
	}
	box, err := f.ip.Asset(ctx, "box")
	if err != nil || box.Kind != ipam.KindUnknown || box.Name != "box.lan" || box.Notes != "found by discovery: vendor ACME; open 22/tcp" {
		t.Fatalf("%+v %v", box, err)
	}
	if _, err := f.ip.Asset(ctx, "ip-192-168-10-41"); err != nil {
		t.Fatal(err)
	}
	web, err := f.ip.Asset(ctx, "ip-192-168-10-50")
	if err != nil || web.HostID != "web1" {
		t.Fatalf("%+v %v", web, err)
	}
	// Imported rows are not imported twice.
	rep, _ = f.s.Import(ctx, "admin", j.ID, []string{"192.168.10.40"}, false)
	if rep.Skipped["192.168.10.40"] != "already imported" {
		t.Fatalf("%+v", rep)
	}
}

func TestFailedAndMissingResults(t *testing.T) {
	ctx := context.Background()
	f := setup(t, nil)
	j1, _ := f.s.Submit(ctx, "admin", Request{Mode: discoveryjob.ModePing, Targets: []string{"192.168.10.1"}})
	j2, _ := f.s.Submit(ctx, "admin", Request{Mode: discoveryjob.ModePing, Targets: []string{"192.168.10.2"}})
	f.answer(t, j1.ID, false)
	f.now = f.now.Add(4 * time.Hour)
	if err := f.s.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	r1, _, _ := f.s.Job(ctx, j1.ID)
	r2, _, _ := f.s.Job(ctx, j2.ID)
	if r1.State != StateFailed || r1.Error != "nmap failed: boom" || r2.State != StateFailed || r2.Error == "" {
		t.Fatalf("%+v %+v", r1, r2)
	}
	if _, err := f.s.Import(ctx, "admin", j1.ID, nil, true); err == nil {
		t.Fatal("failed scan imported")
	}
	// Old jobs are pruned.
	f.now = f.now.Add(100 * 24 * time.Hour)
	_ = f.s.Poll(ctx)
	if jobs, _ := f.s.Jobs(ctx, 10); len(jobs) != 0 {
		t.Fatalf("%+v", jobs)
	}
}

func TestSchedules(t *testing.T) {
	ctx := context.Background()
	f := setup(t, nil)
	req := Request{Mode: discoveryjob.ModePing, Targets: []string{"192.168.10.0/24"}}
	if _, err := f.s.CreateSchedule(ctx, "admin", "often", req, 10*time.Minute, time.Time{}); err == nil {
		t.Fatal("interval under an hour accepted")
	}
	if _, err := f.s.CreateSchedule(ctx, "admin", "bad", Request{Mode: discoveryjob.ModePing, Targets: []string{"10.0.0.1"}}, time.Hour, time.Time{}); err == nil {
		t.Fatal("unknown network accepted")
	}
	hourly, err := f.s.CreateSchedule(ctx, "admin", "hourly", req, time.Hour, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	once, err := f.s.CreateSchedule(ctx, "admin", "tonight", req, 0, f.now.Add(2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.s.RunDue(ctx); err != nil {
		t.Fatal(err)
	}
	jobs, _ := f.s.Jobs(ctx, 10)
	if len(jobs) != 1 || jobs[0].ScheduleID != hourly.ID {
		t.Fatalf("%+v", jobs)
	}
	f.now = f.now.Add(2*time.Hour + time.Minute)
	_ = f.s.RunDue(ctx)
	jobs, _ = f.s.Jobs(ctx, 10)
	if len(jobs) != 3 {
		t.Fatalf("%d jobs", len(jobs))
	}
	scheds, _ := f.s.Schedules(ctx)
	for _, sc := range scheds {
		if sc.ID == once.ID && sc.Enabled || sc.ID == hourly.ID && !sc.NextAt.After(f.now) {
			t.Fatalf("%+v", sc)
		}
	}
	f.now = f.now.Add(5 * time.Hour)
	_ = f.s.RunDue(ctx)
	if jobs, _ = f.s.Jobs(ctx, 10); len(jobs) != 4 {
		t.Fatalf("missed runs are not caught up one by one: %d", len(jobs))
	}
	if err := f.s.DeleteSchedule(ctx, hourly.ID); err != nil {
		t.Fatal(err)
	}
}

// longHostname is a valid DNS name of exactly 200 bytes: longer than the
// IPAM name limit (128), within the hostname limit (253).
func longHostname() string {
	return strings.Repeat("a", 50) + "." + strings.Repeat("b", 50) + "." + strings.Repeat("c", 50) + "." + strings.Repeat("d", 47)
}

func TestLongHostnameImports(t *testing.T) {
	ctx := context.Background()
	f := setup(t, nil)
	name := longHostname()
	if len(name) != 200 {
		t.Fatalf("test name has %d bytes", len(name))
	}
	j, err := f.s.Submit(ctx, "admin", Request{Mode: discoveryjob.ModePing, Targets: []string{"192.168.10.0/24"}})
	if err != nil {
		t.Fatal(err)
	}
	f.answer(t, j.ID, true, discoveryjob.Host{Address: "192.168.10.60", Hostname: name})
	if err := f.s.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	rep, err := f.s.Import(ctx, "admin", j.ID, nil, true)
	if err != nil || len(rep.Skipped) != 0 || len(rep.Created) != 1 {
		t.Fatalf("%+v %v", rep, err)
	}
	a, err := f.ip.Asset(ctx, rep.Created[0])
	if err != nil {
		t.Fatal(err)
	}
	if a.Hostname != name {
		t.Errorf("hostname %q: the full name is kept", a.Hostname)
	}
	if len(a.Name) == 0 || len(a.Name) > 128 || !strings.HasPrefix(name, a.Name) {
		t.Errorf("name %q: want a prefix of the hostname within 128 bytes", a.Name)
	}
}

// assetIDPattern is ipam's ID pattern (ipam idRe).
var assetIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)

func TestAssetIDIsValidAndDerivedFromInput(t *testing.T) {
	long253 := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)
	if len(long253) != 253 {
		t.Fatalf("test name has %d bytes", len(long253))
	}
	for _, tc := range []struct {
		name string
		row  Row
		want string
	}{
		{"uppercase hostname", Row{Host: discoveryjob.Host{Address: "192.168.10.5", Hostname: "NAS.Lan"}}, "nas"},
		{"ipv6 without hostname", Row{Host: discoveryjob.Host{Address: "2001:db8::1"}}, "ip-2001-db8--1"},
		{"253-byte hostname", Row{Host: discoveryjob.Host{Address: "192.168.10.6", Hostname: long253}}, strings.Repeat("a", 56)},
		{"only special characters", Row{Host: discoveryjob.Host{Address: "192.168.10.7", Hostname: "!!--..__"}}, "ip-192-168-10-7"},
		{"empty hostname", Row{Host: discoveryjob.Host{Address: "192.168.10.8"}}, "ip-192-168-10-8"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := &matcher{ids: map[string]bool{}}
			got := m.assetID(tc.row)
			if got != tc.want {
				t.Errorf("assetID = %q, want %q", got, tc.want)
			}
			if !assetIDPattern.MatchString(got) {
				t.Errorf("assetID %q does not match the ipam pattern", got)
			}
		})
	}
}

func TestAssetIDIsDistinctPerAddress(t *testing.T) {
	m := &matcher{ids: map[string]bool{}}
	seen := map[string]string{}
	for _, r := range []Row{
		{Host: discoveryjob.Host{Address: "192.168.10.5", Hostname: "nas.lan"}},
		{Host: discoveryjob.Host{Address: "192.168.10.6", Hostname: "nas.lan"}},
		{Host: discoveryjob.Host{Address: "192.168.10.7", Hostname: "NAS.LAN"}},
		{Host: discoveryjob.Host{Address: "192.168.10.8"}},
		{Host: discoveryjob.Host{Address: "192.168.10.9", Hostname: "!!"}},
		{Host: discoveryjob.Host{Address: "2001:db8::5"}},
	} {
		id := m.assetID(r)
		if other, dup := seen[id]; dup {
			t.Errorf("%s and %s both get ID %q", r.Address, other, id)
		}
		seen[id] = r.Address
	}
	if len(seen) != 6 {
		t.Fatalf("%d IDs for 6 addresses", len(seen))
	}
}

// checkNote reports why a note is not plain text within ipam's limit: no
// control, format or line/paragraph separator characters, valid UTF-8.
func checkNote(note string) error {
	if len(note) > maxAssetNote {
		return fmt.Errorf("note is %d bytes", len(note))
	}
	if !utf8.ValidString(note) {
		return errors.New("note is not UTF-8")
	}
	for _, c := range note {
		if unicode.IsControl(c) || unicode.Is(unicode.Cf, c) || c == 0x2028 || c == 0x2029 {
			return fmt.Errorf("note has the character %U", c)
		}
	}
	return nil
}

func TestNoteForIsPlainAndWithinIPAMLimit(t *testing.T) {
	ctx := context.Background()
	f := setup(t, nil)
	many := make([]discoveryjob.Port, 100)
	for i := range many {
		many[i] = discoveryjob.Port{Port: 1000 + i, Protocol: strings.Repeat("p", 300), State: "open"}
	}
	lineSep := string(rune(0x2028))
	paraSep := string(rune(0x2029))
	zeroWidth := string(rune(0x200b))
	nbsp := string(rune(0xa0))
	for i, r := range []Row{
		{Host: discoveryjob.Host{Address: "192.168.10.9"}},
		{Host: discoveryjob.Host{Address: "192.168.10.9", Vendor: "ACME", OS: "Linux"}},
		{Host: discoveryjob.Host{Address: "192.168.10.9", Vendor: "Müller" + lineSep + "x\x07" + zeroWidth + "GmbH", OS: "a\tb\nc" + nbsp + "d"}},
		{Host: discoveryjob.Host{Address: "192.168.10.9", Vendor: strings.Repeat("ü", 300), OS: strings.Repeat(paraSep, 200)}},
		{Host: discoveryjob.Host{Address: "192.168.10.9", Ports: many}},
		{Host: discoveryjob.Host{Address: "192.168.10.9", Vendor: "bad\xffutf8"}},
	} {
		note := noteFor(r)
		if err := checkNote(note); err != nil {
			t.Errorf("row %d: %v: %q", i, err, note)
		}
		// The real check: ipam takes the note.
		if err := f.ip.SaveAsset(ctx, ipam.Asset{ID: fmt.Sprintf("note-%d", i), Name: "note", Kind: ipam.KindUnknown, Notes: note}); err != nil {
			t.Errorf("row %d: ipam refuses the note: %v", i, err)
		}
	}
}

func FuzzAssetIDAndNote(f *testing.F) {
	f.Add("nas.lan", "192.168.10.21", "aa:aa:aa:aa:aa:01")
	f.Add("", "2001:db8::1", "")
	f.Add("NAS.LAN", "::ffff:192.168.10.1", "AA-BB-CC-DD-EE-FF")
	f.Add(strings.Repeat("a", 253), "192.168.10.1", "zz")
	f.Add("!!..--", "not an address", "\x00")
	f.Fuzz(func(t *testing.T, host, addr, mac string) {
		r := Row{Host: discoveryjob.Host{Address: addr, MAC: mac, Hostname: host, Vendor: host, OS: mac}}
		m := &matcher{ids: map[string]bool{}}
		id := m.assetID(r)
		if !assetIDPattern.MatchString(id) {
			t.Fatalf("assetID %q does not match the ipam pattern", id)
		}
		if again := m.assetID(r); again == id || !assetIDPattern.MatchString(again) {
			t.Fatalf("second assetID %q after %q", again, id)
		}
		if err := checkNote(noteFor(r)); err != nil {
			t.Fatal(err)
		}
		if name := assetName(r); len(name) > maxAssetName || !utf8.ValidString(name) {
			t.Fatalf("name %q", name)
		}
	})
}

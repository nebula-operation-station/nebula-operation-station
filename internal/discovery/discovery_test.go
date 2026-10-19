// SPDX-License-Identifier: AGPL-3.0-or-later

package discovery

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

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

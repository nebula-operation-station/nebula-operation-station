// SPDX-License-Identifier: AGPL-3.0-or-later

package permit

import (
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/schedgrant"
)

// package.list_installed (ADR 0011 D3) runs under a read lease; nothing
// that merely shares its prefix is admitted.
func TestPackageListInstalledInReadOnlyAllowlist(t *testing.T) {
	if !InReadOnlyAllowlist("package.list_installed") {
		t.Fatal("package.list_installed is not in the read-only allowlist")
	}
	for _, id := range []string{"package.list_installed.x", "package.list_install", "package.install_all", "package.refresh", "Package.list_installed"} {
		if InReadOnlyAllowlist(id) {
			t.Errorf("%q is in the read-only allowlist", id)
		}
	}
	if schedgrant.IsTelemetryAction("package.list_installed") {
		t.Fatal("package.list_installed must not ride the telemetry rate profile")
	}
}

// Its own cost limit is 6 h per host; every other action keeps the
// grant's interval.
func TestReadActionMinInterval(t *testing.T) {
	if got := ReadActionMinInterval("package.list_installed"); got != 6*time.Hour {
		t.Fatalf("package.list_installed floor %s, want 6h", got)
	}
	if PackageListInstalledMinInterval > schedgrant.MaxInterval {
		t.Fatal("the floor exceeds what the read store retains")
	}
	for _, id := range []string{"core.facts", "package.list_updates", "net.facts", "", "package.list_installed "} {
		if got := ReadActionMinInterval(id); got != 0 {
			t.Errorf("%q floor %s, want 0", id, got)
		}
	}
}

// A read grant that names package.list_installed parses with the ordinary
// 15-minute interval: the 6 h floor is enforced per run, not by refusing
// grants that also cover cheaper reads.
func TestReadGrantAcceptsPackageListInstalled(t *testing.T) {
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	ph, err := canonical.HashParameters(params)
	if err != nil {
		t.Fatal(err)
	}
	d := readGrantDocAt(t, now, DefaultReadGrantLifetime)
	d.Actions = append(d.Actions, ReadGrantAction{ActionID: "package.list_installed", ModuleVersion: "1.0.0",
		ArtifactSHA256: hexSum(artifact), ParametersHash: ph})
	if _, _, _, err := ParseReadGrant(readGrantRaw(t, d), now); err != nil {
		t.Fatalf("package.list_installed grant refused: %v", err)
	}
	d.RateProfile = schedgrant.TelemetryReadProfile
	if _, _, _, err := ParseReadGrant(readGrantRaw(t, d), now); err == nil {
		t.Fatal("package.list_installed accepted under the telemetry profile")
	}
}

// The 6 h floor holds per host across triggers and overlapping grants,
// while other actions and other hosts are unaffected.
func TestPackageListInstalledSixHourFloor(t *testing.T) {
	e, le := newLeaseEnv(t, ModeStandard)
	now := e.clk.Now()
	actions := []string{"core.facts", "package.list_installed"}
	ga := approveReadGrant(t, e, readGrantRaw(t, readGrantDocWith(t, rgID, now, DefaultReadGrantLifetime, 24, actions)))
	gb := approveReadGrant(t, e, readGrantRaw(t, readGrantDocWith(t, rgID2, now, DefaultReadGrantLifetime, 24, actions)))
	inst := readRun("dockerflux", fpA)
	inst.ActionID = "package.list_installed"
	if _, err := e.auth.AuthorizeReadRun(ga.ID, "i1", TriggerOnDemand, inst); err != nil {
		t.Fatal(err)
	}
	// 16 minutes clear the ordinary floor but not the 6 h one, on either grant.
	e.clk.Add(16 * time.Minute)
	_, err := e.auth.AuthorizeReadRun(ga.ID, "i2", TriggerOnDemand, inst)
	wantCode(t, err, CodeLeaseBudget)
	_, err = e.auth.AuthorizeReadRun(gb.ID, "i3", TriggerOnDemand, inst)
	wantCode(t, err, CodeLeaseBudget)
	if n := len(le.hostRes["dockerflux"]); n != 1 {
		t.Fatalf("%d reservations, want 1 (denials spend nothing)", n)
	}
	// A cheaper read on the same host keeps its own floor.
	if _, err := e.auth.AuthorizeReadRun(ga.ID, "c1", TriggerOnDemand, readRun("dockerflux", fpA)); err != nil {
		t.Fatalf("core.facts after 16 minutes: %v", err)
	}
	// One second short of 6 h is still too soon; 6 h is enough.
	e.clk.Add(6*time.Hour - 16*time.Minute - time.Second)
	_, err = e.auth.AuthorizeReadRun(gb.ID, "i4", TriggerOnDemand, inst)
	wantCode(t, err, CodeLeaseBudget)
	e.clk.Add(time.Second)
	if _, err := e.auth.AuthorizeReadRun(gb.ID, "i5", TriggerOnDemand, inst); err != nil {
		t.Fatalf("after 6 h: %v", err)
	}
	// Another host has its own floor.
	other := readRun("strompi", fpB)
	other.ActionID = "package.list_installed"
	if _, err := e.auth.AuthorizeReadRun(ga.ID, "o1", TriggerOnDemand, other); err != nil {
		t.Fatalf("other host: %v", err)
	}
}

// The floor also applies to scheduled runs and to a grant whose own
// interval is longer: the larger of both wins.
func TestPackageListInstalledFloorKeepsLongerGrantInterval(t *testing.T) {
	e, _ := newLeaseEnv(t, ModeStandard)
	d := readGrantDocWith(t, rgID, e.clk.Now(), DefaultReadGrantLifetime, 24, []string{"package.list_installed"})
	d.Trigger = TriggerBoth
	d.MinIntervalS = int64(12 * time.Hour / time.Second)
	g := approveReadGrant(t, e, readGrantRaw(t, d))
	inst := readRun("dockerflux", fpA)
	inst.ActionID = "package.list_installed"
	if _, err := e.auth.AuthorizeReadRun(g.ID, "s1", TriggerScheduled, inst); err != nil {
		t.Fatal(err)
	}
	e.clk.Add(7 * time.Hour)
	_, err := e.auth.AuthorizeReadRun(g.ID, "s2", TriggerScheduled, inst)
	wantCode(t, err, CodeLeaseBudget)
	e.clk.Add(5 * time.Hour)
	if _, err := e.auth.AuthorizeReadRun(g.ID, "s3", TriggerScheduled, inst); err != nil {
		t.Fatalf("after 12 h: %v", err)
	}
}

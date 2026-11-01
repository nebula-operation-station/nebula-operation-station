// SPDX-License-Identifier: AGPL-3.0-or-later

package permit

import (
	"strings"
	"testing"
	"time"
)

var (
	metricsNode   = ProviderMetricsTarget{Node: "pve1", Kind: MetricsKindNode}
	metricsGuest  = ProviderMetricsTarget{Node: "pve1", Kind: MetricsKindQEMU, VMID: 101, Generation: 3}
	metricsGuest2 = ProviderMetricsTarget{Node: "pve1", Kind: MetricsKindLXC, VMID: 102, Generation: 1}
)

func telemetryDocAt(now time.Time, id, trigger string, budget int64, targets ...ProviderMetricsTarget) ReadGrantDoc {
	if len(targets) == 0 {
		targets = []ProviderMetricsTarget{metricsNode, metricsGuest}
	}
	return ReadGrantDoc{
		Grant: ReadGrantFormat, ID: id, Issuer: "root",
		CreatedUnix: now.Unix(), ExpiryUnix: now.Add(DefaultReadGrantLifetime).Unix(),
		Trigger: trigger, MinIntervalS: 10, RunBudget: budget, RateProfile: ProviderTelemetryProfile,
		Actions: []ReadGrantAction{},
		ProviderTargets: []ProviderTarget{{RemoteID: "pve-1", TrustPin: pvePinA, TrustGeneration: 1, CredentialVersion: 1,
			Methods: []string{ProviderMethodMetrics}, MetricsTargets: targets}},
	}
}

func metricsRead(target ProviderMetricsTarget, live bool) ProviderMetricsRead {
	return ProviderMetricsRead{RemoteID: "pve-1", TrustPin: pvePinA, TrustGeneration: 1, CredentialVersion: 1, Target: target, Live: live}
}

func TestProviderTelemetryGrantDocValidation(t *testing.T) {
	now := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	for _, trigger := range []string{TriggerScheduled, TriggerOnDemand, TriggerBoth} {
		if _, _, _, err := ParseReadGrant(readGrantRaw(t, telemetryDocAt(now, rgID, trigger, 4096)), now); err != nil {
			t.Fatalf("valid %s telemetry grant rejected: %v", trigger, err)
		}
	}
	ordinary := readGrantDocAt(t, now, DefaultReadGrantLifetime)
	cases := map[string]func(d *ReadGrantDoc){
		"ssh action":           func(d *ReadGrantDoc) { d.Actions = ordinary.Actions },
		"ssh target":           func(d *ReadGrantDoc) { d.Targets = ordinary.Targets },
		"interval below 10s":   func(d *ReadGrantDoc) { d.MinIntervalS = 9 },
		"budget zero":          func(d *ReadGrantDoc) { d.RunBudget = 0 },
		"budget above max":     func(d *ReadGrantDoc) { d.RunBudget = MaxProviderTelemetryBudget + 1 },
		"no remotes":           func(d *ReadGrantDoc) { d.ProviderTargets = nil },
		"bad pin":              func(d *ReadGrantDoc) { d.ProviderTargets[0].TrustPin = "abc" },
		"credential version 0": func(d *ReadGrantDoc) { d.ProviderTargets[0].CredentialVersion = 0 },
		"inventory method":     func(d *ReadGrantDoc) { d.ProviderTargets[0].Methods = []string{ProviderMethodNodes} },
		"extra method": func(d *ReadGrantDoc) {
			d.ProviderTargets[0].Methods = []string{ProviderMethodMetrics, ProviderMethodNodes}
		},
		"no metrics targets":  func(d *ReadGrantDoc) { d.ProviderTargets[0].MetricsTargets = nil },
		"node with vmid":      func(d *ReadGrantDoc) { d.ProviderTargets[0].MetricsTargets[0].VMID = 100 },
		"node with gen":       func(d *ReadGrantDoc) { d.ProviderTargets[0].MetricsTargets[0].Generation = 1 },
		"guest without gen":   func(d *ReadGrantDoc) { d.ProviderTargets[0].MetricsTargets[1].Generation = 0 },
		"guest vmid too low":  func(d *ReadGrantDoc) { d.ProviderTargets[0].MetricsTargets[1].VMID = 99 },
		"guest gen too large": func(d *ReadGrantDoc) { d.ProviderTargets[0].MetricsTargets[1].Generation = 1 << 49 },
		"unknown kind":        func(d *ReadGrantDoc) { d.ProviderTargets[0].MetricsTargets[1].Kind = "openvz" },
		"bad node name":       func(d *ReadGrantDoc) { d.ProviderTargets[0].MetricsTargets[0].Node = "../pve" },
		"duplicate target": func(d *ReadGrantDoc) {
			dup := d.ProviderTargets[0].MetricsTargets[1]
			dup.Generation++
			d.ProviderTargets[0].MetricsTargets = append(d.ProviderTargets[0].MetricsTargets, dup)
		},
		"too many targets": func(d *ReadGrantDoc) {
			for i := 0; i < MaxProviderMetricsTargets; i++ {
				d.ProviderTargets[0].MetricsTargets = append(d.ProviderTargets[0].MetricsTargets,
					ProviderMetricsTarget{Node: "pve2", Kind: MetricsKindQEMU, VMID: uint64(200 + i), Generation: 1})
			}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			d := telemetryDocAt(now, rgID, TriggerBoth, 240)
			d.ProviderTargets[0].MetricsTargets = append([]ProviderMetricsTarget(nil), d.ProviderTargets[0].MetricsTargets...)
			mutate(&d)
			if _, _, _, err := ParseReadGrant(readGrantRaw(t, d), now); err == nil {
				t.Fatal("malformed telemetry grant accepted")
			}
		})
	}
	// An inventory provider grant cannot carry metrics targets.
	inv := providerDocAt(now, rgID, 240)
	inv.ProviderTargets[0].MetricsTargets = []ProviderMetricsTarget{metricsNode}
	if _, _, _, err := ParseReadGrant(readGrantRaw(t, inv), now); err == nil {
		t.Fatal("inventory provider grant with metrics targets accepted")
	}
}

func TestProviderMetricsRequiresExactTarget(t *testing.T) {
	e, _ := newLeaseEnv(t, ModeStandard)
	if _, err := e.auth.AuthorizeProviderMetrics(metricsRead(metricsGuest, true)); err == nil {
		t.Fatal("metrics read authorized without any grant")
	} else {
		wantCode(t, err, CodeLeaseNotCovered)
	}
	approveReadGrant(t, e, readGrantRaw(t, telemetryDocAt(e.clk.Now(), rgID, TriggerBoth, 240)))
	claim, err := e.auth.AuthorizeProviderMetrics(metricsRead(metricsGuest, true))
	if err != nil {
		t.Fatalf("covered metrics read denied: %v", err)
	}
	if claim.GrantID != rgID || claim.Check() != nil {
		t.Fatalf("claim %+v does not check", claim)
	}
	recreated := metricsGuest
	recreated.Generation++
	migrated := metricsGuest
	migrated.Node = "pve2"
	pinChanged := metricsRead(metricsNode, true)
	pinChanged.TrustPin = pvePinB
	rotated := metricsRead(metricsNode, true)
	rotated.CredentialVersion = 2
	for name, r := range map[string]ProviderMetricsRead{
		"target not granted":     metricsRead(metricsGuest2, true),
		"guest recreated":        metricsRead(recreated, true),
		"guest on another node":  metricsRead(migrated, true),
		"pin changed":            pinChanged,
		"credential was rotated": rotated,
	} {
		if _, err := e.auth.AuthorizeProviderMetrics(r); err == nil {
			t.Fatalf("%s: metrics read authorized", name)
		} else {
			wantCode(t, err, CodeLeaseNotCovered)
		}
	}
	bad := metricsRead(ProviderMetricsTarget{Node: "pve1", Kind: MetricsKindNode, VMID: 7}, true)
	if _, err := e.auth.AuthorizeProviderMetrics(bad); err == nil {
		t.Fatal("malformed metrics target authorized")
	} else {
		wantCode(t, err, CodeLeaseInvalid)
	}
}

// Telemetry and inventory provider grants confer no authority on each
// other, and neither confers SSH authority.
func TestProviderTelemetryAndInventoryGrantsAreDisjoint(t *testing.T) {
	e, _ := newLeaseEnv(t, ModeStandard)
	approveReadGrant(t, e, readGrantRaw(t, providerDocAt(e.clk.Now(), rgID, 240)))
	if _, err := e.auth.AuthorizeProviderMetrics(metricsRead(metricsNode, false)); err == nil {
		t.Fatal("inventory provider grant authorized a metrics read")
	}
	g := approveReadGrant(t, e, readGrantRaw(t, telemetryDocAt(e.clk.Now(), rgID2, TriggerBoth, 240)))
	if _, err := e.auth.AuthorizeProviderRead(providerRead(ProviderMethodNodes)); err != nil {
		t.Fatalf("inventory read with both grants: %v", err)
	}
	// Only the inventory grant (rgID) may have paid for the inventory read.
	if n, err := e.auth.RevokeProviderGrants("pve-1", "test"); err != nil || n != 2 {
		t.Fatalf("revoke = %d, %v; want both provider grants revoked", n, err)
	}
	if _, err := e.auth.AuthorizeReadRun(g.ID, "e1", TriggerOnDemand, readRun("dockerflux", fpA)); err == nil {
		t.Fatal("telemetry grant authorized an SSH run")
	}
}

func TestProviderMetricsTriggerSelectsPath(t *testing.T) {
	e, _ := newLeaseEnv(t, ModeStandard)
	approveReadGrant(t, e, readGrantRaw(t, telemetryDocAt(e.clk.Now(), rgID, TriggerScheduled, 240)))
	if _, err := e.auth.AuthorizeProviderMetrics(metricsRead(metricsNode, true)); err == nil {
		t.Fatal("scheduled-only grant authorized a live read")
	} else {
		wantCode(t, err, CodeLeaseNotCovered)
	}
	if _, err := e.auth.AuthorizeProviderMetrics(metricsRead(metricsNode, false)); err != nil {
		t.Fatalf("history read under a scheduled grant: %v", err)
	}
	approveReadGrant(t, e, readGrantRaw(t, telemetryDocAt(e.clk.Now(), rgID2, TriggerOnDemand, 240)))
	if _, err := e.auth.AuthorizeProviderMetrics(metricsRead(metricsNode, true)); err != nil {
		t.Fatalf("live read under an on-demand grant: %v", err)
	}
}

// Live reads keep a 10-second and history reads a 5-minute interval per
// target, independently of each other, and all share the remote budget.
func TestProviderMetricsIntervalsAndBudget(t *testing.T) {
	e, _ := newLeaseEnv(t, ModeStandard)
	approveReadGrant(t, e, readGrantRaw(t, telemetryDocAt(e.clk.Now(), rgID, TriggerBoth, 6)))
	read := func(target ProviderMetricsTarget, live bool) error {
		_, err := e.auth.AuthorizeProviderMetrics(metricsRead(target, live))
		return err
	}
	if err := read(metricsGuest, true); err != nil {
		t.Fatal(err)
	}
	if err := read(metricsGuest, false); err != nil {
		t.Fatalf("history beside live: %v", err)
	}
	wantCode(t, read(metricsGuest, true), CodeLeaseBudget)
	e.clk.Add(ProviderTelemetryLiveInterval)
	if err := read(metricsGuest, true); err != nil {
		t.Fatalf("live after 10 s: %v", err)
	}
	// History keeps its 5-minute floor although min_interval_s is 10.
	wantCode(t, read(metricsGuest, false), CodeLeaseBudget)
	e.clk.Add(ProviderTelemetryHistoryInterval)
	if err := read(metricsGuest, false); err != nil {
		t.Fatalf("history after 5 min: %v", err)
	}
	if err := read(metricsNode, true); err != nil {
		t.Fatal(err)
	}
	if err := read(metricsNode, false); err != nil {
		t.Fatal(err)
	}
	// Six of six requests spent on the one remote.
	e.clk.Add(ProviderTelemetryHistoryInterval)
	wantCode(t, read(metricsGuest, true), CodeLeaseBudget)
}

func TestProviderMetricsClaimLockRevocationAndRecovery(t *testing.T) {
	e, le := newLeaseEnv(t, ModeStandard)
	approveReadGrant(t, e, readGrantRaw(t, telemetryDocAt(e.clk.Now(), rgID, TriggerBoth, 240)))
	claim, err := e.auth.AuthorizeProviderMetrics(metricsRead(metricsNode, true))
	if err != nil {
		t.Fatal(err)
	}
	e.auth.Lock("test")
	if err := claim.Check(); err == nil {
		t.Fatal("metrics claim survived lock")
	}
	if _, err := e.auth.AuthorizeProviderMetrics(metricsRead(metricsGuest, true)); err == nil {
		t.Fatal("metrics read authorized while locked")
	} else {
		wantCode(t, err, CodeLeaseInactive)
	}
	if err := e.auth.ResumeReadDispatch(); err != nil {
		t.Fatal(err)
	}
	claim, err = e.auth.AuthorizeProviderMetrics(metricsRead(metricsGuest, true))
	if err != nil {
		t.Fatal(err)
	}
	le.recovering = true
	if err := claim.Check(); err == nil {
		t.Fatal("metrics claim checked during recovery")
	}
	le.recovering = false
	if n, err := e.auth.RevokeProviderGrants("pve-1", "test"); err != nil || n != 1 {
		t.Fatalf("revoke = %d, %v", n, err)
	}
	if err := claim.Check(); err == nil {
		t.Fatal("metrics claim survived revocation")
	}
	le.setDigest(rgID, strings.Repeat("0", 64))
	if _, err := e.auth.AuthorizeProviderMetrics(metricsRead(metricsGuest, true)); err == nil {
		t.Fatal("tampered telemetry grant authorized a read")
	}
}

// Metrics reads spend their own per-remote counter, so live charts cannot
// starve the inventory collection's approved budget, and vice versa.
func TestProviderMetricsBudgetIsSeparateFromInventory(t *testing.T) {
	e, _ := newLeaseEnv(t, ModeStandard)
	approveReadGrant(t, e, readGrantRaw(t, providerDocAt(e.clk.Now(), rgID, 2)))
	approveReadGrant(t, e, readGrantRaw(t, telemetryDocAt(e.clk.Now(), rgID2, TriggerBoth, 3)))
	for i := 0; i < 3; i++ {
		if _, err := e.auth.AuthorizeProviderMetrics(metricsRead(metricsNode, true)); err != nil {
			t.Fatalf("metrics read %d: %v", i, err)
		}
		e.clk.Add(ProviderTelemetryLiveInterval)
	}
	_, err := e.auth.AuthorizeProviderMetrics(metricsRead(metricsNode, true))
	wantCode(t, err, CodeLeaseBudget)
	for _, m := range []string{ProviderMethodNodes, ProviderMethodGuests} {
		if _, err := e.auth.AuthorizeProviderRead(providerRead(m)); err != nil {
			t.Fatalf("inventory %s after metrics spent their budget: %v", m, err)
		}
	}
	e.clk.Add(time.Minute)
	_, err = e.auth.AuthorizeProviderRead(providerRead(ProviderMethodNodes))
	wantCode(t, err, CodeLeaseBudget)
}

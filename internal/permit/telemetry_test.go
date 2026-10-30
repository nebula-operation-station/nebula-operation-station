// SPDX-License-Identifier: AGPL-3.0-or-later

package permit

import (
	"testing"
	"time"

	"github.com/descope/virtualwebauthn"
	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
)

var telemetryActions = []string{"host.metrics", "filesystem.list", "pci.inventory", "gpu.status", "docker.stats"}

func telemetryDoc(t *testing.T, now time.Time) ReadGrantDoc {
	t.Helper()
	d := readGrantDocWith(t, rgID, now, DefaultReadGrantLifetime, 4096, telemetryActions)
	d.RateProfile, d.MinIntervalS = "telemetry", 10
	return d
}

func telemetryRun(action string) Run {
	r := readRun("dockerflux", fpA)
	r.ActionID = action
	return r
}

func TestTelemetryProfileBoundsAndContract(t *testing.T) {
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	for _, interval := range []int64{10, 300, 900} {
		d := telemetryDoc(t, now)
		d.MinIntervalS = interval
		if _, _, _, err := ParseReadGrant(readGrantRaw(t, d), now); err != nil {
			t.Fatalf("interval %d: %v", interval, err)
		}
	}
	for name, change := range map[string]func(*ReadGrantDoc){
		"too fast":              func(d *ReadGrantDoc) { d.MinIntervalS = 9 },
		"budget overflow":       func(d *ReadGrantDoc) { d.RunBudget = 4097 },
		"zero budget":           func(d *ReadGrantDoc) { d.RunBudget = 0 },
		"ordinary fast":         func(d *ReadGrantDoc) { d.RateProfile = "ordinary"; d.RunBudget = 240 },
		"ordinary large budget": func(d *ReadGrantDoc) { d.RateProfile = "ordinary"; d.MinIntervalS = 900 },
		"no credentials":        func(d *ReadGrantDoc) { d.Credentials = nil },
		"old format":            func(d *ReadGrantDoc) { d.Grant = previousReadGrantFormat },
	} {
		t.Run(name, func(t *testing.T) {
			d := telemetryDoc(t, now)
			change(&d)
			if _, _, _, err := ParseReadGrant(readGrantRaw(t, d), now); err == nil {
				t.Fatal("invalid telemetry accepted")
			}
		})
	}
	for _, action := range []string{"core.facts", "package.list_updates", "docker.check_updates", "image.vulnerabilities", "package.refresh", "docker.logs", "service.restart", "shell.exec"} {
		t.Run(action, func(t *testing.T) {
			d := telemetryDoc(t, now)
			d.Actions[0].ActionID = action
			if _, _, _, err := ParseReadGrant(readGrantRaw(t, d), now); err == nil {
				t.Fatal("non-telemetry or costly action gained fast authority")
			}
		})
	}
	d := telemetryDoc(t, now)
	_, _, first, err := ParseReadGrant(readGrantRaw(t, d), now)
	if err != nil {
		t.Fatal(err)
	}
	d.RunBudget--
	_, _, second, err := ParseReadGrant(readGrantRaw(t, d), now)
	if err != nil || first == second {
		t.Fatalf("budget not digest-bound: %v", err)
	}
	d.MinIntervalS = 300
	_, _, third, err := ParseReadGrant(readGrantRaw(t, d), now)
	if err != nil || second == third {
		t.Fatalf("interval not digest-bound: %v", err)
	}
	d.RateProfile, d.MinIntervalS, d.RunBudget = "ordinary", 900, 240
	if _, _, _, err := ParseReadGrant(readGrantRaw(t, d), now); err != nil {
		t.Fatalf("ordinary telemetry: %v", err)
	}
}

func TestTelemetryLiveAndHistoryFloorsShareBudget(t *testing.T) {
	for _, trigger := range []string{TriggerOnDemand, TriggerScheduled} {
		t.Run(trigger, func(t *testing.T) {
			e, _ := newLeaseEnv(t, ModeStandard)
			d := telemetryDoc(t, e.clk.Now())
			d.RunBudget = 2
			g := approveReadGrant(t, e, readGrantRaw(t, d))
			if _, err := e.auth.AuthorizeReadRun(g.ID, "first", trigger, telemetryRun("host.metrics")); err != nil {
				t.Fatal(err)
			}
			floor := 10 * time.Second
			if trigger == TriggerScheduled {
				floor = 5 * time.Minute
			}
			e.clk.Add(floor - time.Second)
			_, err := e.auth.AuthorizeReadRun(g.ID, "early", trigger, telemetryRun("host.metrics"))
			wantCode(t, err, CodeLeaseBudget)
			e.clk.Add(time.Second)
			if _, err := e.auth.AuthorizeReadRun(g.ID, "boundary", trigger, telemetryRun("host.metrics")); err != nil {
				t.Fatal(err)
			}
			_, err = e.auth.AuthorizeReadRun(g.ID, "over-budget", TriggerOnDemand, telemetryRun("gpu.status"))
			wantCode(t, err, CodeLeaseBudget)
		})
	}
}

func TestTelemetryExactAuthorityAndLifecycle(t *testing.T) {
	for scenario, expected := range map[string]Code{
		"host": CodeLeaseNotCovered, "key": CodeLeaseNotCovered,
		"credential": CodeCredentialMismatch, "action": CodeLeaseNotCovered,
		"version": CodeLeaseNotCovered, "artifact": CodeArtifactMismatch,
		"parameters": CodeParametersMismatch, "risk": CodeGrantInvalid,
		"expiry": CodeLeaseInactive, "revoke": CodeLeaseInactive,
		"lock": CodeLeaseBudget, "restart": CodeLeaseBudget, "storage": CodeStorage,
	} {
		t.Run(scenario, func(t *testing.T) {
			e, store := newLeaseEnv(t, ModeStandard)
			g := approveReadGrant(t, e, readGrantRaw(t, telemetryDoc(t, e.clk.Now())))
			run := telemetryRun("host.metrics")
			claim, err := e.auth.AuthorizeReadRun(g.ID, "queued", TriggerOnDemand, run)
			if err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "host":
				run.HostID = "other"
			case "key":
				run.HostKeyFingerprint = fpB
			case "credential":
				run.CredentialVersion = fpB
			case "action":
				run.ActionID = "package.refresh"
			case "version":
				run.ModuleVersion = "2.0.0"
			case "artifact":
				run.Artifact = []byte("unapproved command")
			case "parameters":
				run.ParametersJSON = []byte(`{"command":"anything"}`)
			case "risk":
				e.risk.setHost("dockerflux", canonical.RiskHigh)
			case "expiry":
				e.clk.Add(DefaultReadGrantLifetime)
			case "revoke":
				if err := e.auth.RevokeReadGrant(g.ID, "admin"); err != nil {
					t.Fatal(err)
				}
			case "lock":
				e.auth.Lock("admin")
			case "restart":
				fresh := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
				fresh.auth.leases = store
				if err := fresh.auth.DispatchReadRun(claim, func() error { t.Fatal("old claim dispatched after restart"); return nil }); err == nil {
					t.Fatal("old claim accepted")
				}
				e = fresh
			case "storage":
				store.failReserve = true
			}
			if scenario == "lock" || scenario == "restart" {
				if err := e.auth.DispatchReadRun(claim, func() error { t.Fatal("paused dispatch"); return nil }); err == nil {
					t.Fatal("paused claim accepted")
				}
				if err := e.auth.ResumeReadDispatch(); err != nil {
					t.Fatal(err)
				}
				_, err := e.auth.AuthorizeReadRun(g.ID, "spent", TriggerOnDemand, run)
				wantCode(t, err, CodeLeaseBudget)
				return
			}
			if scenario == "expiry" || scenario == "revoke" || scenario == "risk" {
				if err := e.auth.DispatchReadRun(claim, func() error { t.Fatal("stale authority dispatched"); return nil }); err == nil {
					t.Fatal("stale claim accepted")
				}
			}
			// A preceding claim must not mask a missing scope check with an
			// interval denial. Each case must fail for its own authorization rule.
			e.clk.Add(11 * time.Second)
			_, err = e.auth.AuthorizeReadRun(g.ID, "denied", TriggerOnDemand, run)
			wantCode(t, err, expected)
		})
	}
}

func TestTelemetryHonorsLongerApprovedInterval(t *testing.T) {
	for _, trigger := range []string{TriggerOnDemand, TriggerScheduled} {
		t.Run(trigger, func(t *testing.T) {
			e, _ := newLeaseEnv(t, ModeStandard)
			d := telemetryDoc(t, e.clk.Now())
			d.MinIntervalS = 600
			g := approveReadGrant(t, e, readGrantRaw(t, d))
			if _, err := e.auth.AuthorizeReadRun(g.ID, "first", trigger, telemetryRun("host.metrics")); err != nil {
				t.Fatal(err)
			}
			e.clk.Add(599 * time.Second)
			_, err := e.auth.AuthorizeReadRun(g.ID, "early", trigger, telemetryRun("host.metrics"))
			wantCode(t, err, CodeLeaseBudget)
			e.clk.Add(time.Second)
			if _, err := e.auth.AuthorizeReadRun(g.ID, "boundary", trigger, telemetryRun("host.metrics")); err != nil {
				t.Fatal(err)
			}
		})
	}
}

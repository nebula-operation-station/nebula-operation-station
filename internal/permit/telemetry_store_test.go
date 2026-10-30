// SPDX-License-Identifier: AGPL-3.0-or-later

package permit_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	"github.com/nebula-operation-station/nebula-operation-station/internal/schedgrant"
	"github.com/nebula-operation-station/nebula-operation-station/internal/webauthnverify"
)

type telemetryPolicy struct{}

func (telemetryPolicy) MinimumRisk(canonical.Request, []canonical.Target) (canonical.Risk, string, error) {
	return canonical.RiskLow, "test reviewed telemetry artifact", nil
}

func TestTelemetryDurableBudgetAcrossGrantsAndRestart(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	open := func() *executordb.DB {
		t.Helper()
		db, err := executordb.Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		return db
	}
	db := open()
	defer func() { _ = db.Close() }()
	start := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	now := start
	newAuthority := func() *permit.Authority {
		t.Helper()
		v, err := webauthnverify.New(webauthnverify.Config{RPID: "telemetry.test", Origins: []string{"https://telemetry.test"}, Counters: db}, nil)
		if err != nil {
			t.Fatal(err)
		}
		a, err := permit.New(permit.Options{Mode: permit.ModeHardened, Verifier: v, Store: db, RiskPolicy: telemetryPolicy{}, Leases: db, Schedules: db, Now: func() time.Time { return now }})
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	auth := newAuthority()
	const fp = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	artifact := []byte("#!/bin/sh\necho telemetry\n")
	sum := sha256.Sum256(artifact)
	ph, err := canonical.HashParameters([]byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	d := permit.ReadGrantDoc{Grant: permit.ReadGrantFormat, ID: "00000000-0000-4000-8000-000000000001", Issuer: "admin", CreatedUnix: now.Unix(), ExpiryUnix: now.Add(24 * time.Hour).Unix(), Trigger: permit.TriggerBoth,
		Targets: []canonical.Target{{HostID: "web", HostKeyFingerprint: fp}}, Credentials: []permit.ReadGrantCredential{{HostID: "web", CredentialRef: "default", CredentialVersion: fp}},
		RateProfile: schedgrant.TelemetryReadProfile, MinIntervalS: 10, RunBudget: 6}
	actions := []string{"host.metrics", "filesystem.list", "pci.inventory", "gpu.status", "docker.stats"}
	for _, action := range actions {
		d.Actions = append(d.Actions, permit.ReadGrantAction{ActionID: action, ModuleVersion: "1.0.0", ArtifactSHA256: hex.EncodeToString(sum[:]), ParametersHash: ph})
	}
	approve := func() permit.StoredReadGrant {
		t.Helper()
		raw, err := json.Marshal(d)
		if err != nil {
			t.Fatal(err)
		}
		p, err := auth.ProposeReadGrant(raw)
		if err != nil {
			t.Fatal(err)
		}
		g, err := auth.ApproveReadGrantCLI(p.Digest, "admin")
		if err != nil {
			t.Fatal(err)
		}
		return g
	}
	first := approve()
	d.ID = "00000000-0000-4000-8000-000000000002"
	second := approve()
	if err := auth.ResumeReadDispatch(); err != nil {
		t.Fatal(err)
	}
	run := permit.Run{HostID: "web", HostKeyFingerprint: fp, CredentialRef: "default", CredentialVersion: fp, ModuleVersion: "1.0.0", Artifact: artifact, ParametersJSON: []byte(`{}`)}
	claim := func(id, action string) (permit.Grant, error) {
		run.ActionID = action
		return auth.AuthorizeReadRun(id, "exec-"+action+now.String(), permit.TriggerOnDemand, run)
	}
	for _, action := range actions {
		g, err := claim(first.ID, action)
		if err != nil {
			t.Fatal(err)
		}
		if err := auth.DispatchReadRun(g, func() error { return nil }); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := claim(second.ID, "host.metrics"); permit.CodeOf(err) != permit.CodeLeaseBudget {
		t.Fatalf("overlap bypassed floor: %v", err)
	}
	now = now.Add(9 * time.Second)
	if _, err := claim(second.ID, "host.metrics"); permit.CodeOf(err) != permit.CodeLeaseBudget {
		t.Fatalf("early read: %v", err)
	}
	now = now.Add(time.Second)
	queued, err := claim(second.ID, "host.metrics")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := claim(first.ID, "gpu.status"); permit.CodeOf(err) != permit.CodeLeaseBudget {
		t.Fatalf("overlap multiplied budget: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db = open()
	auth = newAuthority()
	if err := auth.DispatchReadRun(queued, func() error { t.Fatal("queued read survived restart"); return nil }); err == nil {
		t.Fatal("old claim accepted")
	}
	if err := auth.ResumeReadDispatch(); err != nil {
		t.Fatal(err)
	}
	now = now.Add(10 * time.Second)
	if _, err := claim(second.ID, "gpu.status"); permit.CodeOf(err) != permit.CodeLeaseBudget {
		t.Fatalf("restart replenished budget: %v", err)
	}
	now = start.Add(-time.Second)
	if _, err := claim(first.ID, "gpu.status"); permit.CodeOf(err) != permit.CodeLeaseBudget {
		t.Fatalf("rollback replenished budget: %v", err)
	}
	now = start.Add(time.Hour)
	if _, err := claim(second.ID, "gpu.status"); err != nil {
		t.Fatalf("rolling hour did not refill: %v", err)
	}
	if err := auth.RevokeReadGrant(second.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := claim(second.ID, "docker.stats"); permit.CodeOf(err) != permit.CodeLeaseInactive {
		t.Fatalf("revocation ignored: %v", err)
	}
}

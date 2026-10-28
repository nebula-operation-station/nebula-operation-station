// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/scanner"
	"github.com/nebula-operation-station/nebula-operation-station/internal/stageplan"
)

var testFingerprint = "SHA256:" + strings.Repeat("A", 43)

// listPendingRequest builds a valid ProposeExecutionRequest for the nth
// test execution. The artifact is scanned by the executor at proposal
// (rv67 LOW-3); set req.Artifact = nil to propose without the bytes.
func listPendingRequest(t *testing.T, seq int, artifact []byte) *pb.ProposeExecutionRequest {
	t.Helper()
	sum := sha256.Sum256(artifact)
	ph, err := canonical.HashParameters([]byte("{}"))
	if err != nil {
		t.Fatal(err)
	}
	return &pb.ProposeExecutionRequest{
		Request: &pb.ExecutionRequest{
			ExecutionId:    fmt.Sprintf("00000000-0000-4000-8000-%012d", seq),
			ActionId:       "patching.install_security",
			ModuleVersion:  "1.0.0",
			ArtifactSha256: hex.EncodeToString(sum[:]),
			ParametersHash: ph,
			CredentialRefs: []string{"nebula-default"},
			// HIGH keeps the permit pending (typed count) without
			// needing a trusted artifact.
			RiskClass:       pb.RiskClass_RISK_CLASS_HIGH,
			StagePlanHash:   stageplan.SingleStageHash,
			ExpiryUnix:      time.Now().Add(time.Hour).Unix(),
			ResolvedTargets: []*pb.Target{{HostId: "dockerflux", HostKeyFingerprint: testFingerprint}},
		},
		ParametersJson: []byte("{}"),
		Artifact:       artifact,
	}
}

// The executor's ListPending must carry the Safety Scanner verdict for the
// artifact it scanned at proposal — findings (category, line, excerpt) and
// the display preview — so the approval screen shows exactly what the
// executor saw (rv67 LOW-3).
func TestListPendingCarriesScannerFindings(t *testing.T) {
	artifact := []byte("#!/bin/sh\nset -eu\necho precheck\nsystemctl reboot\n")
	want, _ := scanner.Scan(artifact)
	if len(want) == 0 {
		t.Fatal("test artifact must produce findings")
	}

	e := newReconcileEnv(t)
	resp, err := e.svc.ProposeExecution(context.Background(), listPendingRequest(t, 1, artifact))
	if err != nil {
		t.Fatalf("propose: %v", err)
	}
	if resp.GetState() != pb.PermitState_PERMIT_STATE_PENDING {
		t.Fatalf("state = %v, want pending", resp.GetState())
	}

	got, err := e.svc.ListPending(context.Background(), &pb.ListPendingRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.GetPermits()) != 1 {
		t.Fatalf("permits = %d, want 1", len(got.GetPermits()))
	}
	pp := got.GetPermits()[0]
	if pp.GetExecutionDigest() != resp.GetExecutionDigest() {
		t.Fatalf("digest = %q, want %q", pp.GetExecutionDigest(), resp.GetExecutionDigest())
	}
	if len(pp.GetScannerFindings()) != len(want) {
		t.Fatalf("findings = %d, want %d", len(pp.GetScannerFindings()), len(want))
	}
	for i, f := range want {
		g := pp.GetScannerFindings()[i]
		if g.GetCategory() != f.Category || g.GetLine() != int32(f.Line) || g.GetExcerpt() != f.Excerpt {
			t.Errorf("finding %d = {category:%q line:%d excerpt:%q}, want {category:%q line:%d excerpt:%q}",
				i, g.GetCategory(), g.GetLine(), g.GetExcerpt(), f.Category, f.Line, f.Excerpt)
		}
	}
	if !bytes.Equal(pp.GetArtifactPreview(), artifact) {
		t.Errorf("preview = %q, want the short artifact verbatim", pp.GetArtifactPreview())
	}
}

// A clean artifact yields a scanned permit with no findings.
func TestListPendingCleanArtifactHasNoFindings(t *testing.T) {
	artifact := []byte("#!/bin/sh\nset -eu\necho ok\n")
	if f, _ := scanner.Scan(artifact); len(f) != 0 {
		t.Fatalf("test artifact must be clean (findings %v)", f)
	}

	e := newReconcileEnv(t)
	if _, err := e.svc.ProposeExecution(context.Background(), listPendingRequest(t, 1, artifact)); err != nil {
		t.Fatalf("propose: %v", err)
	}
	got, err := e.svc.ListPending(context.Background(), &pb.ListPendingRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.GetPermits()) != 1 {
		t.Fatalf("permits = %d, want 1", len(got.GetPermits()))
	}
	pp := got.GetPermits()[0]
	if len(pp.GetScannerFindings()) != 0 {
		t.Errorf("findings = %v, want none", pp.GetScannerFindings())
	}
	if !bytes.Equal(pp.GetArtifactPreview(), artifact) {
		t.Errorf("preview = %q, want the artifact", pp.GetArtifactPreview())
	}
}

// The display preview is capped at 4 KiB.
func TestListPendingPreviewIsCapped(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 50; i++ {
		fmt.Fprintf(&b, "echo line %02d %s\n", i, strings.Repeat("x", 90))
	}
	artifact := []byte(b.String())
	if len(artifact) <= 4<<10 {
		t.Fatalf("test artifact must exceed the preview cap, got %d bytes", len(artifact))
	}

	e := newReconcileEnv(t)
	if _, err := e.svc.ProposeExecution(context.Background(), listPendingRequest(t, 1, artifact)); err != nil {
		t.Fatalf("propose: %v", err)
	}
	got, err := e.svc.ListPending(context.Background(), &pb.ListPendingRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.GetPermits()) != 1 {
		t.Fatalf("permits = %d, want 1", len(got.GetPermits()))
	}
	preview := got.GetPermits()[0].GetArtifactPreview()
	if len(preview) != 4<<10 {
		t.Fatalf("preview length = %d, want %d", len(preview), 4<<10)
	}
	if !bytes.HasPrefix(artifact, preview) {
		t.Error("preview must be the artifact's first bytes")
	}
}

// A permit proposed without the artifact bytes was never scanned: the
// executor reports no findings and no preview (the CLI shows "not scanned
// by the executor"). This pins the contract both displays rely on.
func TestListPendingWithoutArtifactBytesHasNoScanInfo(t *testing.T) {
	artifact := []byte("#!/bin/sh\nsystemctl reboot\n")
	req := listPendingRequest(t, 1, artifact)
	req.Artifact = nil

	e := newReconcileEnv(t)
	if _, err := e.svc.ProposeExecution(context.Background(), req); err != nil {
		t.Fatalf("propose: %v", err)
	}
	got, err := e.svc.ListPending(context.Background(), &pb.ListPendingRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.GetPermits()) != 1 {
		t.Fatalf("permits = %d, want 1", len(got.GetPermits()))
	}
	pp := got.GetPermits()[0]
	if len(pp.GetScannerFindings()) != 0 {
		t.Errorf("findings = %v, want none (bytes never scanned)", pp.GetScannerFindings())
	}
	if len(pp.GetArtifactPreview()) != 0 {
		t.Errorf("preview = %q, want empty (bytes never scanned)", pp.GetArtifactPreview())
	}
}

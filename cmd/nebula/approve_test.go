// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"

	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

type fakeApprove struct {
	pb.ExecutorServiceClient
	pending  *pb.PendingPermit
	approved *pb.ApproveCLIRequest
}

func (f *fakeApprove) ListPending(context.Context, *pb.ListPendingRequest, ...grpc.CallOption) (*pb.ListPendingResponse, error) {
	return &pb.ListPendingResponse{Permits: []*pb.PendingPermit{f.pending}}, nil
}

func (f *fakeApprove) ApproveCLI(_ context.Context, in *pb.ApproveCLIRequest, _ ...grpc.CallOption) (*pb.ApproveCLIResponse, error) {
	f.approved = in
	return &pb.ApproveCLIResponse{}, nil
}

// approvePermit builds a pending permit the way the executor fills it: with
// the Safety Scanner findings and the artifact preview for display.
func approvePermit() *pb.PendingPermit {
	return &pb.PendingPermit{
		ExecutionDigest: strings.Repeat("ab", 32),
		Request: &pb.ExecutionRequest{
			ActionId:       "core.facts",
			ModuleVersion:  "1.0.0",
			ArtifactSha256: strings.Repeat("cd", 32),
			RiskClass:      pb.RiskClass_RISK_CLASS_LOW,
			ExpiryUnix:     time.Now().Add(time.Hour).Unix(),
			ResolvedTargets: []*pb.Target{{
				HostId: "web-01", HostKeyFingerprint: "SHA256:AAAA",
			}},
		},
		ScannerFindings: []*pb.ScannerFinding{{Category: "rm", Line: 3, Excerpt: `"rm -rf /"`}},
		ArtifactPreview: []byte("#!/bin/sh\nrm -rf /\necho done\n"),
	}
}

func TestApproveShowsScannerAndScript(t *testing.T) {
	f := &fakeApprove{pending: approvePermit()}
	var out bytes.Buffer
	if err := approve(context.Background(), f, "abababab", strings.NewReader("yes\n"), &out); err != nil {
		t.Fatal(err)
	}
	if f.approved == nil || f.approved.GetExecutionDigest() != f.pending.GetExecutionDigest() {
		t.Fatalf("not approved: %v", f.approved)
	}
	for _, want := range []string{
		"safety scanner",
		"rm at line 3",
		`"rm -rf /"`,
		"script (first 40 lines)",
		"#!/bin/sh",
		"rm -rf /",
		"echo done",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output misses %q:\n%s", want, out.String())
		}
	}
}

func TestApproveEscapesControlAndBidiInScript(t *testing.T) {
	p := approvePermit()
	// A crafted script with a terminal escape and a bidi override: neither
	// may reach the screen raw.
	p.ArtifactPreview = []byte("echo ok\x1b[2J\nrm -rf /\u202e\n")
	f := &fakeApprove{pending: p}
	var out bytes.Buffer
	if err := approve(context.Background(), f, "abababab", strings.NewReader("yes\n"), &out); err != nil {
		t.Fatal(err)
	}
	s := out.String()
	if strings.Contains(s, "\x1b") || strings.Contains(s, "\u202e") {
		t.Fatalf("raw control or bidi character reached the screen:\n%q", s)
	}
	for _, want := range []string{`\u001b[2J`, `\u202e`} {
		if !strings.Contains(s, want) {
			t.Errorf("output misses escaped %q:\n%s", want, s)
		}
	}
}

func TestApproveLargeScriptAtTheLimits(t *testing.T) {
	// The executor cuts the preview to 40 lines / 4 KiB; the CLI must show
	// all of it. Build a 40-line preview under 4 KiB.
	var sb strings.Builder
	for i := 0; i < 40; i++ {
		sb.WriteString("line ")
		sb.WriteString(strings.Repeat("x", 80))
		sb.WriteByte('\n')
	}
	p := approvePermit()
	p.ArtifactPreview = []byte(sb.String())
	f := &fakeApprove{pending: p}
	var out bytes.Buffer
	if err := approve(context.Background(), f, "abababab", strings.NewReader("yes\n"), &out); err != nil {
		t.Fatal(err)
	}
	s := out.String()
	for i := 0; i < 40; i++ {
		if !strings.Contains(s, "line "+strings.Repeat("x", 80)) {
			t.Fatalf("40-line preview not shown in full")
		}
	}
}

func TestApproveNoFindings(t *testing.T) {
	p := approvePermit()
	p.ScannerFindings = nil
	f := &fakeApprove{pending: p}
	var out bytes.Buffer
	if err := approve(context.Background(), f, "abababab", strings.NewReader("yes\n"), &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "safety scanner no findings") {
		t.Fatalf("expected 'no findings':\n%s", out.String())
	}
}

func TestApproveNotScanned(t *testing.T) {
	// No artifact preview: the executor has not scanned these bytes, so the
	// CLI must not claim "no findings" and must not show a script.
	p := approvePermit()
	p.ArtifactPreview = nil
	f := &fakeApprove{pending: p}
	var out bytes.Buffer
	if err := approve(context.Background(), f, "abababab", strings.NewReader("yes\n"), &out); err != nil {
		t.Fatal(err)
	}
	s := out.String()
	if !strings.Contains(s, "not scanned by the executor") {
		t.Fatalf("expected 'not scanned':\n%s", s)
	}
	if strings.Contains(s, "no findings") || strings.Contains(s, "script (first 40 lines)") {
		t.Fatalf("claimed findings or a script without the bytes:\n%s", s)
	}
}

func TestApproveStillRequiresYes(t *testing.T) {
	f := &fakeApprove{pending: approvePermit()}
	var out bytes.Buffer
	if err := approve(context.Background(), f, "abababab", strings.NewReader("no\n"), &out); err == nil || f.approved != nil {
		t.Fatalf("approved without yes: %v", f.approved)
	}
}

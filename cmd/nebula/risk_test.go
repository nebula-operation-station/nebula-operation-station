// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc"

	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// fakeClient records risk-data calls; other methods are not used here.
type fakeClient struct {
	pb.ExecutorServiceClient
	trust    *pb.TrustArtifactRequest
	sumReply string
	host     *pb.SetHostCriticalityRequest
	listed   []*pb.TrustedArtifact
}

func (f *fakeClient) ListTrustedArtifacts(context.Context, *pb.ListTrustedArtifactsRequest, ...grpc.CallOption) (*pb.ListTrustedArtifactsResponse, error) {
	return &pb.ListTrustedArtifactsResponse{Artifacts: f.listed}, nil
}

func (f *fakeClient) TrustArtifact(_ context.Context, in *pb.TrustArtifactRequest, _ ...grpc.CallOption) (*pb.TrustArtifactResponse, error) {
	f.trust = in
	sum := sha256.Sum256(in.GetArtifact())
	if f.sumReply != "" {
		return &pb.TrustArtifactResponse{ArtifactSha256: f.sumReply}, nil
	}
	return &pb.TrustArtifactResponse{ArtifactSha256: hex.EncodeToString(sum[:])}, nil
}

func (f *fakeClient) SetHostCriticality(_ context.Context, in *pb.SetHostCriticalityRequest, _ ...grpc.CallOption) (*pb.SetHostCriticalityResponse, error) {
	f.host = in
	return &pb.SetHostCriticalityResponse{Changed: true}, nil
}

func writeScript(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "action.sh")
	if err := os.WriteFile(p, []byte("#!/bin/sh\nuptime\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestArtifactTrustNeedsConfirmation(t *testing.T) {
	f := &fakeClient{}
	args := []string{"--action", "system.uptime", "--version", "1.0.0", "--risk", "low", writeScript(t)}
	if err := artifactTrust(context.Background(), f, args, strings.NewReader("no\n")); err == nil {
		t.Fatal("trusted without 'yes'")
	}
	if f.trust != nil {
		t.Fatal("request sent without confirmation")
	}
	if err := artifactTrust(context.Background(), f, args, strings.NewReader("yes\n")); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("#!/bin/sh\nuptime\n"))
	if f.trust.GetRiskClass() != pb.RiskClass_RISK_CLASS_LOW || f.trust.GetActionId() != "system.uptime" ||
		string(f.trust.GetArtifact()) != "#!/bin/sh\nuptime\n" || f.trust.GetExpectedSha256() != hex.EncodeToString(sum[:]) {
		t.Fatalf("unexpected request: %v", f.trust)
	}
}

// The CLI checks that the executor hashed the same bytes.
func TestArtifactTrustDetectsHashDisagreement(t *testing.T) {
	f := &fakeClient{sumReply: strings.Repeat("0", 64)}
	args := []string{"--action", "system.uptime", "--version", "1.0.0", "--risk", "MEDIUM", writeScript(t)}
	if err := artifactTrust(context.Background(), f, args, strings.NewReader("yes\n")); err == nil {
		t.Fatal("hash disagreement not reported")
	}
}

func TestArtifactTrustRejectsBadInput(t *testing.T) {
	f := &fakeClient{}
	for name, args := range map[string][]string{
		"no file":      {"--action", "a.b", "--version", "1.0.0", "--risk", "LOW"},
		"no action":    {"--version", "1.0.0", "--risk", "LOW", writeScript(t)},
		"unknown risk": {"--action", "a.b", "--version", "1.0.0", "--risk", "SEVERE", writeScript(t)},
		"empty file":   {"--action", "a.b", "--version", "1.0.0", "--risk", "LOW", filepath.Join(t.TempDir(), "missing")},
	} {
		if err := artifactTrust(context.Background(), f, args, strings.NewReader("yes\n")); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if f.trust != nil {
		t.Fatal("request sent for bad input")
	}
}

const fp = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

func TestHostCriticalityCommand(t *testing.T) {
	f := &fakeClient{}
	if err := hostCmd(context.Background(), f, []string{"criticality", "dockerflux", fp, "critical"}); err != nil {
		t.Fatal(err)
	}
	if f.host.GetCriticality() != pb.RiskClass_RISK_CLASS_CRITICAL || f.host.GetHostKeyFingerprint() != fp || f.host.GetClear() {
		t.Fatalf("sent %v", f.host)
	}
	if err := hostCmd(context.Background(), f, []string{"clear", "dockerflux"}); err != nil {
		t.Fatal(err)
	}
	if !f.host.GetClear() || f.host.GetCriticality() != pb.RiskClass_RISK_CLASS_UNSPECIFIED {
		t.Fatalf("clear sent %v", f.host)
	}
	f.host = nil
	for _, args := range [][]string{
		{"criticality", "dockerflux", fp, "huge"},
		{"criticality", "dockerflux", "critical"}, // fingerprint missing
	} {
		if err := hostCmd(context.Background(), f, args); err == nil {
			t.Errorf("%v accepted", args)
		}
	}
	if f.host != nil {
		t.Fatalf("request sent for bad input: %v", f.host)
	}
}

// Labels and actors come from executor.db; the listing escapes anything
// that could rewrite the terminal, and short hashes do not crash it.
func TestArtifactListEscapesText(t *testing.T) {
	f := &fakeClient{listed: []*pb.TrustedArtifact{{
		ArtifactSha256: "abc", ActionId: "a.b", ModuleVersion: "1.0.0", RiskClass: pb.RiskClass_RISK_CLASS_LOW,
		Label: "ok\x1b[2Jcleared", TrustedBy: "admin\u202e",
	}}}
	var out strings.Builder
	if err := artifactList(context.Background(), f, &out); err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(out.String(), "\x1b\u202e") {
		t.Fatalf("control characters reached the terminal: %q", out.String())
	}
}

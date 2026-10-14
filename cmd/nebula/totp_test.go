// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc"

	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

type fakeTOTP struct {
	pb.ExecutorServiceClient
	confirmed string
	removed   bool
}

func (f *fakeTOTP) BeginTOTPSetup(context.Context, *pb.BeginTOTPSetupRequest, ...grpc.CallOption) (*pb.BeginTOTPSetupResponse, error) {
	return &pb.BeginTOTPSetupResponse{SecretBase32: "GEZDGNBV", Uri: "otpauth://totp/x?secret=GEZDGNBV\x1b[2J"}, nil
}

func (f *fakeTOTP) ConfirmTOTPSetup(_ context.Context, in *pb.ConfirmTOTPSetupRequest, _ ...grpc.CallOption) (*pb.ConfirmTOTPSetupResponse, error) {
	f.confirmed = in.GetCode()
	return &pb.ConfirmTOTPSetupResponse{}, nil
}

func (f *fakeTOTP) RemoveTOTP(context.Context, *pb.RemoveTOTPRequest, ...grpc.CallOption) (*pb.RemoveTOTPResponse, error) {
	f.removed = true
	return &pb.RemoveTOTPResponse{Removed: true}, nil
}

func TestTOTPSetupConfirmsTheTypedCode(t *testing.T) {
	f := &fakeTOTP{}
	var out strings.Builder
	if err := totpSetup(context.Background(), f, nil, strings.NewReader(" 123456 \n"), &out); err != nil {
		t.Fatal(err)
	}
	if f.confirmed != "123456" || !strings.Contains(out.String(), "GEZDGNBV") || strings.Contains(out.String(), "\x1b") {
		t.Fatalf("confirmed %q output %q", f.confirmed, out.String())
	}
}

func TestTOTPRemoveNeedsYes(t *testing.T) {
	f := &fakeTOTP{}
	var out strings.Builder
	if err := totpRemove(context.Background(), f, strings.NewReader("no\n"), &out); err == nil || f.removed {
		t.Fatal("removed without yes")
	}
	if err := totpRemove(context.Background(), f, strings.NewReader("yes\n"), &out); err != nil || !f.removed {
		t.Fatalf("remove: %v", err)
	}
}

type fakeRecovery struct {
	pb.ExecutorServiceClient
	creds    []*pb.WebAuthnCredential
	finished string
}

func (f *fakeRecovery) GetTOTPStatus(context.Context, *pb.GetTOTPStatusRequest, ...grpc.CallOption) (*pb.GetTOTPStatusResponse, error) {
	return &pb.GetTOTPStatusResponse{Configured: true, Activated: true, RecoveryPending: true, RecoveryPendingSinceUnix: 100}, nil
}

func (f *fakeRecovery) ListWebAuthnCredentials(context.Context, *pb.ListWebAuthnCredentialsRequest, ...grpc.CallOption) (*pb.ListWebAuthnCredentialsResponse, error) {
	return &pb.ListWebAuthnCredentialsResponse{Credentials: f.creds}, nil
}

func (f *fakeRecovery) FinishRecovery(_ context.Context, in *pb.FinishRecoveryRequest, _ ...grpc.CallOption) (*pb.FinishRecoveryResponse, error) {
	f.finished = in.GetCredentialId()
	return &pb.FinishRecoveryResponse{}, nil
}

func TestTOTPFinishRecoveryNeedsTheAdminsChoice(t *testing.T) {
	f := &fakeRecovery{creds: []*pb.WebAuthnCredential{
		{CredentialId: "OLDOLDOLDOLD", CreatedAtUnix: 50},
		{CredentialId: "abcdefgh1234", Label: "mine", CreatedAtUnix: 150},
		{CredentialId: "abcdefgh9999", Label: "rogue\x1b[2J", CreatedAtUnix: 160},
	}}
	var out strings.Builder
	for _, typed := range []string{"abc\n", "abcdefgh\n", "OLDOLDOLD\n", "zzzzzzzzz\n"} {
		if err := totpFinishRecovery(context.Background(), f, strings.NewReader(typed), &out); err == nil || f.finished != "" {
			t.Fatalf("%q accepted", typed)
		}
	}
	if !strings.Contains(out.String(), "may be compromised") || strings.Contains(out.String(), "\x1b") || strings.Contains(out.String(), "OLDOLD") {
		t.Fatalf("output %q", out.String())
	}
	if err := totpFinishRecovery(context.Background(), f, strings.NewReader("abcdefgh12\n"), &out); err != nil || f.finished != "abcdefgh1234" {
		t.Fatalf("%v %q", err, f.finished)
	}
}

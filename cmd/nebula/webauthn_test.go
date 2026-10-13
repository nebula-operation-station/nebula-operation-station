// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc"

	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

type fakeWebAuthn struct {
	pb.ExecutorServiceClient
	codeReq *pb.CreateRegistrationCodeRequest
	creds   []*pb.WebAuthnCredential
	removed string
}

func (f *fakeWebAuthn) CreateRegistrationCode(_ context.Context, in *pb.CreateRegistrationCodeRequest, _ ...grpc.CallOption) (*pb.CreateRegistrationCodeResponse, error) {
	f.codeReq = in
	return &pb.CreateRegistrationCodeResponse{Code: "ABCD-EFGH-JKMN-PQRS-TVWX", ExpiryUnix: 1}, nil
}

func (f *fakeWebAuthn) ListWebAuthnCredentials(context.Context, *pb.ListWebAuthnCredentialsRequest, ...grpc.CallOption) (*pb.ListWebAuthnCredentialsResponse, error) {
	return &pb.ListWebAuthnCredentialsResponse{Credentials: f.creds}, nil
}

func (f *fakeWebAuthn) RemoveWebAuthnCredential(_ context.Context, in *pb.RemoveWebAuthnCredentialRequest, _ ...grpc.CallOption) (*pb.RemoveWebAuthnCredentialResponse, error) {
	f.removed = in.GetCredentialId()
	return &pb.RemoveWebAuthnCredentialResponse{Removed: true}, nil
}

func TestWebAuthnCode(t *testing.T) {
	f := &fakeWebAuthn{}
	var out strings.Builder
	if err := webauthnCode(context.Background(), f, []string{"--user", "axel", "--label", "YubiKey"}, &out); err != nil {
		t.Fatal(err)
	}
	if f.codeReq.GetUserName() != "axel" || f.codeReq.GetLabel() != "YubiKey" || !strings.Contains(out.String(), "ABCD-EFGH-JKMN-PQRS-TVWX") {
		t.Fatalf("request %v, output %q", f.codeReq, out.String())
	}
}

func TestWebAuthnRemoveNeedsUniquePrefixAndConfirmation(t *testing.T) {
	f := &fakeWebAuthn{creds: []*pb.WebAuthnCredential{
		{CredentialId: "abcdefgh111", Label: "one"},
		{CredentialId: "abcdefgh222", Label: "two"},
		{CredentialId: "zzzzzzzz333", Label: "three\x1b[2J"},
	}}
	ctx := context.Background()
	var out strings.Builder
	if err := webauthnRemove(ctx, f, []string{"abcdefgh"}, strings.NewReader("yes\n"), &out); err == nil {
		t.Fatal("ambiguous prefix accepted")
	}
	if err := webauthnRemove(ctx, f, []string{"abc"}, strings.NewReader("yes\n"), &out); err == nil {
		t.Fatal("short prefix accepted")
	}
	if err := webauthnRemove(ctx, f, []string{"zzzzzzzz"}, strings.NewReader("no\n"), &out); err == nil || f.removed != "" {
		t.Fatal("removed without confirmation")
	}
	if strings.Contains(out.String(), "\x1b") {
		t.Fatalf("escape reached the terminal: %q", out.String())
	}
	if err := webauthnRemove(ctx, f, []string{"zzzzzzzz"}, strings.NewReader("yes\n"), &out); err != nil || f.removed != "zzzzzzzz333" {
		t.Fatalf("remove: %v, sent %q", err, f.removed)
	}
}

// An attacker-chosen ID that extends a legitimate one cannot shadow it: the
// exact ID always selects the legitimate credential.
func TestWebAuthnRemoveExactIDWins(t *testing.T) {
	f := &fakeWebAuthn{creds: []*pb.WebAuthnCredential{
		{CredentialId: "legitimateID123"},
		{CredentialId: "legitimateID123evil"},
	}}
	var out strings.Builder
	if err := webauthnRemove(context.Background(), f, []string{"legitimateID123"}, strings.NewReader("yes\n"), &out); err != nil {
		t.Fatal(err)
	}
	if f.removed != "legitimateID123" {
		t.Fatalf("removed %q", f.removed)
	}
	f.removed = ""
	if err := webauthnRemove(context.Background(), f, []string{"legitimateID123evil"}, strings.NewReader("yes\n"), &out); err != nil || f.removed != "legitimateID123evil" {
		t.Fatalf("remove second: %v %q", err, f.removed)
	}
}

func TestWebAuthnListEscapes(t *testing.T) {
	f := &fakeWebAuthn{creds: []*pb.WebAuthnCredential{{CredentialId: "id", UserName: "a\u202eb", Label: "x\x07", CreatedBy: "c"}}}
	var out strings.Builder
	if err := webauthnList(context.Background(), f, &out); err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(out.String(), "\u202e\x07") {
		t.Fatalf("control characters reached the terminal: %q", out.String())
	}
}

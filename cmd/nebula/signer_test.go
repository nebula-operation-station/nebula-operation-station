// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc"

	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

type fakeSigners struct {
	pb.ExecutorServiceClient
	added     *pb.AddSignerRequest
	confirmed *pb.ConfirmModuleSignerRequest
}

func (f *fakeSigners) AddSigner(_ context.Context, in *pb.AddSignerRequest, _ ...grpc.CallOption) (*pb.AddSignerResponse, error) {
	f.added = in
	k, _, _, _, _ := ssh.ParseAuthorizedKey([]byte(in.GetPublicKey()))
	return &pb.AddSignerResponse{Fingerprint: ssh.FingerprintSHA256(k)}, nil
}

// Adding a signer needs the full fingerprint typed.
func TestSignerAddNeedsTheTypedFingerprint(t *testing.T) {
	const pub = "../../internal/sshsig/testdata/signer.pub"
	f := &fakeSigners{}
	var out strings.Builder
	if err := signerAdd(context.Background(), f, []string{"--name", "Releases", pub}, strings.NewReader("yes\n"), &out); err == nil || f.added != nil {
		t.Fatal("added without the fingerprint")
	}
	fp := strings.TrimSpace(strings.SplitN(strings.SplitN(out.String(), "key          ", 2)[1], "\n", 2)[0])
	if !strings.HasPrefix(fp, "SHA256:") {
		t.Fatal(out.String())
	}
	if err := signerAdd(context.Background(), f, []string{"--name", "Releases", pub}, strings.NewReader(fp+"\n"), &out); err != nil || f.added == nil ||
		f.added.GetName() != "Releases" || !strings.HasPrefix(f.added.GetPublicKey(), "ssh-ed25519 ") {
		t.Fatalf("%v %v", err, f.added)
	}
	if !strings.Contains(out.String(), "CRITICAL") {
		t.Fatal("no CRITICAL warning")
	}
}

// A file with two keys is refused: only the first would be trusted.
func TestSignerAddRefusesSeveralKeys(t *testing.T) {
	b, err := os.ReadFile("../../internal/sshsig/testdata/signer.pub")
	if err != nil {
		t.Fatal(err)
	}
	two := filepath.Join(t.TempDir(), "two.pub")
	if err := os.WriteFile(two, append(append(append([]byte{}, b...), '\n'), b...), 0o600); err != nil {
		t.Fatal(err)
	}
	f := &fakeSigners{}
	var out strings.Builder
	if err := signerAdd(context.Background(), f, []string{"--name", "x", two}, strings.NewReader("\n"), &out); err == nil || !strings.Contains(err.Error(), "more than one key") {
		t.Fatal(err)
	}
}

func (f *fakeSigners) ListSigners(context.Context, *pb.ListSignersRequest, ...grpc.CallOption) (*pb.ListSignersResponse, error) {
	return &pb.ListSignersResponse{Signers: []*pb.Signer{{Fingerprint: "SHA256:" + strings.Repeat("A", 43), Name: "Old"},
		{Fingerprint: "SHA256:" + strings.Repeat("B", 43), Name: "New"}},
		Modules: []*pb.ModuleSigner{{Module: "demo", Fingerprint: "SHA256:" + strings.Repeat("A", 43)}}}, nil
}

func (f *fakeSigners) ConfirmModuleSigner(_ context.Context, in *pb.ConfirmModuleSignerRequest, _ ...grpc.CallOption) (*pb.ConfirmModuleSignerResponse, error) {
	f.confirmed = in
	return &pb.ConfirmModuleSignerResponse{Previous: in.GetExpectedPrevious()}, nil
}

// Changing a module's signer shows both keys and needs the new
// fingerprint typed; the executor gets the signer that was shown.
func TestConfirmSignerNeedsTheTypedFingerprint(t *testing.T) {
	newFP, oldFP := "SHA256:"+strings.Repeat("B", 43), "SHA256:"+strings.Repeat("A", 43)
	f := &fakeSigners{}
	var out strings.Builder
	if err := moduleCmd(context.Background(), f, []string{"confirm-signer", "demo", newFP}, strings.NewReader("yes\n"), &out); err == nil || f.confirmed != nil {
		t.Fatal("confirmed without the fingerprint")
	}
	if !strings.Contains(out.String(), oldFP+"  Old") || !strings.Contains(out.String(), newFP+"  New") {
		t.Fatal(out.String())
	}
	if err := moduleCmd(context.Background(), f, []string{"confirm-signer", "demo", newFP}, strings.NewReader(newFP+"\n"), &out); err != nil ||
		f.confirmed.GetExpectedPrevious() != oldFP {
		t.Fatal(err, f.confirmed)
	}
	if err := moduleCmd(context.Background(), f, []string{"confirm-signer", "demo", "SHA256:" + strings.Repeat("C", 43)}, strings.NewReader("\n"), &out); err == nil {
		t.Fatal("an untrusted signer accepted")
	}
}

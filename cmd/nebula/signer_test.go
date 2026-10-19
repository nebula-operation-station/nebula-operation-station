// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc"

	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

type fakeSigners struct {
	pb.ExecutorServiceClient
	added *pb.AddSignerRequest
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

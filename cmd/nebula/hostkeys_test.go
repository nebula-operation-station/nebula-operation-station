// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc"

	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

func pubKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

type fakeHosts struct {
	pb.ExecutorServiceClient
	keys   map[string]ssh.PublicKey // endpoint -> presented key
	pinReq *pb.PinHostKeyRequest
	unpin  *pb.UnpinHostKeyRequest
	pins   []*pb.HostKeyPin
}

func (f *fakeHosts) ProbeHostKey(_ context.Context, in *pb.ProbeHostKeyRequest, _ ...grpc.CallOption) (*pb.ProbeHostKeyResponse, error) {
	k := f.keys[in.GetEndpoint()]
	return &pb.ProbeHostKeyResponse{Endpoint: in.GetEndpoint(), KeyType: k.Type(), Fingerprint: ssh.FingerprintSHA256(k),
		AuthorizedKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k)))}, nil
}

func (f *fakeHosts) PinHostKey(_ context.Context, in *pb.PinHostKeyRequest, _ ...grpc.CallOption) (*pb.PinHostKeyResponse, error) {
	f.pinReq = in
	return &pb.PinHostKeyResponse{Pin: &pb.HostKeyPin{HostId: in.GetHostId(), Fingerprint: in.GetExpectedFingerprint()}}, nil
}

func (f *fakeHosts) ListHostKeys(context.Context, *pb.ListHostKeysRequest, ...grpc.CallOption) (*pb.ListHostKeysResponse, error) {
	return &pb.ListHostKeysResponse{Hosts: f.pins}, nil
}

func (f *fakeHosts) UnpinHostKey(_ context.Context, in *pb.UnpinHostKeyRequest, _ ...grpc.CallOption) (*pb.UnpinHostKeyResponse, error) {
	f.unpin = in
	return &pb.UnpinHostKeyResponse{Removed: true}, nil
}

func TestHostPinProbesEveryEndpointAndNeedsYes(t *testing.T) {
	k := pubKey(t)
	f := &fakeHosts{keys: map[string]ssh.PublicKey{"192.168.0.10:22": k, "10.8.0.5:22": k}}
	ctx := context.Background()
	var out strings.Builder
	if err := hostPin(ctx, f, []string{"dockerflux", "192.168.0.10", "10.8.0.5"}, strings.NewReader("no\n"), &out); err == nil || f.pinReq != nil {
		t.Fatal("pinned without 'yes'")
	}
	out.Reset()
	if err := hostPin(ctx, f, []string{"--user", "ops", "dockerflux", "192.168.0.10", "10.8.0.5"}, strings.NewReader("yes\n"), &out); err != nil {
		t.Fatal(err)
	}
	r := f.pinReq
	if r.GetExpectedFingerprint() != ssh.FingerprintSHA256(k) || r.GetSshUser() != "ops" || r.GetCredentialRef() != "nebula-default" ||
		r.GetSource() != pb.HostKeySource_HOST_KEY_SOURCE_PROBE || !strings.Contains(out.String(), "ssh-keygen -lf") {
		t.Fatalf("request %v output %q", r, out.String())
	}
}

func TestHostPinRefusesEndpointsWithDifferentKeys(t *testing.T) {
	f := &fakeHosts{keys: map[string]ssh.PublicKey{"192.168.0.10:22": pubKey(t), "10.8.0.5:22": pubKey(t)}}
	var out strings.Builder
	err := hostPin(context.Background(), f, []string{"dockerflux", "192.168.0.10", "10.8.0.5"}, strings.NewReader("yes\n"), &out)
	if err == nil || f.pinReq != nil || !strings.Contains(err.Error(), "not the same host") {
		t.Fatalf("pinned across differing keys: %v", err)
	}
}

func TestHostPinFromKnownHosts(t *testing.T) {
	k := pubKey(t)
	file := filepath.Join(t.TempDir(), "known_hosts")
	line := "dockerflux.lan " + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k))) + "\n"
	if err := os.WriteFile(file, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	f := &fakeHosts{}
	var out strings.Builder
	if err := hostPin(context.Background(), f, []string{"--known-hosts", file, "dockerflux", "dockerflux.lan"}, strings.NewReader("yes\n"), &out); err != nil {
		t.Fatal(err)
	}
	if f.pinReq.GetSource() != pb.HostKeySource_HOST_KEY_SOURCE_KNOWN_HOSTS || f.pinReq.GetExpectedFingerprint() != ssh.FingerprintSHA256(k) {
		t.Fatalf("request %v", f.pinReq)
	}
}

func TestHostUnpinSendsTheShownFingerprint(t *testing.T) {
	f := &fakeHosts{pins: []*pb.HostKeyPin{{HostId: "dockerflux", Fingerprint: "SHA256:old", KeyType: "ssh-ed25519",
		Blocked: true, BlockedEndpoint: "10.8.0.5:22", BlockedFingerprint: "SHA256:new\x1b[2J"}}}
	var out strings.Builder
	if err := hostUnpin(context.Background(), f, []string{"dockerflux"}, strings.NewReader("yes\n"), &out); err != nil {
		t.Fatal(err)
	}
	if f.unpin.GetExpectedFingerprint() != "SHA256:old" || strings.Contains(out.String(), "\x1b") {
		t.Fatalf("request %v output %q", f.unpin, out.String())
	}
	if err := hostUnpin(context.Background(), f, []string{"strompi"}, strings.NewReader("yes\n"), &out); err == nil {
		t.Fatal("unknown host unpinned")
	}
}

func TestHostKeysListEscapesHostData(t *testing.T) {
	f := &fakeHosts{pins: []*pb.HostKeyPin{{HostId: "dockerflux", Fingerprint: "SHA256:x", Blocked: true, BlockedEndpoint: "evil\x1b]0;x\x07"}}}
	var out strings.Builder
	if err := hostKeys(context.Background(), f, &out); err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(out.String(), "\x1b\x07") || !strings.Contains(out.String(), "BLOCKED") {
		t.Fatalf("output %q", out.String())
	}
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/nebula-operation-station/nebula-operation-station/internal/peercred"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// The credential-version read is a read RPC like ListHostKeys: server and
// admin only, never the collector or an unknown role.
func TestBatchCredentialVersionsMethodRoles(t *testing.T) {
	method := pb.ExecutorService_GetBatchCredentialVersions_FullMethodName
	roles := map[peercred.Role]bool{peercred.RoleServer: true, peercred.RoleAdmin: true, peercred.RolePVECollector: false, peercred.Role("discovery"): false}
	uids := map[uint32][]peercred.Role{}
	want := map[uint32]bool{}
	uid := uint32(1)
	for r, ok := range roles {
		uids[uid], want[uid] = []peercred.Role{r}, ok
		uid++
	}
	policy := peercred.NewPolicy(uids, MethodRoles())
	for u, ok := range want {
		if _, got := policy.Allowed(u, method); got != ok {
			t.Errorf("role %v allowed=%v, want %v", uids[u], got, ok)
		}
	}
	if _, ok := policy.Allowed(999, method); ok {
		t.Error("unknown UID allowed")
	}
}

// Without a batch authority the RPC is Unimplemented, like the other batch
// RPCs: the server then keeps its batch-less fallback.
func TestBatchCredentialVersionsUnconfiguredIsUnimplemented(t *testing.T) {
	s := &Service{}
	for _, refs := range [][]string{nil, {"cred"}} {
		if _, err := s.GetBatchCredentialVersions(context.Background(), &pb.GetBatchCredentialVersionsRequest{CredentialRefs: refs}); status.Code(err) != codes.Unimplemented {
			t.Errorf("refs %v: want Unimplemented, got %v", refs, err)
		}
	}
}

// A loaded reference returns a stable nonzero version derived from its
// public key and the public-key fingerprint, nothing else.
func TestBatchCredentialVersionsReturnsPublicVersions(t *testing.T) {
	env := newBatchRPCEnv(t, uint32(os.Getuid()))
	ctx := context.Background()
	resp, err := env.svc.GetBatchCredentialVersions(ctx, &pb.GetBatchCredentialVersionsRequest{CredentialRefs: []string{"cred"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.GetVersions()) != 1 {
		t.Fatalf("versions = %v", resp.GetVersions())
	}
	v := resp.GetVersions()[0]
	if v.GetCredentialRef() != "cred" || v.GetVersion() == 0 || v.GetVersion() != CredentialVersionOf(env.userPub) ||
		v.GetPublicKeyFingerprint() != ssh.FingerprintSHA256(env.userPub) {
		t.Errorf("version = %+v", v)
	}
	again, err := env.svc.GetBatchCredentialVersions(ctx, &pb.GetBatchCredentialVersionsRequest{CredentialRefs: []string{"cred"}})
	if err != nil || again.GetVersions()[0].GetVersion() != v.GetVersion() {
		t.Errorf("version not stable: %v %v", again, err)
	}
	raw, err := proto.Marshal(resp)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, _ := testCredentialKey(t)
	if bytes.Contains(raw, env.userPub.Marshal()) || bytes.Contains(raw, keyPEM) || bytes.Contains(raw, []byte("PRIVATE")) {
		t.Error("response carries key material")
	}
	// An empty request only reports that batches are available.
	empty, err := env.svc.GetBatchCredentialVersions(ctx, &pb.GetBatchCredentialVersionsRequest{})
	if err != nil || len(empty.GetVersions()) != 0 {
		t.Errorf("empty request: %v %v", empty, err)
	}
}

// Malformed and oversize requests, and references a canonical batch would
// reject, are refused before the keyring is read;
// unknown references and a locked keyring are refused with distinct codes.
func TestBatchCredentialVersionsRejections(t *testing.T) {
	env := newBatchRPCEnv(t, uint32(os.Getuid()))
	ctx := context.Background()
	tooMany := make([]string, maxBatchCredentialRefs+1)
	for i := range tooMany {
		tooMany[i] = "cred" + strings.Repeat("x", i)
	}
	cases := map[string]struct {
		refs []string
		code codes.Code
	}{
		"too many":      {tooMany, codes.InvalidArgument},
		"empty ref":     {[]string{""}, codes.InvalidArgument},
		"oversize ref":  {[]string{strings.Repeat("a", 65)}, codes.InvalidArgument},
		"uppercase ref": {[]string{"Cred"}, codes.InvalidArgument},
		"space in ref":  {[]string{"my cred"}, codes.InvalidArgument},
		"not UTF-8":     {[]string{"cred\xff"}, codes.InvalidArgument},
		"control char":  {[]string{"cred\n"}, codes.InvalidArgument},
		"duplicate ref": {[]string{"cred", "cred"}, codes.InvalidArgument},
		"unknown ref":   {[]string{"cred", "other"}, codes.NotFound},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			resp, err := env.svc.GetBatchCredentialVersions(ctx, &pb.GetBatchCredentialVersionsRequest{CredentialRefs: c.refs})
			if status.Code(err) != c.code || resp != nil {
				t.Errorf("got %v %v, want %v", resp, err, c.code)
			}
		})
	}
	if _, err := env.svc.GetBatchCredentialVersions(ctx, nil); status.Code(err) != codes.InvalidArgument {
		t.Errorf("nil request: %v", err)
	}
	env.usePrivateKeyring()
	env.svc.keys.Lock()
	if _, err := env.svc.GetBatchCredentialVersions(ctx, &pb.GetBatchCredentialVersionsRequest{CredentialRefs: []string{"cred"}}); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("locked keyring: %v", err)
	}
}

// The version changes with the key behind a reference and is never zero.
func TestCredentialVersionOfFollowsTheKey(t *testing.T) {
	seen := map[uint64]bool{}
	for range 16 {
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		k, err := ssh.NewPublicKey(pub)
		if err != nil {
			t.Fatal(err)
		}
		v := CredentialVersionOf(k)
		if v == 0 || seen[v] || CredentialVersionOf(k) != v {
			t.Fatalf("version %d (seen %v)", v, seen[v])
		}
		seen[v] = true
	}
	if CredentialVersionOf(nil) != 0 {
		t.Error("nil key has a version")
	}
}

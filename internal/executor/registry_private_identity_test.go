// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"
	"strings"
	"testing"
	"time"

	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// TestPrivateRegistryInfoCarriesLeaseIdentity: the metadata the server may
// list carries exactly the record digest and credential identity the
// registry read lease check compares (cu06, G13), and both change on the
// events that must invalidate a lease: rotation changes the credential
// identity, removal and re-add changes both.
func TestPrivateRegistryInfoCarriesLeaseIdentity(t *testing.T) {
	e := newRegistryEnv(t)
	added := e.add(t)
	l, err := e.svc.loadRegistry("corp")
	if err != nil {
		t.Fatal(err)
	}
	wantDigest, wantCred := l.configDigest, l.cred.ID
	l.wipe()
	list, err := e.svc.ListPrivateRegistries(context.Background(), &pb.ListPrivateRegistriesRequest{})
	if err != nil || len(list.GetRegistries()) != 1 {
		t.Fatalf("list = %+v, %v", list, err)
	}
	for _, info := range []*pb.PrivateRegistryInfo{added, list.GetRegistries()[0]} {
		if info.GetConfigDigest() != wantDigest || info.GetCredentialId() != wantCred {
			t.Fatalf("info identity = %q/%q, want %q/%q", info.GetConfigDigest(), info.GetCredentialId(), wantDigest, wantCred)
		}
		if len(info.GetConfigDigest()) != 64 || len(info.GetCredentialId()) != 32 {
			t.Fatalf("identity shape = %q/%q", info.GetConfigDigest(), info.GetCredentialId())
		}
		if strings.Contains(info.String(), regSecret) || strings.Contains(info.String(), regUser) {
			t.Fatalf("credential leaked: %s", info.String())
		}
	}
	rot, err := e.svc.RotatePrivateRegistryCredential(context.Background(), &pb.RotatePrivateRegistryCredentialRequest{
		RegistryId: "corp", Username: regUser, Secret: []byte(regSecret + "-2"),
		CredentialExpiresUnix: e.clock.Now().Add(30 * 24 * time.Hour).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	if r := rot.GetRegistry(); r.GetConfigDigest() != wantDigest || r.GetCredentialId() == wantCred || len(r.GetCredentialId()) != 32 {
		t.Fatalf("after rotation: %q/%q", r.GetConfigDigest(), r.GetCredentialId())
	}
	if _, err := e.svc.RemovePrivateRegistry(context.Background(), &pb.RemovePrivateRegistryRequest{RegistryId: "corp"}); err != nil {
		t.Fatal(err)
	}
	readded := e.add(t)
	if readded.GetConfigDigest() == wantDigest || readded.GetCredentialId() == wantCred {
		t.Fatal("re-added registry kept the old record or credential identity")
	}
}

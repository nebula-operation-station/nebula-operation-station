// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"

	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

type fakeVault struct {
	pb.ExecutorServiceClient
	keysPass, vaultPass string
	unlocks             []*pb.UnlockRequest
	init                []byte
	set                 *pb.SetSecretRequest
	deleted             string
	list                []*pb.SecretInfo
}

func (f *fakeVault) Unlock(_ context.Context, in *pb.UnlockRequest, _ ...grpc.CallOption) (*pb.UnlockResponse, error) {
	p := string(in.GetPassphrase())
	f.unlocks = append(f.unlocks, &pb.UnlockRequest{Passphrase: []byte(p), Scope: in.GetScope()})
	r := &pb.UnlockResponse{VaultState: pb.VaultState_VAULT_STATE_LOCKED}
	if in.GetScope() != pb.UnlockScope_UNLOCK_SCOPE_VAULT {
		if p == f.keysPass {
			r.KeysUnlocked, r.LoadedCredentialRefs = true, []string{"nebula-default"}
		} else {
			r.KeysWrongPassphrase, r.KeysError = true, "keyring: passphrase does not decrypt every key"
		}
	}
	if in.GetScope() != pb.UnlockScope_UNLOCK_SCOPE_KEYS {
		if p == f.vaultPass {
			r.VaultState = pb.VaultState_VAULT_STATE_UNLOCKED
		} else {
			r.VaultWrongPassphrase = true
		}
	}
	if !r.KeysUnlocked && r.VaultState != pb.VaultState_VAULT_STATE_UNLOCKED {
		return nil, grpcstatus.Error(codes.Unauthenticated, "the passphrase does not unlock anything")
	}
	return r, nil
}

func (f *fakeVault) InitVault(_ context.Context, in *pb.InitVaultRequest, _ ...grpc.CallOption) (*pb.InitVaultResponse, error) {
	f.init = append([]byte(nil), in.GetPassphrase()...)
	return &pb.InitVaultResponse{}, nil
}

func (f *fakeVault) SetSecret(_ context.Context, in *pb.SetSecretRequest, _ ...grpc.CallOption) (*pb.SetSecretResponse, error) {
	f.set = &pb.SetSecretRequest{Id: in.GetId(), Value: append([]byte(nil), in.GetValue()...)}
	return &pb.SetSecretResponse{Version: 3}, nil
}

func (f *fakeVault) ListSecrets(context.Context, *pb.ListSecretsRequest, ...grpc.CallOption) (*pb.ListSecretsResponse, error) {
	return &pb.ListSecretsResponse{Secrets: f.list, VaultState: pb.VaultState_VAULT_STATE_LOCKED}, nil
}

func (f *fakeVault) DeleteSecret(_ context.Context, in *pb.DeleteSecretRequest, _ ...grpc.CallOption) (*pb.DeleteSecretResponse, error) {
	f.deleted = in.GetId()
	return &pb.DeleteSecretResponse{}, nil
}

// answers returns a prompter that hands out the given answers in order.
func answers(t *testing.T, a ...string) (prompter, *[]string) {
	var asked []string
	return func(prompt string) ([]byte, error) {
		asked = append(asked, prompt)
		if len(a) == 0 {
			t.Fatalf("unexpected prompt %q", prompt)
		}
		v := a[0]
		a = a[1:]
		return []byte(v), nil
	}, &asked
}

func TestUnlockAsksOnceWhenOnePassphraseFitsBoth(t *testing.T) {
	f := &fakeVault{keysPass: "same", vaultPass: "same"}
	ask, asked := answers(t, "same")
	var out strings.Builder
	if err := unlockWith(context.Background(), f, ask, &out); err != nil {
		t.Fatal(err)
	}
	if len(*asked) != 1 || len(f.unlocks) != 1 || !strings.Contains(out.String(), "keys:  unlocked") || !strings.Contains(out.String(), "vault: unlocked") {
		t.Fatalf("asked %v unlocks %d out %q", *asked, len(f.unlocks), out.String())
	}
}

func TestUnlockAsksAgainOnlyForThePartThatDidNotFit(t *testing.T) {
	f := &fakeVault{keysPass: "keys", vaultPass: "vault"}
	ask, asked := answers(t, "keys", "vault")
	var out strings.Builder
	if err := unlockWith(context.Background(), f, ask, &out); err != nil {
		t.Fatal(err)
	}
	if len(*asked) != 2 || !strings.HasPrefix((*asked)[1], "Vault passphrase") || f.unlocks[1].GetScope() != pb.UnlockScope_UNLOCK_SCOPE_VAULT ||
		!strings.Contains(out.String(), "vault: unlocked") {
		t.Fatalf("asked %v unlocks %v out %q", *asked, f.unlocks, out.String())
	}

	f = &fakeVault{keysPass: "keys", vaultPass: "vault"}
	ask, asked = answers(t, "vault", "keys")
	out.Reset()
	if err := unlockWith(context.Background(), f, ask, &out); err != nil {
		t.Fatal(err)
	}
	if len(*asked) != 2 || !strings.HasPrefix((*asked)[1], "SSH key passphrase") || f.unlocks[1].GetScope() != pb.UnlockScope_UNLOCK_SCOPE_KEYS ||
		!strings.Contains(out.String(), "keys:  unlocked") {
		t.Fatalf("asked %v unlocks %v out %q", *asked, f.unlocks, out.String())
	}

	f = &fakeVault{keysPass: "keys", vaultPass: "vault"}
	ask, _ = answers(t, "neither")
	if err := unlockWith(context.Background(), f, ask, &out); grpcstatus.Code(err) != codes.Unauthenticated {
		t.Fatalf("wrong passphrase: %v", err)
	}
}

func TestVaultInitNeedsTheSamePassphraseTwice(t *testing.T) {
	f := &fakeVault{}
	ask, _ := answers(t, "a", "b")
	if err := vaultCmd(context.Background(), f, []string{"init"}, ask, &strings.Builder{}); err == nil || f.init != nil {
		t.Fatal("differing passphrases accepted")
	}
	ask, _ = answers(t, "p", "p")
	if err := vaultCmd(context.Background(), f, []string{"init"}, ask, &strings.Builder{}); err != nil || string(f.init) != "p" {
		t.Fatalf("init: %v %q", err, f.init)
	}
}

func TestSecretCommands(t *testing.T) {
	f := &fakeVault{list: []*pb.SecretInfo{{Id: "telegram.token", Version: 2, UpdatedBy: "admin\x1b[2J"}}}
	var out strings.Builder
	value := func() ([]byte, error) { return []byte("tok"), nil }
	if err := secretCmd(context.Background(), f, []string{"set", "telegram.token"}, value, nil, &out); err != nil {
		t.Fatal(err)
	}
	if f.set.GetId() != "telegram.token" || string(f.set.GetValue()) != "tok" || strings.Contains(out.String(), "tok\n") {
		t.Fatalf("set %v out %q", f.set, out.String())
	}
	out.Reset()
	if err := secretCmd(context.Background(), f, []string{"list"}, nil, nil, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "telegram.token") || strings.Contains(out.String(), "\x1b") {
		t.Fatalf("list %q", out.String())
	}
	if err := secretCmd(context.Background(), f, []string{"rm", "telegram.token"}, nil, strings.NewReader("no\n"), &out); err == nil || f.deleted != "" {
		t.Fatal("deleted without yes")
	}
	if err := secretCmd(context.Background(), f, []string{"rm", "telegram.token"}, nil, strings.NewReader("yes\n"), &out); err != nil || f.deleted != "telegram.token" {
		t.Fatalf("rm: %v", err)
	}
	// The value is never taken from the command line.
	if err := secretCmd(context.Background(), f, []string{"set", "x", "value"}, value, nil, &out); err == nil {
		t.Fatal("value accepted as argument")
	}
}

func TestReadValueStripsOneLineEndingOnly(t *testing.T) {
	for in, want := range map[string]string{"tok\n": "tok", "tok\r\n": "tok", "tok\n\n": "tok\n", "tok": "tok", "tok\r": "tok\r", "tok\r\r\n": "tok\r"} {
		got, err := readValue(strings.NewReader(in))
		if err != nil || !bytes.Equal(got, []byte(want)) {
			t.Errorf("%q -> %q %v", in, got, err)
		}
	}
	if _, err := readValue(errReader{}); err == nil {
		t.Error("read error ignored")
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("boom") }

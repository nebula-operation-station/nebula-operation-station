// SPDX-License-Identifier: AGPL-3.0-or-later

package security

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/nebula-operation-station/nebula-operation-station/internal/peercred"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

const secretValue = "s3cr3t-provider-token-0815"

func (h *harness) vaultState() pb.VaultState {
	h.t.Helper()
	s, err := h.client.GetStatus(h.ctx(), &pb.GetStatusRequest{})
	if err != nil {
		h.t.Fatal(err)
	}
	return s.GetVaultState()
}

// Spec 06 vault: created by the admin, unlocked with the executor
// passphrase, locked with the executor, kept across restarts.
func TestM2_VaultLifecycle(t *testing.T) {
	dir := privateDir(t)
	h := newHarness(t, harnessOptions{dataDir: dir})
	if h.vaultState() != pb.VaultState_VAULT_STATE_NOT_INITIALIZED {
		t.Fatal("fresh executor has a vault")
	}
	// Without a vault, unlock behaves as before.
	r, err := h.client.Unlock(h.ctx(), &pb.UnlockRequest{Passphrase: []byte(passphrase)})
	if err != nil || !r.GetKeysUnlocked() || r.GetVaultState() != pb.VaultState_VAULT_STATE_NOT_INITIALIZED {
		t.Fatalf("unlock: %v %v", r, err)
	}
	_, err = h.client.SetSecret(h.ctx(), &pb.SetSecretRequest{Id: "telegram.token", Value: []byte(secretValue)})
	wantCode(t, err, codes.FailedPrecondition, "not initialized")

	_, err = h.client.InitVault(h.ctx(), &pb.InitVaultRequest{Passphrase: []byte("too short")})
	wantCode(t, err, codes.InvalidArgument, "32")
	if _, err := h.client.InitVault(h.ctx(), &pb.InitVaultRequest{Passphrase: []byte(passphrase)}); err != nil {
		t.Fatal(err)
	}
	_, err = h.client.InitVault(h.ctx(), &pb.InitVaultRequest{Passphrase: []byte(passphrase)})
	wantCode(t, err, codes.FailedPrecondition, "already")
	if h.vaultState() != pb.VaultState_VAULT_STATE_UNLOCKED {
		t.Fatal("vault not unlocked after init")
	}
	s, err := h.client.SetSecret(h.ctx(), &pb.SetSecretRequest{Id: "telegram.token", Value: []byte(secretValue)})
	if err != nil || s.GetVersion() != 1 {
		t.Fatalf("set: %v %v", s, err)
	}
	_, err = h.client.SetSecret(h.ctx(), &pb.SetSecretRequest{Id: "../etc", Value: []byte("x")})
	wantCode(t, err, codes.InvalidArgument, "")
	h.requireAudit("secret_set", "telegram.token")

	// Lock: the vault key is gone with the SSH keys.
	if _, err := h.client.Lock(h.ctx(), &pb.LockRequest{}); err != nil {
		t.Fatal(err)
	}
	if h.vaultState() != pb.VaultState_VAULT_STATE_LOCKED {
		t.Fatal("vault still unlocked after lock")
	}
	_, err = h.client.SetSecret(h.ctx(), &pb.SetSecretRequest{Id: "telegram.token", Value: []byte("new")})
	wantCode(t, err, codes.FailedPrecondition, "locked")
	_, err = h.client.DeleteSecret(h.ctx(), &pb.DeleteSecretRequest{Id: "telegram.token"})
	wantCode(t, err, codes.FailedPrecondition, "locked")
	l, err := h.client.ListSecrets(h.ctx(), &pb.ListSecretsRequest{})
	if err != nil || len(l.GetSecrets()) != 1 || l.GetSecrets()[0].GetId() != "telegram.token" || l.GetVaultState() != pb.VaultState_VAULT_STATE_LOCKED {
		t.Fatalf("list while locked: %v %v", l, err)
	}
	_, err = h.client.Unlock(h.ctx(), &pb.UnlockRequest{Passphrase: []byte(passphrase + "x")})
	wantCode(t, err, codes.Unauthenticated, "")

	// Restart: the vault stays locked until `nebula unlock`.
	h.stop()
	h = newHarness(t, harnessOptions{dataDir: dir})
	if h.vaultState() != pb.VaultState_VAULT_STATE_LOCKED {
		t.Fatal("vault unlocked after restart")
	}
	r, err = h.client.Unlock(h.ctx(), &pb.UnlockRequest{Passphrase: []byte(passphrase)})
	if err != nil || !r.GetKeysUnlocked() || r.GetVaultState() != pb.VaultState_VAULT_STATE_UNLOCKED {
		t.Fatalf("one unlock for both: %v %v", r, err)
	}
	s, err = h.client.SetSecret(h.ctx(), &pb.SetSecretRequest{Id: "telegram.token", Value: []byte("rotated")})
	if err != nil || s.GetVersion() != 2 {
		t.Fatalf("rotate: %v %v", s, err)
	}
	if _, err := h.client.DeleteSecret(h.ctx(), &pb.DeleteSecretRequest{Id: "telegram.token"}); err != nil {
		t.Fatal(err)
	}
	_, err = h.client.DeleteSecret(h.ctx(), &pb.DeleteSecretRequest{Id: "telegram.token"})
	wantCode(t, err, codes.NotFound, "")

	// Neither the value nor the passphrase reaches the log or a file in
	// clear.
	for _, needle := range []string{secretValue, passphrase} {
		if strings.Contains(h.logs.String(), needle) {
			t.Fatalf("log contains %q", needle)
		}
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		b, _ := os.ReadFile(dir + "/" + e.Name())
		if strings.Contains(string(b), secretValue) {
			t.Fatalf("%s contains the secret in clear", e.Name())
		}
	}
}

// A different vault passphrase: unlock tells which part did not fit, and
// each part can be unlocked alone.
func TestM2_VaultWithItsOwnPassphrase(t *testing.T) {
	const vaultPass = "another generated passphrase, 40 characters"
	h := newHarness(t, harnessOptions{})
	if _, err := h.client.InitVault(h.ctx(), &pb.InitVaultRequest{Passphrase: []byte(vaultPass)}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.client.Lock(h.ctx(), &pb.LockRequest{}); err != nil {
		t.Fatal(err)
	}
	r, err := h.client.Unlock(h.ctx(), &pb.UnlockRequest{Passphrase: []byte(passphrase)})
	if err != nil || !r.GetKeysUnlocked() || !r.GetVaultWrongPassphrase() || r.GetVaultState() != pb.VaultState_VAULT_STATE_LOCKED {
		t.Fatalf("keys passphrase: %v %v", r, err)
	}
	r, err = h.client.Unlock(h.ctx(), &pb.UnlockRequest{Passphrase: []byte(vaultPass), Scope: pb.UnlockScope_UNLOCK_SCOPE_VAULT})
	if err != nil || r.GetVaultState() != pb.VaultState_VAULT_STATE_UNLOCKED || r.GetKeysUnlocked() {
		t.Fatalf("vault scope: %v %v", r, err)
	}
	if _, err := h.client.Lock(h.ctx(), &pb.LockRequest{}); err != nil {
		t.Fatal(err)
	}
	r, err = h.client.Unlock(h.ctx(), &pb.UnlockRequest{Passphrase: []byte(vaultPass)})
	if err != nil || r.GetKeysUnlocked() || !r.GetKeysWrongPassphrase() || r.GetVaultState() != pb.VaultState_VAULT_STATE_UNLOCKED {
		t.Fatalf("vault passphrase: %v %v\n%s", r, err, h.logs.String())
	}
	if st, _ := h.client.GetStatus(h.ctx(), &pb.GetStatusRequest{}); st.GetUnlocked() {
		t.Fatal("keys unlocked with the vault passphrase")
	}
	_, err = h.client.Unlock(h.ctx(), &pb.UnlockRequest{Passphrase: []byte(vaultPass), Scope: pb.UnlockScope_UNLOCK_SCOPE_KEYS})
	wantCode(t, err, codes.Unauthenticated, "")
}

func TestM2_VaultIsAdminOnly(t *testing.T) {
	uid := uint32(os.Getuid())
	h := newHarness(t, harnessOptions{uidRoles: map[uint32][]peercred.Role{uid: {peercred.RoleServer}}})
	_, err := h.client.InitVault(h.ctx(), &pb.InitVaultRequest{Passphrase: []byte(passphrase)})
	wantCode(t, err, codes.PermissionDenied, "")
	_, err = h.client.SetSecret(h.ctx(), &pb.SetSecretRequest{Id: "x", Value: []byte("y")})
	wantCode(t, err, codes.PermissionDenied, "")
	_, err = h.client.ListSecrets(h.ctx(), &pb.ListSecretsRequest{})
	wantCode(t, err, codes.PermissionDenied, "")
	_, err = h.client.DeleteSecret(h.ctx(), &pb.DeleteSecretRequest{Id: "x"})
	wantCode(t, err, codes.PermissionDenied, "")
}

// No RPC can return a secret value: no method reads one out, and no
// response message of the vault RPCs has a bytes field.
func TestM2_NoRPCReturnsSecretValues(t *testing.T) {
	svc := pb.File_nebula_executor_v1_executor_proto.Services().ByName("ExecutorService")
	reveal := regexp.MustCompile(`(?i)(get|read|open|reveal|export|dump).*(secret|vault)`)
	for i := 0; i < svc.Methods().Len(); i++ {
		m := svc.Methods().Get(i)
		if reveal.MatchString(string(m.Name())) {
			t.Errorf("method %s looks like it reveals vault content", m.Name())
		}
	}
	for _, msg := range []proto.Message{&pb.InitVaultResponse{}, &pb.SetSecretResponse{}, &pb.ListSecretsResponse{}, &pb.DeleteSecretResponse{}, &pb.UnlockResponse{}, &pb.GetStatusResponse{}} {
		checkNoBytes(t, msg.ProtoReflect().Descriptor(), map[protoreflect.FullName]bool{})
	}
}

func checkNoBytes(t *testing.T, d protoreflect.MessageDescriptor, seen map[protoreflect.FullName]bool) {
	t.Helper()
	if seen[d.FullName()] {
		return
	}
	seen[d.FullName()] = true
	for i := 0; i < d.Fields().Len(); i++ {
		f := d.Fields().Get(i)
		switch f.Kind() {
		case protoreflect.BytesKind:
			t.Errorf("%s.%s is a bytes field", d.FullName(), f.Name())
		case protoreflect.MessageKind:
			checkNoBytes(t, f.Message(), seen)
		}
	}
}

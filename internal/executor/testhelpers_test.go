// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/nebula-operation-station/nebula-operation-station/internal/keyring"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vault"
)

// testVaultParams is the Argon2id cost test vaults use. vault.MinParams
// needs 256 MiB and three passes per Init or Unlock, which takes more than a
// second under -race and dominated the package's test time. Every test vault
// lowers its floor to these params with SetMinParams/SetVaultParams, the
// test-only hook the vault package provides; the production floor and its
// enforcement are covered by the vault package's own tests.
var testVaultParams = vault.Params{Time: 1, MemoryKiB: 64, Threads: 1}

// sharedKeys is one unlocked keyring holding the shared credential key.
// keyring.Unlock runs the bcrypt KDF of the OpenSSH key format, which takes
// about 1.4 s under -race; doing it once per test binary instead of once
// per reconcileEnv removes most of the package's test time. A keyring only
// changes state on Lock and Unlock, so envs that never lock it cannot
// affect each other. Tests that lock the keyring call
// (*reconcileEnv).usePrivateKeyring first; newReconcileEnv fails any test
// that leaves the shared keyring locked.
var sharedKeys struct {
	once sync.Once
	dir  string
	kr   *keyring.Keyring
	err  error
}

// TestMain removes the shared keyring's key directory after the run.
func TestMain(m *testing.M) {
	code := m.Run()
	if sharedKeys.dir != "" {
		_ = os.RemoveAll(sharedKeys.dir)
	}
	os.Exit(code)
}

// sharedTestKeyring returns the shared unlocked keyring and its public key.
func sharedTestKeyring(t *testing.T) (*keyring.Keyring, ssh.PublicKey) {
	t.Helper()
	keyPEM, pub := testCredentialKey(t)
	k := &sharedKeys
	k.once.Do(func() {
		dir, err := os.MkdirTemp("", "executor-test-keys-")
		if err != nil {
			k.err = fmt.Errorf("shared key directory: %w", err)
			return
		}
		k.dir = dir
		k.kr, k.err = unlockTestKeyring(dir, keyPEM)
	})
	if k.err != nil {
		t.Fatal(k.err)
	}
	return k.kr, pub
}

// newPrivateTestKeyring returns an unlocked keyring of its own, with its key
// directory under dir, for tests that lock or re-unlock the keyring.
func newPrivateTestKeyring(t *testing.T, dir string) *keyring.Keyring {
	t.Helper()
	keyPEM, _ := testCredentialKey(t)
	kr, err := unlockTestKeyring(dir, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return kr
}

// unlockTestKeyring writes keyPEM as the "cred" key into dir/keys and
// returns the unlocked keyring reading that directory.
func unlockTestKeyring(dir string, keyPEM []byte) (*keyring.Keyring, error) {
	keysDir := filepath.Join(dir, "keys")
	if err := os.MkdirAll(keysDir, 0o700); err != nil {
		return nil, fmt.Errorf("key directory: %w", err)
	}
	if err := os.WriteFile(filepath.Join(keysDir, "cred.key"), keyPEM, 0o600); err != nil {
		return nil, fmt.Errorf("write credential key: %w", err)
	}
	kr := keyring.New(keysDir)
	if _, err := kr.Unlock([]byte(testPassphrase)); err != nil {
		return nil, fmt.Errorf("unlock test keyring: %w", err)
	}
	return kr, nil
}

// usePrivateKeyring gives e's Service a keyring of its own instead of the
// shared one. Call it before anything that locks the keyring.
func (e *reconcileEnv) usePrivateKeyring() {
	e.t.Helper()
	e.svc.keys = newPrivateTestKeyring(e.t, e.t.TempDir())
}

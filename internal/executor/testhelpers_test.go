// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
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
// It fails t if the keyring is locked when t ends; a test that locks the
// keyring must use a private one (newPrivateTestKeyring).
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
	kr := k.kr
	t.Cleanup(func() {
		if !kr.Unlocked() {
			t.Error("test locked the shared keyring; use a private keyring before locking")
			if _, err := kr.Unlock([]byte(testPassphrase)); err != nil {
				t.Errorf("re-unlock shared keyring: %v", err)
			}
		}
	})
	return kr, pub
}

// templateDB holds the bytes of a freshly migrated executor database.
// Applying all migrations takes about 0.4 s under -race; copying the
// migrated file takes milliseconds. executordb's own tests cover migrating
// an empty database.
var templateDB struct {
	once sync.Once
	raw  []byte
	err  error
}

// openTestDB opens the executor database in dir (a private directory). If
// dir holds no database yet, it starts from a copy of the migrated
// template instead of migrating an empty file. The database is closed when
// t ends.
func openTestDB(t *testing.T, dir string) *executordb.DB {
	t.Helper()
	path := filepath.Join(dir, executordb.FileName)
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		tp := &templateDB
		tp.once.Do(func() { tp.raw, tp.err = buildTemplateDB() })
		if tp.err != nil {
			t.Fatal(tp.err)
		}
		if err := os.WriteFile(path, tp.raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	db, err := executordb.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// buildTemplateDB migrates an empty database in a scratch directory and
// returns the closed database file.
func buildTemplateDB() ([]byte, error) {
	dir, err := os.MkdirTemp("", "executor-test-db-")
	if err != nil {
		return nil, fmt.Errorf("template directory: %w", err)
	}
	defer os.RemoveAll(dir)
	db, err := executordb.Open(dir)
	if err != nil {
		return nil, fmt.Errorf("migrate template: %w", err)
	}
	if err := db.Close(); err != nil {
		return nil, fmt.Errorf("close template: %w", err)
	}
	// Close checkpoints the WAL into the main file; a leftover WAL would
	// mean the copy misses data.
	if _, err := os.Lstat(filepath.Join(dir, executordb.FileName+"-wal")); err == nil {
		return nil, fmt.Errorf("template database left a WAL file")
	}
	raw, err := os.ReadFile(filepath.Join(dir, executordb.FileName))
	if err != nil {
		return nil, fmt.Errorf("read template: %w", err)
	}
	return raw, nil
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

// SPDX-License-Identifier: AGPL-3.0-or-later

package vault

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
)

var testParams = Params{Time: 1, MemoryKiB: 64, Threads: 1}

const pass = "correct horse battery staple 0123456789"

func newDB(t *testing.T) (*executordb.DB, string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	db, err := executordb.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db, dir
}

func initVault(t *testing.T) (*Vault, *executordb.DB) {
	t.Helper()
	db, _ := newDB(t)
	v := newTestVault(db)
	if err := v.Init([]byte(pass), testParams, "admin"); err != nil {
		t.Fatal(err)
	}
	return v, db
}

func state(t *testing.T, v *Vault) State {
	t.Helper()
	s, err := v.State()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestLifecycle(t *testing.T) {
	db, dir := newDB(t)
	v := newTestVault(db)
	if state(t, v) != StateNotInitialized {
		t.Fatal("fresh vault initialized")
	}
	if err := v.Unlock([]byte(pass)); !errors.Is(err, ErrNotInitialized) {
		t.Fatalf("unlock before init: %v", err)
	}
	if err := v.Init([]byte("short"), testParams, "admin"); !errors.Is(err, ErrWeakPassphrase) {
		t.Fatalf("weak passphrase: %v", err)
	}
	if err := v.Init([]byte(pass), testParams, "admin"); err != nil {
		t.Fatal(err)
	}
	if state(t, v) != StateUnlocked {
		t.Fatal("not unlocked after init")
	}
	if err := v.Init([]byte(pass), testParams, "admin"); !errors.Is(err, ErrInitialized) {
		t.Fatalf("second init: %v", err)
	}
	ver, err := v.Put("telegram.token", []byte("123:abc"), "admin")
	if err != nil || ver != 1 {
		t.Fatalf("put: %d %v", ver, err)
	}
	if ver, err = v.Put("telegram.token", []byte("456:def"), "admin"); err != nil || ver != 2 {
		t.Fatalf("update: %d %v", ver, err)
	}
	v.Lock()
	if state(t, v) != StateLocked {
		t.Fatal("not locked")
	}
	if _, err := v.Open("telegram.token"); !errors.Is(err, ErrLocked) {
		t.Fatalf("open while locked: %v", err)
	}
	if _, err := v.Put("x", []byte("y"), "admin"); !errors.Is(err, ErrLocked) {
		t.Fatalf("put while locked: %v", err)
	}
	if err := v.Delete("telegram.token"); !errors.Is(err, ErrLocked) {
		t.Fatalf("delete while locked: %v", err)
	}
	if l, err := v.List(); err != nil || len(l) != 1 || l[0].ID != "telegram.token" || l[0].Version != 2 {
		t.Fatalf("list while locked: %+v %v", l, err)
	}
	if err := v.Unlock([]byte(pass + "x")); !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("wrong passphrase: %v", err)
	}

	// A restart: a new vault on the reopened database.
	db.Close()
	db2, err := executordb.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db2.Close()
	v2 := newTestVault(db2)
	if state(t, v2) != StateLocked {
		t.Fatal("vault unlocked after restart")
	}
	if err := v2.Unlock([]byte(pass)); err != nil {
		t.Fatal(err)
	}
	got, err := v2.Open("telegram.token")
	if err != nil || string(got) != "456:def" {
		t.Fatalf("open: %q %v", got, err)
	}
	if err := v2.Delete("telegram.token"); err != nil {
		t.Fatal(err)
	}
	if _, err := v2.Open("telegram.token"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("open deleted: %v", err)
	}
	if err := v2.Delete("telegram.token"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("delete twice: %v", err)
	}
}

func TestNoPlaintextAtRest(t *testing.T) {
	db, dir := newDB(t)
	v := newTestVault(db)
	if err := v.Init([]byte(pass), testParams, "admin"); err != nil {
		t.Fatal(err)
	}
	secret := []byte("very-secret-api-token-value-4711")
	if _, err := v.Put("api", secret, "admin"); err != nil {
		t.Fatal(err)
	}
	db.Close()
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		b, err := os.ReadFile(dir + "/" + e.Name())
		if err != nil {
			continue
		}
		if bytes.Contains(b, secret) || bytes.Contains(b, []byte(pass)) {
			t.Fatalf("%s contains plaintext", e.Name())
		}
	}
}

// Blobs moved between records or versions do not decrypt.
func TestAssociatedDataBindsIDAndVersion(t *testing.T) {
	v, db := initVault(t)
	for _, id := range []string{"a", "b"} {
		if _, err := v.Put(id, []byte("value-"+id), "admin"); err != nil {
			t.Fatal(err)
		}
	}
	a, _ := db.GetSecret("a")
	b, _ := db.GetSecret("b")

	// b's blobs under a's ID with the same version 1: only the ID differs.
	if _, err := db.DeleteSecret("a"); err != nil {
		t.Fatal(err)
	}
	swap(t, db, executordb.VaultSecret{ID: "a", Version: 1, WrappedDEK: b.WrappedDEK, Sealed: b.Sealed, UpdatedBy: "x"})
	if _, err := v.Open("a"); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("swapped blob opened: %v", err)
	}
	// a's own version-1 blobs stored as version 2 (rollback disguised as an update).
	swap(t, db, executordb.VaultSecret{ID: "a", Version: 2, WrappedDEK: a.WrappedDEK, Sealed: a.Sealed, UpdatedBy: "x"})
	if _, err := v.Open("a"); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("blob under another version opened: %v", err)
	}
	// Flipped ciphertext byte.
	c, _ := db.GetSecret("b")
	c.Sealed[len(c.Sealed)-1] ^= 1
	c.Version++
	swap(t, db, c)
	if _, err := v.Open("b"); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("tampered blob opened: %v", err)
	}
}

func swap(t *testing.T, db *executordb.DB, s executordb.VaultSecret) {
	t.Helper()
	if err := db.PutSecret(s); err != nil {
		t.Fatal(err)
	}
}

func TestInputLimits(t *testing.T) {
	v, _ := initVault(t)
	for _, id := range []string{"", "Upper", "-lead", "a b", "a/b", strings.Repeat("a", 65), "ü"} {
		if _, err := v.Put(id, []byte("x"), "admin"); !errors.Is(err, ErrInvalidID) {
			t.Errorf("id %q: %v", id, err)
		}
	}
	if _, err := v.Put("x", nil, "admin"); !errors.Is(err, ErrInvalidValue) {
		t.Errorf("empty value: %v", err)
	}
	if _, err := v.Put("x", make([]byte, MaxValueSize+1), "admin"); !errors.Is(err, ErrInvalidValue) {
		t.Errorf("large value: %v", err)
	}
	if _, err := v.Put("x", make([]byte, MaxValueSize), "admin"); err != nil {
		t.Errorf("max value: %v", err)
	}
	if err := v.Unlock(make([]byte, MaxPassphraseLen+1)); !errors.Is(err, ErrWrongPassphrase) {
		t.Errorf("huge passphrase: %v", err)
	}
}

func TestConcurrentPutsKeepOneVersionEach(t *testing.T) {
	v, _ := initVault(t)
	var wg sync.WaitGroup
	var mu sync.Mutex
	versions := map[int64]bool{}
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				ver, err := v.Put("k", []byte("v"), "admin")
				if errors.Is(err, ErrConcurrentChange) {
					continue
				}
				if err != nil {
					t.Error(err)
					return
				}
				mu.Lock()
				if versions[ver] {
					t.Errorf("version %d twice", ver)
				}
				versions[ver] = true
				mu.Unlock()
				return
			}
		}()
	}
	wg.Wait()
	if len(versions) != 8 {
		t.Fatalf("versions %v", versions)
	}
	if _, err := v.Open("k"); err != nil {
		t.Fatal(err)
	}
}

func TestDefaultParamsFollowSpec(t *testing.T) {
	if DefaultParams.MemoryKiB != 256<<10 || DefaultParams.Time != 3 {
		t.Fatalf("defaults %+v", DefaultParams)
	}
}

func newTestVault(s Store) *Vault {
	v := New(s)
	v.SetMinParams(testParams)
	return v
}

func TestWeakParamsAreRefused(t *testing.T) {
	db, _ := newDB(t)
	// The production floor refuses a cheap vault at creation ...
	if err := New(db).Init([]byte(pass), testParams, "admin"); !errors.Is(err, ErrWeakParams) {
		t.Fatalf("weak Init: %v", err)
	}
	if err := New(db).Init([]byte(pass), Params{Time: 3, MemoryKiB: 128 << 10, Threads: 4}, "admin"); !errors.Is(err, ErrWeakParams) {
		t.Fatalf("128 MiB accepted: %v", err)
	}
	// ... and when cheap parameters are read back from the database.
	if err := newTestVault(db).Init([]byte(pass), testParams, "admin"); err != nil {
		t.Fatal(err)
	}
	if err := New(db).Unlock([]byte(pass)); !errors.Is(err, ErrWeakParams) {
		t.Fatalf("weak stored parameters used: %v", err)
	}
	if DefaultParams.below(MinParams) || MinParams.below(MinParams) {
		t.Fatal("the defaults must meet the floor")
	}
}

func TestLockWinsOverAnUnlockInFlight(t *testing.T) {
	v, _ := initVault(t)
	v.Lock()
	// An unlock reads the generation before its (slow) key derivation; a
	// Lock in between makes it drop the derived key.
	gen := v.generation()
	v.Lock()
	if err := v.setMaster(make([]byte, keyLen), gen); !errors.Is(err, ErrLockedDuringUnlock) {
		t.Fatalf("stale unlock installed: %v", err)
	}
	if state(t, v) != StateLocked {
		t.Fatal("vault unlocked after a Lock that came later")
	}
	if err := v.Unlock([]byte(pass)); err != nil || state(t, v) != StateUnlocked {
		t.Fatalf("a fresh unlock must work: %v", err)
	}
}

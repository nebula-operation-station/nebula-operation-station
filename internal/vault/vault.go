// SPDX-License-Identifier: AGPL-3.0-or-later

// Package vault is the executor's secret vault (spec 06): API tokens,
// provider credentials and secret runbook parameters, never SSH keys.
//
//   - Master key: 256 random bits, stored only wrapped.
//   - Unlock: passphrase -> Argon2id (parameters stored with the vault;
//     default 256 MiB, 3 passes) -> key-encryption key -> master key.
//   - Each secret has its own data key; values and data keys are sealed
//     with XChaCha20-Poly1305 and the secret's ID and version as
//     associated data, so blobs cannot be swapped between records.
//
// There is deliberately no API that returns a value to a caller outside
// the executor: Open is for the executor's own use at run time
// (Milestone 4). The passphrase is never stored. Go cannot reliably wipe
// memory; Lock drops and zeroes the master key on a best-effort basis.
package vault

import (
	"crypto/rand"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
)

// Limits.
const (
	// MinPassphraseLen follows spec 06: at least 32 random characters
	// from a password manager.
	MinPassphraseLen = 32
	MaxPassphraseLen = 1024
	MaxValueSize     = 64 << 10
	keyLen           = chacha20poly1305.KeySize
	saltLen          = 16
	format           = 1
)

// Params are the Argon2id parameters.
type Params struct {
	Time      uint32
	MemoryKiB uint32
	Threads   uint8
}

// DefaultParams are the spec 06 defaults.
var DefaultParams = Params{Time: 3, MemoryKiB: 256 << 10, Threads: 4}

// MinParams is the weakest Argon2id cost the vault accepts, both when it is
// created and when stored parameters are read back: an attacker with a copy
// of executor.db guesses offline at the cost these parameters set, so a
// cheaper vault (a hand-edited or restored database, a future option) is
// refused instead of used. Threads do not raise an attacker's cost and are
// not part of the floor.
var MinParams = Params{Time: 3, MemoryKiB: 256 << 10, Threads: 1}

// below reports whether p is cheaper than the floor.
func (p Params) below(floor Params) bool {
	return p.Time < floor.Time || p.MemoryKiB < floor.MemoryKiB || p.Threads < max(floor.Threads, 1)
}

// Errors.
var (
	ErrNotInitialized   = errors.New("vault: not initialized; run `nebula vault init`")
	ErrInitialized      = errors.New("vault: already initialized")
	ErrLocked           = errors.New("vault: locked; run `nebula unlock`")
	ErrWrongPassphrase  = errors.New("vault: wrong passphrase")
	ErrWeakPassphrase   = fmt.Errorf("vault: the passphrase must have at least %d characters (use a generated one)", MinPassphraseLen)
	ErrInvalidID        = errors.New("vault: secret IDs are 1-64 characters a-z, 0-9, '.', '_' or '-', starting with a letter or digit")
	ErrInvalidValue     = fmt.Errorf("vault: a secret value must be 1 to %d bytes", MaxValueSize)
	ErrNotFound         = errors.New("vault: secret not found")
	ErrCorrupt          = errors.New("vault: stored data does not decrypt (corrupted or tampered)")
	ErrConcurrentChange = errors.New("vault: secret changed concurrently; retry")
	// ErrLockedDuringUnlock means Lock was called while Unlock was running;
	// Lock wins and the vault stays locked (as in the keyring).
	ErrLockedDuringUnlock = errors.New("vault: locked while unlocking; still locked")
	// ErrWeakParams means Argon2id parameters below MinParams.
	ErrWeakParams = errors.New("vault: Argon2id parameters below the minimum (3 passes, 256 MiB)")
)

var idRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// Store is the persistence the vault needs (executordb.DB).
type Store interface {
	InitVault(executordb.VaultMeta) error
	GetVault() (executordb.VaultMeta, error)
	PutSecret(executordb.VaultSecret) error
	GetSecret(id string) (executordb.VaultSecret, error)
	ListSecrets() ([]executordb.VaultSecret, error)
	DeleteSecret(id string) (bool, error)
}

// State of the vault.
type State int

// States.
const (
	StateNotInitialized State = iota
	StateLocked
	StateUnlocked
)

// Info describes one secret without its value.
type Info struct {
	ID        string
	Version   int64
	UpdatedAt time.Time
	UpdatedBy string
}

// Vault is safe for concurrent use.
type Vault struct {
	store Store
	// unlockMu serializes Init and Unlock: each Argon2id run takes the
	// configured memory, so parallel attempts are not allowed to multiply it.
	unlockMu sync.Mutex
	mu       sync.RWMutex
	master   []byte // nil while locked
	// gen increases on every Lock (under mu); an Init or Unlock that started
	// before a Lock does not install its master key.
	gen uint64
	// floor is MinParams unless a test lowered it.
	floor Params
}

// New returns a locked vault on store.
func New(store Store) *Vault {
	if store == nil {
		panic("vault: New needs a store")
	}
	return &Vault{store: store, floor: MinParams}
}

// SetMinParams lowers the parameter floor. Only tests use it, to keep
// Argon2id fast; production code never calls it.
func (v *Vault) SetMinParams(p Params) {
	v.unlockMu.Lock()
	v.floor = p
	v.unlockMu.Unlock()
}

func (v *Vault) generation() uint64 {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.gen
}

// State reports whether the vault exists and is unlocked.
func (v *Vault) State() (State, error) {
	v.mu.RLock()
	unlocked := v.master != nil
	v.mu.RUnlock()
	if unlocked {
		return StateUnlocked, nil
	}
	if _, err := v.store.GetVault(); errors.Is(err, executordb.ErrNoVault) {
		return StateNotInitialized, nil
	} else if err != nil {
		return 0, err
	}
	return StateLocked, nil
}

func checkPassphrase(p []byte) error {
	n := len([]rune(string(p)))
	if n < MinPassphraseLen || len(p) > MaxPassphraseLen {
		return ErrWeakPassphrase
	}
	return nil
}

func kek(pass []byte, salt []byte, p Params) []byte {
	return argon2.IDKey(pass, salt, p.Time, p.MemoryKiB, p.Threads, keyLen)
}

var masterAD = []byte("nebula-vault-master-v1")

// Init creates the vault with a new random master key, wrapped under
// passphrase, and leaves it unlocked. by names the caller for the record.
func (v *Vault) Init(passphrase []byte, p Params, by string) error {
	if err := checkPassphrase(passphrase); err != nil {
		return err
	}
	v.unlockMu.Lock()
	defer v.unlockMu.Unlock()
	if p.Time == 0 || p.MemoryKiB < 8 || p.Threads == 0 || p.below(v.floor) {
		return ErrWeakParams
	}
	gen := v.generation()
	if _, err := v.store.GetVault(); err == nil {
		return ErrInitialized
	} else if !errors.Is(err, executordb.ErrNoVault) {
		return err
	}
	master := make([]byte, keyLen)
	salt := make([]byte, saltLen)
	if _, err := rand.Read(master); err != nil {
		return fmt.Errorf("vault: random: %w", err)
	}
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("vault: random: %w", err)
	}
	k := kek(passphrase, salt, p)
	wrapped, err := seal(k, master, masterAD)
	wipe(k)
	if err != nil {
		return err
	}
	err = v.store.InitVault(executordb.VaultMeta{Format: format, KDFTime: p.Time, KDFMemoryKiB: p.MemoryKiB, KDFThreads: p.Threads,
		Salt: salt, WrappedMaster: wrapped, CreatedBy: by})
	if errors.Is(err, executordb.ErrVaultExists) {
		return ErrInitialized
	}
	if err != nil {
		return err
	}
	// The vault exists now; a Lock issued meanwhile keeps it locked.
	_ = v.setMaster(master, gen)
	return nil
}

// Unlock derives the key-encryption key from passphrase and unwraps the
// master key.
func (v *Vault) Unlock(passphrase []byte) error {
	if len(passphrase) == 0 || len(passphrase) > MaxPassphraseLen {
		return ErrWrongPassphrase
	}
	v.unlockMu.Lock()
	defer v.unlockMu.Unlock()
	gen := v.generation()
	m, err := v.store.GetVault()
	if errors.Is(err, executordb.ErrNoVault) {
		return ErrNotInitialized
	}
	if err != nil {
		return err
	}
	if m.Format != format || len(m.Salt) != saltLen {
		return ErrCorrupt
	}
	p := Params{Time: m.KDFTime, MemoryKiB: m.KDFMemoryKiB, Threads: m.KDFThreads}
	if p.below(v.floor) {
		return ErrWeakParams
	}
	k := kek(passphrase, m.Salt, p)
	master, err := open(k, m.WrappedMaster, masterAD)
	wipe(k)
	if err != nil || len(master) != keyLen {
		return ErrWrongPassphrase
	}
	return v.setMaster(master, gen)
}

// setMaster installs master unless a Lock happened after generation gen
// was read; then it wipes master and returns ErrLockedDuringUnlock.
func (v *Vault) setMaster(master []byte, gen uint64) error {
	v.mu.Lock()
	if v.gen != gen {
		v.mu.Unlock()
		wipe(master)
		return ErrLockedDuringUnlock
	}
	old := v.master
	v.master = master
	v.mu.Unlock()
	wipe(old)
	return nil
}

// Lock drops the master key.
func (v *Vault) Lock() {
	v.mu.Lock()
	m := v.master
	v.master = nil
	v.gen++
	v.mu.Unlock()
	wipe(m)
}

// withMaster runs f with a copy of the master key.
func (v *Vault) withMaster(f func(master []byte) error) error {
	v.mu.RLock()
	if v.master == nil {
		v.mu.RUnlock()
		return ErrLocked
	}
	m := append([]byte(nil), v.master...)
	v.mu.RUnlock()
	defer wipe(m)
	return f(m)
}

func ad(kind, id string, version int64) []byte {
	return []byte("nebula-vault-" + kind + "-v1\x00" + id + "\x00" + strconv.FormatInt(version, 10))
}

// unlocked runs f with the master key; while locked it reports whether
// the vault exists at all.
func (v *Vault) unlocked(f func(master []byte) error) error {
	err := v.withMaster(f)
	if errors.Is(err, ErrLocked) {
		if st, serr := v.State(); serr == nil && st == StateNotInitialized {
			return ErrNotInitialized
		}
	}
	return err
}

// Put stores value under id as a new version and returns that version.
func (v *Vault) Put(id string, value []byte, by string) (int64, error) {
	if !idRe.MatchString(id) {
		return 0, ErrInvalidID
	}
	if len(value) == 0 || len(value) > MaxValueSize {
		return 0, ErrInvalidValue
	}
	var version int64
	err := v.unlocked(func(master []byte) error {
		version = 1
		if cur, err := v.store.GetSecret(id); err == nil {
			version = cur.Version + 1
		} else if !errors.Is(err, executordb.ErrNoSecret) {
			return err
		}
		dek := make([]byte, keyLen)
		if _, err := rand.Read(dek); err != nil {
			return fmt.Errorf("vault: random: %w", err)
		}
		defer wipe(dek)
		wrapped, err := seal(master, dek, ad("dek", id, version))
		if err != nil {
			return err
		}
		sealed, err := seal(dek, value, ad("data", id, version))
		if err != nil {
			return err
		}
		err = v.store.PutSecret(executordb.VaultSecret{ID: id, Version: version, WrappedDEK: wrapped, Sealed: sealed, UpdatedBy: by})
		if errors.Is(err, executordb.ErrSecretVersion) {
			return ErrConcurrentChange
		}
		return err
	})
	return version, err
}

// Open decrypts secret id. It is for the executor's own use; no RPC
// returns its result.
func (v *Vault) Open(id string) ([]byte, error) {
	if !idRe.MatchString(id) {
		return nil, ErrInvalidID
	}
	var out []byte
	err := v.unlocked(func(master []byte) error {
		s, err := v.store.GetSecret(id)
		if errors.Is(err, executordb.ErrNoSecret) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		dek, err := open(master, s.WrappedDEK, ad("dek", s.ID, s.Version))
		if err != nil || len(dek) != keyLen {
			return ErrCorrupt
		}
		defer wipe(dek)
		out, err = open(dek, s.Sealed, ad("data", s.ID, s.Version))
		if err != nil {
			return ErrCorrupt
		}
		return nil
	})
	return out, err
}

// List returns the stored secrets without values. It works while locked:
// IDs are not secret.
func (v *Vault) List() ([]Info, error) {
	rows, err := v.store.ListSecrets()
	if err != nil {
		return nil, err
	}
	out := make([]Info, len(rows))
	for i, r := range rows {
		out[i] = Info{ID: r.ID, Version: r.Version, UpdatedAt: r.UpdatedAt, UpdatedBy: r.UpdatedBy}
	}
	return out, nil
}

// Delete removes secret id. It needs the unlocked vault, like Put, so a
// locked executor cannot be made to lose secrets.
func (v *Vault) Delete(id string) error {
	if !idRe.MatchString(id) {
		return ErrInvalidID
	}
	return v.unlocked(func([]byte) error {
		ok, err := v.store.DeleteSecret(id)
		if err != nil {
			return err
		}
		if !ok {
			return ErrNotFound
		}
		return nil
	})
}

func seal(key, plaintext, additional []byte) ([]byte, error) {
	a, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("vault: cipher: %w", err)
	}
	nonce := make([]byte, a.NonceSize(), a.NonceSize()+len(plaintext)+a.Overhead())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("vault: random: %w", err)
	}
	return a.Seal(nonce, nonce, plaintext, additional), nil
}

func open(key, blob, additional []byte) ([]byte, error) {
	a, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	if len(blob) < a.NonceSize()+a.Overhead() {
		return nil, ErrCorrupt
	}
	return a.Open(nil, blob[:a.NonceSize()], blob[a.NonceSize():], additional)
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

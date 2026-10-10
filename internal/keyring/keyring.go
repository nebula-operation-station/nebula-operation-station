// SPDX-License-Identifier: AGPL-3.0-or-later

// Package keyring holds the executor's SSH private keys in memory.
//
// Keys live on disk as passphrase-protected OpenSSH private keys, one file
// per credential reference ("<ref>.key"). Unlock decrypts all of them into an
// in-process agent keyring (golang.org/x/crypto/ssh/agent); no agent socket
// is ever exposed. Lock wipes the keyring.
//
// Stated limit (docs/threat-model.md): Go cannot reliably erase memory, so
// key material may linger in the heap until it is reused. The executor unit
// disables core dumps; operators should use encrypted or no swap.
package keyring

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// MaxKeyFileSize bounds key files read from disk.
const MaxKeyFileSize = 64 << 10

// MinRSABits is the smallest RSA key accepted.
const MinRSABits = 3072

var fileRe = regexp.MustCompile(`^([a-z0-9][a-z0-9_-]{0,63})\.key$`)

// Errors.
var (
	ErrLocked        = errors.New("keyring: locked")
	ErrUnknownRef    = errors.New("keyring: credential reference not loaded")
	ErrNoKeys        = errors.New("keyring: no key files found")
	ErrWrongPassword = errors.New("keyring: passphrase does not decrypt every key")
)

// Keyring is safe for concurrent use.
type Keyring struct {
	dir string

	mu       sync.Mutex
	agent    agent.Agent
	refs     map[string][]byte // ref -> marshalled public key
	unlocked bool
}

// New returns a locked keyring reading key files from dir.
func New(dir string) *Keyring {
	return &Keyring{dir: dir, agent: agent.NewKeyring(), refs: map[string][]byte{}}
}

// Unlock decrypts every key file with passphrase. It is all-or-nothing: if
// any file is unsafe or does not decrypt, the keyring stays locked. The
// passphrase slice is overwritten before returning (best effort).
func (k *Keyring) Unlock(passphrase []byte) ([]string, error) {
	defer clear(passphrase)
	if len(passphrase) == 0 {
		return nil, errors.New("keyring: empty passphrase")
	}

	entries, err := os.ReadDir(k.dir)
	if err != nil {
		return nil, fmt.Errorf("keyring: read key directory: %w", err)
	}

	type loaded struct {
		ref string
		key any
	}
	var keys []loaded
	var bad []string
	for _, e := range entries {
		m := fileRe.FindStringSubmatch(e.Name())
		if m == nil {
			continue
		}
		raw, err := readKeyFile(filepath.Join(k.dir, e.Name()))
		if err != nil {
			return nil, err
		}
		if _, err := ssh.ParseRawPrivateKey(raw); err == nil {
			return nil, fmt.Errorf("keyring: %s is not passphrase-protected; refusing to use it", e.Name())
		} else if !isPassphraseMissing(err) {
			return nil, fmt.Errorf("keyring: %s: %v", e.Name(), err)
		}
		key, err := ssh.ParseRawPrivateKeyWithPassphrase(raw, passphrase)
		clear(raw)
		if err != nil {
			bad = append(bad, m[1])
			continue
		}
		if err := checkKeyType(key); err != nil {
			return nil, fmt.Errorf("keyring: %s: %w", e.Name(), err)
		}
		keys = append(keys, loaded{ref: m[1], key: key})
	}
	if len(bad) > 0 {
		return nil, fmt.Errorf("%w: %s", ErrWrongPassword, strings.Join(bad, ", "))
	}
	if len(keys) == 0 {
		return nil, ErrNoKeys
	}

	fresh := agent.NewKeyring()
	refs := make(map[string][]byte, len(keys))
	for _, l := range keys {
		signer, err := ssh.NewSignerFromKey(l.key)
		if err != nil {
			return nil, fmt.Errorf("keyring: %s: %w", l.ref, err)
		}
		if err := fresh.Add(agent.AddedKey{PrivateKey: l.key, Comment: l.ref}); err != nil {
			return nil, fmt.Errorf("keyring: add %s: %w", l.ref, err)
		}
		refs[l.ref] = signer.PublicKey().Marshal()
	}

	k.mu.Lock()
	defer k.mu.Unlock()
	_ = k.agent.RemoveAll()
	k.agent, k.refs, k.unlocked = fresh, refs, true
	return sortedKeys(refs), nil
}

// Lock removes all keys from memory.
func (k *Keyring) Lock() {
	k.mu.Lock()
	defer k.mu.Unlock()
	_ = k.agent.RemoveAll()
	k.agent = agent.NewKeyring()
	k.refs = map[string][]byte{}
	k.unlocked = false
}

// Unlocked reports whether keys are loaded.
func (k *Keyring) Unlocked() bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.unlocked
}

// Refs returns the loaded credential references, sorted.
func (k *Keyring) Refs() []string {
	k.mu.Lock()
	defer k.mu.Unlock()
	return sortedKeys(k.refs)
}

// Signer returns the signer for exactly one credential reference. Callers
// must offer only this signer to a host (the IdentitiesOnly principle).
func (k *Keyring) Signer(ref string) (ssh.Signer, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if !k.unlocked {
		return nil, ErrLocked
	}
	want, ok := k.refs[ref]
	if !ok {
		return nil, ErrUnknownRef
	}
	signers, err := k.agent.Signers()
	if err != nil {
		return nil, err
	}
	for _, s := range signers {
		if slices.Equal(s.PublicKey().Marshal(), want) {
			return s, nil
		}
	}
	return nil, ErrUnknownRef
}

func readKeyFile(path string) ([]byte, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("keyring: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("keyring: %s is not a regular file", filepath.Base(path))
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("keyring: %s has mode %o; must not be accessible by group or others", filepath.Base(path), fi.Mode().Perm())
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Geteuid() {
		return nil, fmt.Errorf("keyring: %s is owned by uid %d, expected %d", filepath.Base(path), st.Uid, os.Geteuid())
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("keyring: %w", err)
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, MaxKeyFileSize+1))
	if err != nil {
		return nil, fmt.Errorf("keyring: %w", err)
	}
	if len(b) > MaxKeyFileSize {
		return nil, fmt.Errorf("keyring: %s is too large", filepath.Base(path))
	}
	return b, nil
}

func isPassphraseMissing(err error) bool {
	var pm *ssh.PassphraseMissingError
	return errors.As(err, &pm)
}

func checkKeyType(key any) error {
	switch k := key.(type) {
	case ed25519.PrivateKey, *ed25519.PrivateKey, *ecdsa.PrivateKey:
		return nil
	case *rsa.PrivateKey:
		if k.N.BitLen() < MinRSABits {
			return fmt.Errorf("RSA key has %d bits, need at least %d", k.N.BitLen(), MinRSABits)
		}
		return nil
	default:
		return fmt.Errorf("unsupported key type %T", key)
	}
}

func sortedKeys(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for r := range m {
		out = append(out, r)
	}
	slices.Sort(out)
	return out
}

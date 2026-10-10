// SPDX-License-Identifier: AGPL-3.0-or-later

package keyring

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

const pass = "correct horse battery staple, 32+ chars"

func writeKey(t *testing.T, dir, ref string, key any, passphrase string, mode os.FileMode) ssh.PublicKey {
	t.Helper()
	var block *pem.Block
	var err error
	if passphrase == "" {
		block, err = ssh.MarshalPrivateKey(key, ref)
	} else {
		block, err = ssh.MarshalPrivateKeyWithPassphrase(key, ref, []byte(passphrase))
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ref+".key"), pem.EncodeToMemory(block), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(dir, ref+".key"), mode); err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return signer.PublicKey()
}

func ed(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestUnlockSignerLock(t *testing.T) {
	dir := t.TempDir()
	pubA := writeKey(t, dir, "nebula-default", ed(t), pass, 0o600)
	pubB := writeKey(t, dir, "lab-b", ed(t), pass, 0o600)
	if err := os.WriteFile(filepath.Join(dir, "README"), []byte("ignored"), 0o600); err != nil {
		t.Fatal(err)
	}

	k := New(dir)
	if k.Unlocked() {
		t.Fatal("new keyring must be locked")
	}
	if _, err := k.Signer("nebula-default"); !errors.Is(err, ErrLocked) {
		t.Fatalf("locked keyring handed out a signer: %v", err)
	}

	p := []byte(pass)
	refs, err := k.Unlock(p)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(refs, []string{"lab-b", "nebula-default"}) {
		t.Fatalf("refs = %v", refs)
	}
	if strings.Trim(string(p), "\x00") != "" {
		t.Fatal("passphrase buffer was not cleared")
	}

	for ref, pub := range map[string]ssh.PublicKey{"nebula-default": pubA, "lab-b": pubB} {
		s, err := k.Signer(ref)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(s.PublicKey().Marshal(), pub.Marshal()) {
			t.Fatalf("%s: wrong key returned", ref)
		}
		sig, err := s.Sign(rand.Reader, []byte("data"))
		if err != nil || pub.Verify([]byte("data"), sig) != nil {
			t.Fatalf("%s: signature does not verify: %v", ref, err)
		}
	}
	if _, err := k.Signer("missing"); !errors.Is(err, ErrUnknownRef) {
		t.Fatalf("unknown ref: %v", err)
	}

	k.Lock()
	if k.Unlocked() || len(k.Refs()) != 0 {
		t.Fatal("lock did not clear the keyring")
	}
	if _, err := k.Signer("nebula-default"); !errors.Is(err, ErrLocked) {
		t.Fatalf("signer after lock: %v", err)
	}
}

func TestWrongPassphraseKeepsLocked(t *testing.T) {
	dir := t.TempDir()
	writeKey(t, dir, "a", ed(t), pass, 0o600)
	writeKey(t, dir, "b", ed(t), "a different passphrase entirely!", 0o600)
	k := New(dir)
	if _, err := k.Unlock([]byte(pass)); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("expected wrong password, got %v", err)
	}
	if k.Unlocked() {
		t.Fatal("partial unlock must not happen")
	}
}

func TestUnencryptedKeyRefused(t *testing.T) {
	dir := t.TempDir()
	writeKey(t, dir, "plain", ed(t), "", 0o600)
	if _, err := New(dir).Unlock([]byte(pass)); err == nil || !strings.Contains(err.Error(), "not passphrase-protected") {
		t.Fatalf("unencrypted key accepted: %v", err)
	}
}

func TestLoosePermissionsRefused(t *testing.T) {
	dir := t.TempDir()
	writeKey(t, dir, "loose", ed(t), pass, 0o640)
	if _, err := New(dir).Unlock([]byte(pass)); err == nil || !strings.Contains(err.Error(), "mode") {
		t.Fatalf("group-readable key accepted: %v", err)
	}
}

func TestSymlinkRefused(t *testing.T) {
	dir := t.TempDir()
	other := t.TempDir()
	writeKey(t, other, "target", ed(t), pass, 0o600)
	if err := os.Symlink(filepath.Join(other, "target.key"), filepath.Join(dir, "link.key")); err != nil {
		t.Fatal(err)
	}
	if _, err := New(dir).Unlock([]byte(pass)); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("symlinked key accepted: %v", err)
	}
}

func TestWeakRSARefused(t *testing.T) {
	dir := t.TempDir()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	writeKey(t, dir, "weak", k, pass, 0o600)
	if _, err := New(dir).Unlock([]byte(pass)); err == nil || !strings.Contains(err.Error(), "bits") {
		t.Fatalf("2048-bit RSA accepted: %v", err)
	}
}

func TestEmptyDirAndEmptyPassphrase(t *testing.T) {
	dir := t.TempDir()
	if _, err := New(dir).Unlock([]byte(pass)); !errors.Is(err, ErrNoKeys) {
		t.Fatalf("empty dir: %v", err)
	}
	if _, err := New(dir).Unlock(nil); err == nil {
		t.Fatal("empty passphrase accepted")
	}
}

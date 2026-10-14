// SPDX-License-Identifier: AGPL-3.0-or-later

package executordb

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
)

func hostPub(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func pin(host string, k ssh.PublicKey) HostKey {
	return HostKey{HostID: host, PublicKey: k.Marshal(), User: "nebula", CredentialRef: "default",
		Source: SourceProbe, PinnedBy: "admin:uid1000"}
}

func TestPinHostKeyDurableAndUnique(t *testing.T) {
	dir := privateDir(t)
	db := openAtT(t, dir, t0)
	ka, kb := hostPub(t), hostPub(t)
	got, err := db.PinHostKey(pin("dockerflux", ka))
	if err != nil {
		t.Fatal(err)
	}
	if got.Fingerprint != ssh.FingerprintSHA256(ka) || !got.PinnedAt.Equal(t0) {
		t.Fatalf("pin %+v", got)
	}
	if _, err := db.PinHostKey(pin("dockerflux", kb)); !errors.Is(err, ErrHostPinned) {
		t.Fatalf("second pin for a host: %v", err)
	}
	// The same key for another host (a cloned VM) is refused.
	if _, err := db.PinHostKey(pin("strompi", ka)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("shared key: %v", err)
	}
	if _, err := db.PinHostKey(pin("strompi", kb)); err != nil {
		t.Fatal(err)
	}
	db.Close()

	db = openT(t, dir)
	list, err := db.ListHostKeys()
	if err != nil || len(list) != 2 || list[0].HostID != "dockerflux" || list[1].Fingerprint != ssh.FingerprintSHA256(kb) {
		t.Fatalf("list %+v %v", list, err)
	}
	k, ok, err := db.HostKey("dockerflux")
	if err != nil || !ok || k.User != "nebula" || k.CredentialRef != "default" || k.Blocked != nil {
		t.Fatalf("host key %+v %v %v", k, ok, err)
	}
	if _, ok, _ := db.HostKey("nope"); ok {
		t.Fatal("unknown host found")
	}
}

func TestBlockHostKeepsFirstMismatchUntilUnpin(t *testing.T) {
	db := openAtT(t, privateDir(t), t0)
	ka := hostPub(t)
	if _, err := db.PinHostKey(pin("dockerflux", ka)); err != nil {
		t.Fatal(err)
	}
	set, err := db.BlockHost("dockerflux", "SHA256:first", "192.168.0.10:22")
	if err != nil || !set {
		t.Fatalf("block: %v %v", set, err)
	}
	if set, _ := db.BlockHost("dockerflux", "SHA256:second", "10.8.0.5:22"); set {
		t.Fatal("second block overwrote the first")
	}
	k, _, _ := db.HostKey("dockerflux")
	if k.Blocked == nil || k.Blocked.Fingerprint != "SHA256:first" || k.Blocked.Endpoint != "192.168.0.10:22" {
		t.Fatalf("block %+v", k.Blocked)
	}
	if set, _ := db.BlockHost("unknown", "x", "y"); set {
		t.Fatal("blocked a host without pin")
	}
	if _, removed, err := db.UnpinHostKey("dockerflux", ssh.FingerprintSHA256(hostPub(t))); removed || !errors.Is(err, ErrInvalid) {
		t.Fatalf("unpin with a stale fingerprint: %v %v", removed, err)
	}
	old, removed, err := db.UnpinHostKey("dockerflux", ssh.FingerprintSHA256(ka))
	if err != nil || !removed || old.Fingerprint != ssh.FingerprintSHA256(ka) || old.Blocked == nil {
		t.Fatalf("unpin %+v %v %v", old, removed, err)
	}
	if _, removed, _ := db.UnpinHostKey("dockerflux", ssh.FingerprintSHA256(ka)); removed {
		t.Fatal("second unpin reported success")
	}
	k2, err := db.PinHostKey(pin("dockerflux", ka))
	if err != nil || k2.Blocked != nil {
		t.Fatalf("re-pin: %+v %v", k2, err)
	}
}

func TestPinHostKeyValidation(t *testing.T) {
	db := openT(t, privateDir(t))
	weak, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	weakPub, _ := ssh.NewPublicKey(&weak.PublicKey)
	for name, mut := range map[string]func(*HostKey){
		"bad host":   func(k *HostKey) { k.HostID = "Docker Flux" },
		"no key":     func(k *HostKey) { k.PublicKey = nil },
		"garbage":    func(k *HostKey) { k.PublicKey = []byte{0, 0, 0, 1, 'x'} },
		"trailing":   func(k *HostKey) { k.PublicKey = append(k.PublicKey, 0) },
		"weak rsa":   func(k *HostKey) { k.PublicKey = weakPub.Marshal() },
		"bad user":   func(k *HostKey) { k.User = "root;id" },
		"no user":    func(k *HostKey) { k.User = "" },
		"bad ref":    func(k *HostKey) { k.CredentialRef = "../etc" },
		"bad source": func(k *HostKey) { k.Source = "server" },
		"no actor":   func(k *HostKey) { k.PinnedBy = "" },
	} {
		k := pin("dockerflux", hostPub(t))
		mut(&k)
		if _, err := db.PinHostKey(k); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: want ErrInvalid, got %v", name, err)
		}
	}
}

// With a pinned key, the criticality record follows the pin.
func TestCriticalityBindsToPinnedKey(t *testing.T) {
	db := openT(t, privateDir(t))
	ka := hostPub(t)
	fp := ssh.FingerprintSHA256(ka)
	if _, err := db.PinHostKey(pin("dockerflux", ka)); err != nil {
		t.Fatal(err)
	}
	got, err := db.SetHostCriticality("dockerflux", "", canonical.RiskCritical, "admin")
	if err != nil || got != fp {
		t.Fatalf("empty fingerprint: %q %v", got, err)
	}
	if _, err := db.SetHostCriticality("dockerflux", ssh.FingerprintSHA256(hostPub(t)), canonical.RiskLow, "admin"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("other fingerprint accepted: %v", err)
	}
	if got, err := db.SetHostCriticality("dockerflux", fp, canonical.RiskLow, "admin"); err != nil || got != fp {
		t.Fatalf("pinned fingerprint: %q %v", got, err)
	}
}

func TestRepinHostKeyOnlyForTheApprovedBlock(t *testing.T) {
	db := openAtT(t, privateDir(t), t0)
	oldKey, newKey, other := hostPub(t), hostPub(t), hostPub(t)
	oldFP, newFP := ssh.FingerprintSHA256(oldKey), ssh.FingerprintSHA256(newKey)
	if _, err := db.PinHostKey(pin("dockerflux", oldKey)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.SetHostCriticality("dockerflux", "", canonical.RiskCritical, "admin"); err != nil {
		t.Fatal(err)
	}
	// Not blocked: nothing to re-pin.
	if _, err := db.RepinHostKey("dockerflux", oldFP, t0, newKey.Marshal(), "web:axel"); !errors.Is(err, ErrRepinStale) {
		t.Fatalf("unblocked host: %v", err)
	}
	if _, err := db.BlockHost("dockerflux", newFP, "192.168.0.10:22"); err != nil {
		t.Fatal(err)
	}
	k, _, _ := db.HostKey("dockerflux")
	at := k.Blocked.At
	for name, tc := range map[string]struct {
		old string
		at  int64
		key ssh.PublicKey
	}{
		"other presented key": {oldFP, at.Unix(), other},
		"other block event":   {oldFP, at.Unix() + 1, newKey},
		"stale pin":           {newFP, at.Unix(), newKey},
	} {
		if _, err := db.RepinHostKey("dockerflux", tc.old, time.Unix(tc.at, 0), tc.key.Marshal(), "web:axel"); !errors.Is(err, ErrRepinStale) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	got, err := db.RepinHostKey("dockerflux", oldFP, at, newKey.Marshal(), "web:axel")
	if err != nil || got.Fingerprint != newFP || got.Blocked != nil || got.PinnedBy != "web:axel" {
		t.Fatalf("repin %+v %v", got, err)
	}
	k, _, _ = db.HostKey("dockerflux")
	if k.Fingerprint != newFP || k.Blocked != nil || k.User != "nebula" || k.CredentialRef != "default" {
		t.Fatalf("stored %+v", k)
	}
	// The criticality moved with the key: still exactly CRITICAL.
	if c, exact, err := db.HostCriticality("dockerflux", newFP); err != nil || !exact || c != canonical.RiskCritical {
		t.Fatalf("criticality %v %v %v", c, exact, err)
	}
	// Done once: the same approval cannot be applied again.
	if _, err := db.RepinHostKey("dockerflux", oldFP, at, newKey.Marshal(), "web:axel"); !errors.Is(err, ErrRepinStale) {
		t.Fatalf("second repin: %v", err)
	}
}

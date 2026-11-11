// SPDX-License-Identifier: AGPL-3.0-or-later

package executordb

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const testGroup = "nos-managed"

// testSetupKey is a setup key in the form NetBird issues (spec 09).
func testSetupKey(t *testing.T) string {
	t.Helper()
	b := rand32(t)
	h := strings.ToUpper(hex.EncodeToString(b[:16]))
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

// sealTestKey encrypts key the way package vault does (AES-GCM, nonce ||
// ciphertext) with a throw-away key, so the store sees a realistic
// ciphertext and never the key itself.
func sealTestKey(t *testing.T, id, key string) VaultSecret {
	t.Helper()
	dek := rand32(t)
	block, err := aes.NewCipher(dek[:])
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	wrapped := make([]byte, 72)
	if _, err := rand.Read(wrapped); err != nil {
		t.Fatal(err)
	}
	return VaultSecret{
		ID:         id,
		Version:    1,
		WrappedDEK: wrapped,
		Sealed:     gcm.Seal(nonce, nonce, []byte(key), []byte(id)),
		UpdatedBy:  "executor",
	}
}

// fixedSetupKeySecret is a stand-in vault secret for the offer's setup
// key, for tests that only drive the state machine.
func fixedSetupKeySecret(id [32]byte) VaultSecret {
	return VaultSecret{
		ID:         SetupKeyVaultRef(id),
		Version:    1,
		WrappedDEK: bytes.Repeat([]byte{0x5a}, 72),
		Sealed:     bytes.Repeat([]byte{0xa5}, 64),
		UpdatedBy:  "executor",
	}
}

// netbirdOffer is a NetBird offer with its test setup key and script.
type netbirdOffer struct {
	NewOffer
	key    string
	line   string // the script line that carries the key
	script [32]byte
	secret VaultSecret
}

func newNetBirdOffer(t *testing.T, db *DB) netbirdOffer {
	t.Helper()
	n := netbirdOffer{NewOffer: mustCreateOffer(t, db, true), key: testSetupKey(t)}
	n.line = "NB_SETUP_KEY='" + n.key + "'"
	n.script = sha256.Sum256([]byte("#!/bin/sh\n" + n.line + "\n"))
	n.secret = sealTestKey(t, SetupKeyVaultRef(n.IDHash), n.key)
	return n
}

// openNetBird drives a new NetBird offer through pending and created into
// open.
func openNetBird(t *testing.T, db *DB) netbirdOffer {
	t.Helper()
	n := newNetBirdOffer(t, db)
	if _, err := db.MarkSetupKeyPending(n.IDHash, testGroup); err != nil {
		t.Fatalf("pending: %v", err)
	}
	if err := db.OpenNetBirdOffer(n.IDHash, "key"+offerLogID(n.IDHash), n.secret, n.script); err != nil {
		t.Fatalf("open: %v", err)
	}
	return n
}

func pendingNetBird(t *testing.T, db *DB) netbirdOffer {
	t.Helper()
	n := newNetBirdOffer(t, db)
	if _, err := db.MarkSetupKeyPending(n.IDHash, testGroup); err != nil {
		t.Fatalf("pending: %v", err)
	}
	return n
}

func TestSetupKeyMigrationShippedInOrder(t *testing.T) {
	ms := mustMigrations(t)
	idx := -1
	for i, m := range ms {
		if m.name == "0026_enroll_offer_netbird.sql" {
			idx = i
		}
	}
	if idx < 1 || ms[idx].version != 26 || ms[idx-1].version != 25 {
		t.Fatalf("NetBird offer migration not shipped as 0026 after 0025 (index %d)", idx)
	}
}

func TestSetupKeyNamesDeriveFromOfferIDHash(t *testing.T) {
	var id [32]byte
	for i := range id {
		id[i] = byte(i + 0xa0)
	}
	if got := SetupKeyName(id); got != "nos-offer-a0a1a2a3" {
		t.Fatalf("key name %q", got)
	}
	if got := SetupKeyVaultRef(id); got != "netbird-setup-key-a0a1a2a3a4a5a6a7a8a9aaabacadaeaf" || len(got) > 64 {
		t.Fatalf("vault ref %q", got)
	}
}

func TestNewNetBirdOfferHasNoSetupKeyRecord(t *testing.T) {
	db, _ := offerDB(t)
	n := newNetBirdOffer(t, db)
	r := mustOffer(t, db, n.IDHash).SetupKey
	if r.Status != SetupKeyNone || r.Name != "" || r.KeyID != "" || r.VaultRef != "" || r.Open() {
		t.Fatalf("fresh record %+v", r)
	}
}

func TestSetupKeyPendingPersistsReconcileRecord(t *testing.T) {
	db, clk := offerDB(t)
	n := newNetBirdOffer(t, db)
	clk.Add(2 * time.Minute)
	now := clk.Now()
	r, err := db.MarkSetupKeyPending(n.IDHash, testGroup)
	if err != nil {
		t.Fatal(err)
	}
	stored := mustOffer(t, db, n.IDHash)
	if stored.State != OfferAwaitingApproval {
		t.Fatalf("state %s", stored.State)
	}
	for _, got := range []SetupKeyRecord{r, stored.SetupKey} {
		if got.Status != SetupKeyPending || got.Name != SetupKeyName(n.IDHash) || got.Group != testGroup ||
			got.KeyID != "" || got.VaultRef != "" || got.Verified || got.NameMismatch || !got.Open() {
			t.Fatalf("pending record %+v", got)
		}
		if !got.WindowStart.Equal(now.Add(-NetBirdKeyClockSkew)) ||
			!got.WindowEnd.Equal(now.Add(NetBirdCreateTimeout+NetBirdKeyClockSkew)) {
			t.Fatalf("window %v .. %v", got.WindowStart, got.WindowEnd)
		}
		if !got.Deadline().Equal(got.WindowEnd.Add(NetBirdSetupKeyMaxLifetime)) {
			t.Fatalf("deadline %v", got.Deadline())
		}
	}
	// A record that is already pending is never moved again, so create is
	// never called twice for it.
	if _, err := db.MarkSetupKeyPending(n.IDHash, testGroup); !errors.Is(err, ErrSetupKeyState) {
		t.Fatalf("second pending: %v, want ErrSetupKeyState", err)
	}
	if got := mustOffer(t, db, n.IDHash).SetupKey; got != stored.SetupKey {
		t.Fatalf("refused pending changed the record: %+v", got)
	}
}

func TestSetupKeyPendingRefused(t *testing.T) {
	db, clk := offerDB(t)
	plain := offerIn(t, db, OfferOpen)
	if _, err := db.MarkSetupKeyPending(plain.IDHash, testGroup); !errors.Is(err, ErrOfferState) {
		t.Fatalf("plain offer: %v, want ErrOfferState", err)
	}
	revoked := newNetBirdOffer(t, db)
	if err := db.EndOffer(revoked.IDHash, OfferAwaitingApproval, OfferRevoked); err != nil {
		t.Fatal(err)
	}
	if _, err := db.MarkSetupKeyPending(revoked.IDHash, testGroup); !errors.Is(err, ErrOfferState) {
		t.Fatalf("revoked offer: %v, want ErrOfferState", err)
	}
	if _, err := db.MarkSetupKeyPending(rand32(t), testGroup); !errors.Is(err, ErrOfferNotFound) {
		t.Fatalf("unknown offer: %v, want ErrOfferNotFound", err)
	}
	n := newNetBirdOffer(t, db)
	for _, g := range []string{"", strings.Repeat("g", maxSetupKeyGroupLen+1), "bad\ngroup", "\xff"} {
		if _, err := db.MarkSetupKeyPending(n.IDHash, g); !errors.Is(err, ErrInvalid) {
			t.Fatalf("group %q: %v, want ErrInvalid", g, err)
		}
	}
	// Expired but not yet swept: still awaiting_approval, but no key.
	clk.Add(OfferLifetime)
	if _, err := db.MarkSetupKeyPending(n.IDHash, testGroup); !errors.Is(err, ErrOfferExpired) {
		t.Fatalf("expired offer: %v, want ErrOfferExpired", err)
	}
	for _, id := range [][32]byte{plain.IDHash, revoked.IDHash, n.IDHash} {
		if r := mustOffer(t, db, id).SetupKey; r.Status != SetupKeyNone {
			t.Fatalf("refused pending left record %+v", r)
		}
	}
}

func TestOpenNetBirdOfferCreatesRecord(t *testing.T) {
	db, _ := offerDB(t)
	n := pendingNetBird(t, db)
	before := mustOffer(t, db, n.IDHash).SetupKey
	if err := db.OpenNetBirdOffer(n.IDHash, "abc123", n.secret, n.script); err != nil {
		t.Fatal(err)
	}
	o := mustOffer(t, db, n.IDHash)
	if o.State != OfferOpen || !bytes.Equal(o.ScriptSHA256, n.script[:]) {
		t.Fatalf("offer %s script %x", o.State, o.ScriptSHA256)
	}
	r := o.SetupKey
	if r.Status != SetupKeyCreated || r.KeyID != "abc123" || r.VaultRef != SetupKeyVaultRef(n.IDHash) || !r.Verified ||
		r.Name != before.Name || r.Group != before.Group || !r.WindowStart.Equal(before.WindowStart) ||
		!r.WindowEnd.Equal(before.WindowEnd) {
		t.Fatalf("created record %+v", r)
	}
	s, err := db.GetSecret(r.VaultRef)
	if err != nil || !bytes.Equal(s.Sealed, n.secret.Sealed) {
		t.Fatalf("vault secret: %v", err)
	}
	// pending -> created happens once.
	if err := db.OpenNetBirdOffer(n.IDHash, "abc123", n.secret, n.script); !errors.Is(err, ErrOfferState) {
		t.Fatalf("second open: %v, want ErrOfferState", err)
	}
}

func TestOpenNetBirdOfferRefused(t *testing.T) {
	db, clk := offerDB(t)
	// No pending record: no key may exist, nothing is stored.
	none := newNetBirdOffer(t, db)
	if err := db.OpenNetBirdOffer(none.IDHash, "abc", none.secret, none.script); !errors.Is(err, ErrSetupKeyState) {
		t.Fatalf("open without pending: %v, want ErrSetupKeyState", err)
	}
	n := pendingNetBird(t, db)
	for _, tc := range []struct {
		name   string
		keyID  string
		secret func(VaultSecret) VaultSecret
		script [32]byte
	}{
		{"empty key ID", "", nil, n.script},
		{"long key ID", strings.Repeat("a", NetBirdKeyIDMaxLen+1), nil, n.script},
		{"uppercase key ID", "ABC", nil, n.script},
		{"key ID with slash", "a/b", nil, n.script},
		{"key ID with NUL", "a\x00b", nil, n.script},
		{"zero script hash", "abc", nil, [32]byte{}},
		{"foreign vault ID", "abc", func(s VaultSecret) VaultSecret { s.ID = "pve-token-1"; return s }, n.script},
		{"vault version 2", "abc", func(s VaultSecret) VaultSecret { s.Version = 2; return s }, n.script},
	} {
		s := n.secret
		if tc.secret != nil {
			s = tc.secret(s)
		}
		if err := db.OpenNetBirdOffer(n.IDHash, tc.keyID, s, tc.script); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%s: %v, want ErrInvalid", tc.name, err)
		}
	}
	// Expired before the create answer arrived: nothing stored, record
	// stays pending for the caller's failure path.
	clk.Add(OfferLifetime)
	if err := db.OpenNetBirdOffer(n.IDHash, "abc", n.secret, n.script); !errors.Is(err, ErrOfferExpired) {
		t.Fatalf("expired: %v, want ErrOfferExpired", err)
	}
	for _, x := range []netbirdOffer{none, n} {
		o := mustOffer(t, db, x.IDHash)
		if o.State != OfferAwaitingApproval || o.SetupKey.KeyID != "" || o.SetupKey.VaultRef != "" {
			t.Fatalf("refused open changed the offer: %s %+v", o.State, o.SetupKey)
		}
		if _, err := db.GetSecret(SetupKeyVaultRef(x.IDHash)); !errors.Is(err, ErrNoSecret) {
			t.Fatalf("refused open stored the secret: %v", err)
		}
	}
}

// TestOpenNetBirdOfferAfterRevokeKeepsPending: the create call raced a
// revoke. The compare-and-set fails, no secret is stored and the record
// stays pending until the caller stores the key ID.
func TestOpenNetBirdOfferAfterRevokeKeepsPending(t *testing.T) {
	db, _ := offerDB(t)
	n := pendingNetBird(t, db)
	if err := db.EndOffer(n.IDHash, OfferAwaitingApproval, OfferRevoked); err != nil {
		t.Fatal(err)
	}
	if err := db.OpenNetBirdOffer(n.IDHash, "abc", n.secret, n.script); !errors.Is(err, ErrOfferState) {
		t.Fatalf("open after revoke: %v, want ErrOfferState", err)
	}
	if _, err := db.GetSecret(SetupKeyVaultRef(n.IDHash)); !errors.Is(err, ErrNoSecret) {
		t.Fatalf("secret stored for a revoked offer: %v", err)
	}
	if r := mustOffer(t, db, n.IDHash).SetupKey; r.Status != SetupKeyPending || !r.Open() {
		t.Fatalf("record %+v", r)
	}
}

// TestPendingSetupKeySurvivesRevokeExpiryAndRestart: revoke and the expiry
// sweep end the offer but leave the pending record open, and both survive
// a restart and are listed for the reconcile.
func TestPendingSetupKeySurvivesRevokeExpiryAndRestart(t *testing.T) {
	dir := privateDir(t)
	clk := &offerClock{t: t0}
	db := openOfferDB(t, dir, clk)
	revoked := pendingNetBird(t, db)
	if err := db.EndOffer(revoked.IDHash, OfferAwaitingApproval, OfferRevoked); err != nil {
		t.Fatal(err)
	}
	expired := pendingNetBird(t, db)
	failed := pendingNetBird(t, db)
	if err := db.EndOffer(failed.IDHash, OfferAwaitingApproval, OfferFailed); err != nil {
		t.Fatal(err)
	}
	live := pendingNetBird(t, db) // crash while the create call runs
	clk.Add(OfferLifetime - time.Second)
	live2 := pendingNetBird(t, db)
	clk.Add(time.Second)
	swept, err := db.ExpireOffers()
	if err != nil {
		t.Fatal(err)
	}
	if len(swept) != 2 { // expired and live; live2 is younger
		t.Fatalf("swept %d offers", len(swept))
	}
	want := map[[32]byte]OfferState{
		revoked.IDHash: OfferRevoked, expired.IDHash: OfferExpired, failed.IDHash: OfferFailed,
		live.IDHash: OfferExpired, live2.IDHash: OfferAwaitingApproval,
	}
	before := map[[32]byte]SetupKeyRecord{}
	for id, st := range want {
		o := mustOffer(t, db, id)
		if o.State != st || o.SetupKey.Status != SetupKeyPending || !o.SetupKey.Open() ||
			o.SetupKey.Name != SetupKeyName(id) {
			t.Fatalf("offer %x: %s %+v", id[:4], o.State, o.SetupKey)
		}
		before[id] = o.SetupKey
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	db2 := openOfferDB(t, dir, clk)
	recs, err := db2.OpenSetupKeyRecords()
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != len(want) {
		t.Fatalf("%d open records after restart, want %d", len(recs), len(want))
	}
	for _, o := range recs {
		if o.State != want[o.IDHash] || o.SetupKey != before[o.IDHash] {
			t.Fatalf("after restart %x: %s %+v", o.IDHash[:4], o.State, o.SetupKey)
		}
	}
	// After a restart no second key is created for a pending record.
	if _, err := db2.MarkSetupKeyPending(live2.IDHash, testGroup); !errors.Is(err, ErrSetupKeyState) {
		t.Fatalf("pending again after restart: %v, want ErrSetupKeyState", err)
	}
	// Ending the still-live one keeps its record too.
	if err := db2.EndOffer(live2.IDHash, OfferAwaitingApproval, OfferFailed); err != nil {
		t.Fatal(err)
	}
	if r := mustOffer(t, db2, live2.IDHash).SetupKey; r != before[live2.IDHash] {
		t.Fatalf("fail dropped the pending record: %+v", r)
	}
}

// keyOnDisk returns the database files that contain any of needles.
func keyOnDisk(t *testing.T, dir string, needles ...[]byte) []string {
	t.Helper()
	var in []string
	for _, name := range []string{FileName, FileName + "-wal", FileName + "-journal"} {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		for _, n := range needles {
			if bytes.Contains(b, n) {
				in = append(in, name)
				break
			}
		}
	}
	return in
}

// TestFinalStateWipesSetupKeySecret checks every way into a final state:
// the vault secret and the reference are gone in the same write, the key
// ID stays for the revoke. The test scans the database file, WAL and
// journal: the setup key and the script line that carries it are never
// there, and the sealed secret is gone once the final state is written.
func TestFinalStateWipesSetupKeySecret(t *testing.T) {
	for _, tc := range []struct {
		name string
		prep func(*DB, [32]byte) error
		end  func(*DB, *offerClock, [32]byte) error
		want OfferState
	}{
		{"revoke", nil, func(db *DB, _ *offerClock, id [32]byte) error {
			return db.EndOffer(id, OfferOpen, OfferRevoked)
		}, OfferRevoked},
		{"fail after download", func(db *DB, id [32]byte) error {
			return db.ClaimOfferDownload(id, "192.0.2.10", "127.0.0.1")
		}, func(db *DB, _ *offerClock, id [32]byte) error {
			return db.EndOffer(id, OfferDownloaded, OfferFailed)
		}, OfferFailed},
		{"enrol", proposeOffer, func(db *DB, _ *offerClock, id [32]byte) error {
			return db.CompleteOffer(id)
		}, OfferEnrolled},
		{"expiry sweep after download", func(db *DB, id [32]byte) error {
			return db.ClaimOfferDownload(id, "192.0.2.10", "127.0.0.1")
		}, func(db *DB, clk *offerClock, _ [32]byte) error {
			clk.Add(OfferLifetime)
			_, err := db.ExpireOffers()
			return err
		}, OfferExpired},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := privateDir(t)
			clk := &offerClock{t: t0}
			db := openOfferDB(t, dir, clk)
			n := openNetBird(t, db)
			if tc.prep != nil {
				if err := tc.prep(db, n.IDHash); err != nil {
					t.Fatal(err)
				}
			}
			clk.Add(time.Minute)
			other := openNetBird(t, db) // a live neighbour on the same pages
			clk.Add(-time.Minute)
			if in := keyOnDisk(t, dir, n.secret.Sealed); len(in) == 0 {
				t.Fatal("live sealed secret not found on disk: the scan proves nothing")
			}
			if err := tc.end(db, clk, n.IDHash); err != nil {
				t.Fatal(err)
			}
			o := mustOffer(t, db, n.IDHash)
			if o.State != tc.want || o.SetupKey.VaultRef != "" || o.SetupKey.KeyID != "key"+offerLogID(n.IDHash) ||
				o.SetupKey.Status != SetupKeyCreated || !o.SetupKey.Open() {
				t.Fatalf("final offer %s %+v", o.State, o.SetupKey)
			}
			if _, err := db.GetSecret(SetupKeyVaultRef(n.IDHash)); !errors.Is(err, ErrNoSecret) {
				t.Fatalf("setup-key secret survived the final state: %v", err)
			}
			check := func(when string) {
				t.Helper()
				if in := keyOnDisk(t, dir, n.secret.Sealed); len(in) != 0 {
					t.Fatalf("%s: wiped sealed secret still in %v", when, in)
				}
				for _, x := range []netbirdOffer{n, other} {
					if in := keyOnDisk(t, dir, []byte(x.key), []byte(x.line)); len(in) != 0 {
						t.Fatalf("%s: setup key or script line in %v", when, in)
					}
				}
			}
			check("open database")
			if tc.name != "expiry sweep after download" {
				if _, err := db.GetSecret(SetupKeyVaultRef(other.IDHash)); err != nil {
					t.Fatalf("live neighbour lost its secret: %v", err)
				}
				if in := keyOnDisk(t, dir, other.secret.Sealed); len(in) == 0 {
					t.Fatal("live neighbour's sealed secret missing on disk")
				}
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			check("after close")
		})
	}
}

// TestSetupKeyIDWipedOnlyAfterRevokeOrExpiry: the key ID stays until a
// revoke succeeded or the key's latest possible expiry has passed.
func TestSetupKeyIDWipedOnlyAfterRevokeOrExpiry(t *testing.T) {
	db, clk := offerDB(t)
	n := openNetBird(t, db)
	keyID := "key" + offerLogID(n.IDHash)
	// Not before the offer is final.
	if err := db.SetupKeyRevoked(n.IDHash, keyID); !errors.Is(err, ErrSetupKeyState) {
		t.Fatalf("revoke of a live offer's key: %v, want ErrSetupKeyState", err)
	}
	if err := db.EndOffer(n.IDHash, OfferOpen, OfferRevoked); err != nil {
		t.Fatal(err)
	}
	if err := db.SetupKeyRevoked(n.IDHash, "otherkey"); !errors.Is(err, ErrSetupKeyState) {
		t.Fatalf("revoke with another key ID: %v, want ErrSetupKeyState", err)
	}
	r := mustOffer(t, db, n.IDHash).SetupKey
	clk.Add(r.Deadline().Sub(clk.Now()) - time.Second)
	if err := db.CloseExpiredSetupKey(n.IDHash); !errors.Is(err, ErrSetupKeyLive) {
		t.Fatalf("close before the key's expiry: %v, want ErrSetupKeyLive", err)
	}
	if got := mustOffer(t, db, n.IDHash).SetupKey; got.KeyID != keyID || !got.Open() {
		t.Fatalf("refused calls wiped the key ID: %+v", got)
	}
	if err := db.SetupKeyRevoked(n.IDHash, keyID); err != nil {
		t.Fatal(err)
	}
	got := mustOffer(t, db, n.IDHash).SetupKey
	if got.KeyID != "" || got.Open() || got.Close != SetupKeyClosedRevoked || !got.ClosedAt.Equal(clk.Now()) ||
		got.Status != SetupKeyCreated || got.Name != r.Name {
		t.Fatalf("revoked record %+v", got)
	}
	if err := db.SetupKeyRevoked(n.IDHash, keyID); !errors.Is(err, ErrSetupKeyState) {
		t.Fatalf("second revoke: %v, want ErrSetupKeyState", err)
	}
	if err := db.CloseExpiredSetupKey(n.IDHash); !errors.Is(err, ErrSetupKeyState) {
		t.Fatalf("expiry close after revoke: %v, want ErrSetupKeyState", err)
	}

	// Expiry without a successful revoke: created and pending records.
	for _, mk := range []func() [32]byte{
		func() [32]byte {
			x := openNetBird(t, db)
			if err := db.EndOffer(x.IDHash, OfferOpen, OfferExpired); err != nil {
				t.Fatal(err)
			}
			return x.IDHash
		},
		func() [32]byte {
			x := pendingNetBird(t, db)
			if err := db.EndOffer(x.IDHash, OfferAwaitingApproval, OfferRevoked); err != nil {
				t.Fatal(err)
			}
			return x.IDHash
		},
	} {
		id := mk()
		r := mustOffer(t, db, id).SetupKey
		clk.Add(r.Deadline().Sub(clk.Now()) - time.Second)
		if err := db.CloseExpiredSetupKey(id); !errors.Is(err, ErrSetupKeyLive) {
			t.Fatalf("early close: %v, want ErrSetupKeyLive", err)
		}
		clk.Add(time.Second)
		if err := db.CloseExpiredSetupKey(id); err != nil {
			t.Fatal(err)
		}
		got := mustOffer(t, db, id).SetupKey
		if got.KeyID != "" || got.Open() || got.Close != SetupKeyClosedExpiredUnrevoked || got.Status != r.Status {
			t.Fatalf("expired record %+v", got)
		}
	}
	// A plain offer has no record to close.
	plain := offerIn(t, db, OfferRevoked)
	if err := db.CloseExpiredSetupKey(plain.IDHash); !errors.Is(err, ErrSetupKeyState) {
		t.Fatalf("plain offer: %v, want ErrSetupKeyState", err)
	}
	if err := db.SetupKeyRevoked(rand32(t), "abc"); !errors.Is(err, ErrOfferNotFound) {
		t.Fatalf("unknown offer: %v, want ErrOfferNotFound", err)
	}
}

// TestSetupKeyRevokeRetriesSurviveRestart: failed revokes are counted with
// the ADR backoff (1 minute, then 5 minutes) and resume after a restart.
func TestSetupKeyRevokeRetriesSurviveRestart(t *testing.T) {
	dir := privateDir(t)
	clk := &offerClock{t: t0}
	db := openOfferDB(t, dir, clk)
	n := openNetBird(t, db)
	if _, err := db.RecordSetupKeyRevokeFailure(n.IDHash); !errors.Is(err, ErrSetupKeyState) {
		t.Fatalf("revoke failure on a live offer: %v, want ErrSetupKeyState", err)
	}
	if err := db.EndOffer(n.IDHash, OfferOpen, OfferRevoked); err != nil {
		t.Fatal(err)
	}
	next, err := db.RecordSetupKeyRevokeFailure(n.IDHash)
	if err != nil || !next.Equal(clk.Now().Add(SetupKeyRevokeFirstRetry)) {
		t.Fatalf("first failure: next %v, %v", next, err)
	}
	next, err = db.RecordSetupKeyRevokeFailure(n.IDHash)
	if err != nil || !next.Equal(clk.Now().Add(SetupKeyRevokeRetryInterval)) {
		t.Fatalf("second failure: next %v, %v", next, err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db2 := openOfferDB(t, dir, clk)
	recs, err := db2.OpenSetupKeyRecords()
	if err != nil || len(recs) != 1 {
		t.Fatalf("records after restart: %d, %v", len(recs), err)
	}
	r := recs[0].SetupKey
	if r.KeyID != "key"+offerLogID(n.IDHash) || r.RevokeFailures != 2 || !r.NextRetryAt.Equal(next) {
		t.Fatalf("retry record after restart %+v", r)
	}
	if err := db2.SetupKeyRevoked(n.IDHash, r.KeyID); err != nil {
		t.Fatal(err)
	}
	if recs, err := db2.OpenSetupKeyRecords(); err != nil || len(recs) != 0 {
		t.Fatalf("records after revoke: %d, %v", len(recs), err)
	}
	if _, err := db2.RecordSetupKeyRevokeFailure(n.IDHash); !errors.Is(err, ErrSetupKeyState) {
		t.Fatalf("revoke failure on a closed record: %v, want ErrSetupKeyState", err)
	}
}

// TestFailSetupKeyCreate covers the write that precedes every revoke after
// a create answer that cannot be used.
func TestFailSetupKeyCreate(t *testing.T) {
	db, _ := offerDB(t)

	t.Run("invalid key ID keeps pending", func(t *testing.T) {
		n := pendingNetBird(t, db)
		if err := db.FailSetupKeyCreate(n.IDHash, "", false, true); err != nil {
			t.Fatal(err)
		}
		o := mustOffer(t, db, n.IDHash)
		if o.State != OfferFailed || o.Salt != nil || o.SetupKey.Status != SetupKeyPending ||
			!o.SetupKey.NameMismatch || !o.SetupKey.Open() || o.SetupKey.Name != SetupKeyName(n.IDHash) {
			t.Fatalf("offer %s %+v", o.State, o.SetupKey)
		}
	})
	t.Run("unverified key ID", func(t *testing.T) {
		n := pendingNetBird(t, db)
		if err := db.FailSetupKeyCreate(n.IDHash, "abc", false, false); err != nil {
			t.Fatal(err)
		}
		o := mustOffer(t, db, n.IDHash)
		if o.State != OfferFailed || o.SetupKey.Status != SetupKeyCreated || o.SetupKey.KeyID != "abc" ||
			o.SetupKey.Verified || o.SetupKey.VaultRef != "" || !o.SetupKey.Open() {
			t.Fatalf("offer %s %+v", o.State, o.SetupKey)
		}
		// Never revoked or closed on the unverified ID alone.
		if err := db.SetupKeyRevoked(n.IDHash, "abc"); !errors.Is(err, ErrSetupKeyState) {
			t.Fatalf("revoke unverified: %v, want ErrSetupKeyState", err)
		}
		// A get by ID or the reconcile confirms it; then it can be revoked.
		if err := db.ReconcileSetupKey(n.IDHash, "abc"); err != nil {
			t.Fatal(err)
		}
		if err := db.SetupKeyRevoked(n.IDHash, "abc"); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("offer already final", func(t *testing.T) {
		n := pendingNetBird(t, db)
		if err := db.EndOffer(n.IDHash, OfferAwaitingApproval, OfferRevoked); err != nil {
			t.Fatal(err)
		}
		if err := db.FailSetupKeyCreate(n.IDHash, "abc2", true, false); err != nil {
			t.Fatal(err)
		}
		o := mustOffer(t, db, n.IDHash)
		if o.State != OfferRevoked || o.SetupKey.Status != SetupKeyCreated || o.SetupKey.KeyID != "abc2" ||
			!o.SetupKey.Verified || !o.SetupKey.Open() {
			t.Fatalf("offer %s %+v", o.State, o.SetupKey)
		}
		if err := db.SetupKeyRevoked(n.IDHash, "abc2"); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("refused", func(t *testing.T) {
		none := newNetBirdOffer(t, db)
		if err := db.FailSetupKeyCreate(none.IDHash, "abc", true, false); !errors.Is(err, ErrSetupKeyState) {
			t.Fatalf("no pending record: %v, want ErrSetupKeyState", err)
		}
		opened := openNetBird(t, db)
		if err := db.FailSetupKeyCreate(opened.IDHash, "abc", true, false); !errors.Is(err, ErrSetupKeyState) {
			t.Fatalf("created record: %v, want ErrSetupKeyState", err)
		}
		n := pendingNetBird(t, db)
		if err := db.FailSetupKeyCreate(n.IDHash, "A/B", true, false); !errors.Is(err, ErrInvalid) {
			t.Fatalf("bad key ID: %v, want ErrInvalid", err)
		}
		if err := db.FailSetupKeyCreate(n.IDHash, "", true, false); !errors.Is(err, ErrInvalid) {
			t.Fatalf("verified without key ID: %v, want ErrInvalid", err)
		}
		if err := db.FailSetupKeyCreate(rand32(t), "abc", true, false); !errors.Is(err, ErrOfferNotFound) {
			t.Fatalf("unknown offer: %v, want ErrOfferNotFound", err)
		}
		for _, x := range []netbirdOffer{none, n} {
			if o := mustOffer(t, db, x.IDHash); o.State != OfferAwaitingApproval {
				t.Fatalf("refused fail changed the offer to %s", o.State)
			}
		}
		if o := mustOffer(t, db, opened.IDHash); o.State != OfferOpen || o.SetupKey.VaultRef == "" {
			t.Fatalf("refused fail changed the opened offer: %s %+v", o.State, o.SetupKey)
		}
	})
}

func TestReconcileSetupKey(t *testing.T) {
	db, _ := offerDB(t)
	pending := pendingNetBird(t, db)
	if err := db.ReconcileSetupKey(pending.IDHash, "rec1"); !errors.Is(err, ErrSetupKeyState) {
		t.Fatalf("reconcile on a live offer: %v, want ErrSetupKeyState", err)
	}
	if err := db.EndOffer(pending.IDHash, OfferAwaitingApproval, OfferFailed); err != nil {
		t.Fatal(err)
	}
	if err := db.ReconcileSetupKey(pending.IDHash, "REC1"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("bad key ID: %v, want ErrInvalid", err)
	}
	if err := db.ReconcileSetupKey(pending.IDHash, "rec1"); err != nil {
		t.Fatal(err)
	}
	r := mustOffer(t, db, pending.IDHash).SetupKey
	if r.Status != SetupKeyCreated || r.KeyID != "rec1" || !r.Verified || r.VaultRef != "" || !r.Open() {
		t.Fatalf("reconciled record %+v", r)
	}
	// A verified record is not reconciled again.
	if err := db.ReconcileSetupKey(pending.IDHash, "rec2"); !errors.Is(err, ErrSetupKeyState) {
		t.Fatalf("second reconcile: %v, want ErrSetupKeyState", err)
	}
}

func TestSetupKeyParallelPendingOneWins(t *testing.T) {
	db, _ := offerDB(t)
	n := newNetBirdOffer(t, db)
	const workers = 16
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := db.MarkSetupKeyPending(n.IDHash, testGroup)
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	won := 0
	for err := range errs {
		switch {
		case err == nil:
			won++
		case !errors.Is(err, ErrSetupKeyState):
			t.Fatalf("losing pending: %v", err)
		}
	}
	if won != 1 {
		t.Fatalf("%d pending moves won, want 1", won)
	}
}

// TestSetupKeyOpenRacingRevoke: a create answer and a revoke arrive
// together. Either the offer opens with its secret, or it is revoked with
// the record still pending and no secret; never a mix.
func TestSetupKeyOpenRacingRevoke(t *testing.T) {
	db, _ := offerDB(t)
	for i := 0; i < 20; i++ {
		n := pendingNetBird(t, db)
		var wg sync.WaitGroup
		var openErr, endErr error
		wg.Add(2)
		go func() { defer wg.Done(); openErr = db.OpenNetBirdOffer(n.IDHash, "abc", n.secret, n.script) }()
		go func() { defer wg.Done(); endErr = db.EndOffer(n.IDHash, OfferAwaitingApproval, OfferRevoked) }()
		wg.Wait()
		o := mustOffer(t, db, n.IDHash)
		_, secretErr := db.GetSecret(SetupKeyVaultRef(n.IDHash))
		switch {
		case openErr == nil && errors.Is(endErr, ErrOfferState):
			if o.State != OfferOpen || o.SetupKey.Status != SetupKeyCreated || secretErr != nil {
				t.Fatalf("open won: %s %+v secret %v", o.State, o.SetupKey, secretErr)
			}
		case endErr == nil && errors.Is(openErr, ErrOfferState):
			if o.State != OfferRevoked || o.SetupKey.Status != SetupKeyPending || !errors.Is(secretErr, ErrNoSecret) {
				t.Fatalf("revoke won: %s %+v secret %v", o.State, o.SetupKey, secretErr)
			}
		default:
			t.Fatalf("open %v, revoke %v", openErr, endErr)
		}
	}
}

func TestSetupKeyParallelRevokeAndFailureRecords(t *testing.T) {
	db, _ := offerDB(t)
	n := openNetBird(t, db)
	if err := db.EndOffer(n.IDHash, OfferOpen, OfferRevoked); err != nil {
		t.Fatal(err)
	}
	keyID := "key" + offerLogID(n.IDHash)
	const workers = 8
	var wg sync.WaitGroup
	revokes := make(chan error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(2)
		go func() { defer wg.Done(); revokes <- db.SetupKeyRevoked(n.IDHash, keyID) }()
		go func() { defer wg.Done(); db.RecordSetupKeyRevokeFailure(n.IDHash) }()
	}
	wg.Wait()
	close(revokes)
	ok := 0
	for err := range revokes {
		if err == nil {
			ok++
		} else if !errors.Is(err, ErrSetupKeyState) {
			t.Fatal(err)
		}
	}
	if ok != 1 {
		t.Fatalf("%d revokes recorded, want 1", ok)
	}
	if r := mustOffer(t, db, n.IDHash).SetupKey; r.Open() || r.KeyID != "" {
		t.Fatalf("record %+v", r)
	}
}

// TestSetupKeySchemaRefusesBypass bypasses the store: the schema alone
// keeps the record forward-only and the key ID until the record closes.
func TestSetupKeySchemaRefusesBypass(t *testing.T) {
	db, _ := offerDB(t)
	pending := pendingNetBird(t, db)
	opened := openNetBird(t, db)
	final := openNetBird(t, db)
	if err := db.EndOffer(final.IDHash, OfferOpen, OfferRevoked); err != nil {
		t.Fatal(err)
	}
	none := newNetBirdOffer(t, db)
	plain := offerIn(t, db, OfferOpen)
	if err := db.PutSecret(sealTestKey(t, "pve-token-1", "an unrelated PVE token secret")); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		q    string
		id   [32]byte
	}{
		{"pending back to none", `UPDATE enroll_offers SET setup_key_record = 'none', setup_key_name = NULL,
			setup_key_group = NULL, setup_key_window_start = NULL, setup_key_window_end = NULL WHERE id_hash = ?`, pending.IDHash},
		{"created back to pending", `UPDATE enroll_offers SET setup_key_record = 'pending', setup_key_id = NULL,
			setup_key_verified = 0 WHERE id_hash = ?`, final.IDHash},
		{"key ID wiped while open", `UPDATE enroll_offers SET setup_key_id = NULL WHERE id_hash = ?`, final.IDHash},
		{"key ID wiped with close on live offer", `UPDATE enroll_offers SET setup_key_id = NULL, setup_key_vault_ref = NULL,
			setup_key_closed_at = 1, setup_key_close = 'revoked' WHERE id_hash = ?`, opened.IDHash},
		{"key ID replaced", `UPDATE enroll_offers SET setup_key_id = 'other' WHERE id_hash = ?`, final.IDHash},
		{"key name changed", `UPDATE enroll_offers SET setup_key_name = 'nos-offer-00000000' WHERE id_hash = ?`, pending.IDHash},
		{"window widened", `UPDATE enroll_offers SET setup_key_window_end = setup_key_window_end + 3600 WHERE id_hash = ?`, pending.IDHash},
		{"pending skipped", `UPDATE enroll_offers SET setup_key_record = 'created', setup_key_name = 'nos-offer-' || lower(hex(substr(id_hash, 1, 4))),
			setup_key_group = 'g', setup_key_window_start = 1, setup_key_window_end = 2, setup_key_id = 'abc',
			setup_key_verified = 1 WHERE id_hash = ?`, none.IDHash},
		{"opened without setup key", `UPDATE enroll_offers SET state = 'open', script_sha256 = zeroblob(32) WHERE id_hash = ?`, pending.IDHash},
		{"record on plain offer", `UPDATE enroll_offers SET setup_key_record = 'pending', setup_key_name = 'nos-offer-' || lower(hex(substr(id_hash, 1, 4))),
			setup_key_group = 'g', setup_key_window_start = 1, setup_key_window_end = 2 WHERE id_hash = ?`, plain.IDHash},
		{"foreign vault secret referenced", `UPDATE enroll_offers SET setup_key_vault_ref = 'pve-token-1' WHERE id_hash = ?`, opened.IDHash},
		{"vault secret kept on final", `UPDATE enroll_offers SET state = 'failed', salt = NULL WHERE id_hash = ?`, opened.IDHash},
		{"secret deleted under a live offer", `DELETE FROM vault_secrets WHERE id = 'netbird-setup-key-' || lower(hex(substr(?, 1, 16)))`, opened.IDHash},
		{"open record deleted", `DELETE FROM enroll_offers WHERE id_hash = ?`, final.IDHash},
		{"failures decreased", `UPDATE enroll_offers SET setup_key_revoke_failures = -1 WHERE id_hash = ?`, final.IDHash},
	} {
		if _, err := db.sql.Exec(tc.q, tc.id[:]); err == nil {
			t.Errorf("%s: schema allowed it", tc.name)
		}
	}
	if _, err := db.GetSecret("pve-token-1"); err != nil {
		t.Fatalf("unrelated secret: %v", err)
	}
	if o := mustOffer(t, db, opened.IDHash); o.State != OfferOpen || o.SetupKey.VaultRef == "" {
		t.Fatal("opened offer changed")
	}
	// A closed record is frozen, and its final offer may then be deleted.
	if err := db.SetupKeyRevoked(final.IDHash, "key"+offerLogID(final.IDHash)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.sql.Exec(`UPDATE enroll_offers SET setup_key_id = 'abc', setup_key_closed_at = NULL,
		setup_key_close = NULL WHERE id_hash = ?`, final.IDHash[:]); err == nil {
		t.Error("closed record reopened")
	}
	if _, err := db.sql.Exec(`DELETE FROM enroll_offers WHERE id_hash = ?`, final.IDHash[:]); err != nil {
		t.Fatalf("delete of a final offer with a closed record: %v", err)
	}
}

func TestOrphanPeers(t *testing.T) {
	dir := privateDir(t)
	clk := &offerClock{t: t0}
	db := openOfferDB(t, dir, clk)
	n := openNetBird(t, db)
	peer := OrphanPeer{
		OfferIDHash: n.IDHash, PeerID: "ch8i4ug6lnn4g9hqv7m0", PeerName: "web-01",
		NetBirdIP: "100.92.14.7", Attribution: AttributionSetupKey,
	}
	// Only once the offer has ended without enrolling.
	if err := db.RecordOrphanPeer(peer); !errors.Is(err, ErrOfferState) {
		t.Fatalf("orphan of a live offer: %v, want ErrOfferState", err)
	}
	if err := db.EndOffer(n.IDHash, OfferOpen, OfferFailed); err != nil {
		t.Fatal(err)
	}
	if err := db.RecordOrphanPeer(peer); err != nil {
		t.Fatal(err)
	}
	if err := db.RecordOrphanPeer(peer); !errors.Is(err, ErrOrphanPeerExists) {
		t.Fatalf("duplicate: %v, want ErrOrphanPeerExists", err)
	}
	enrolled := openNetBird(t, db)
	if err := proposeOffer(db, enrolled.IDHash); err != nil {
		t.Fatal(err)
	}
	if err := db.CompleteOffer(enrolled.IDHash); err != nil {
		t.Fatal(err)
	}
	plain := offerIn(t, db, OfferFailed)
	for _, id := range [][32]byte{enrolled.IDHash, plain.IDHash} {
		p := peer
		p.OfferIDHash, p.PeerID = id, "other"
		if err := db.RecordOrphanPeer(p); !errors.Is(err, ErrOfferState) {
			t.Fatalf("orphan of enrolled or plain offer: %v, want ErrOfferState", err)
		}
	}
	p := peer
	p.OfferIDHash = rand32(t)
	if err := db.RecordOrphanPeer(p); !errors.Is(err, ErrOfferNotFound) {
		t.Fatalf("unknown offer: %v, want ErrOfferNotFound", err)
	}
	for _, mut := range []func(*OrphanPeer){
		func(p *OrphanPeer) { p.PeerID = "" },
		func(p *OrphanPeer) { p.PeerID = "UPPER" },
		func(p *OrphanPeer) { p.PeerID = strings.Repeat("a", maxOrphanPeerIDLen+1) },
		func(p *OrphanPeer) { p.PeerName = "" },
		func(p *OrphanPeer) { p.PeerName = "evil\x1b[31m" },
		func(p *OrphanPeer) { p.PeerName = "\xff" },
		func(p *OrphanPeer) { p.PeerName = strings.Repeat("n", maxOrphanPeerNameLen+1) },
		func(p *OrphanPeer) { p.NetBirdIP = "not-an-ip" },
		func(p *OrphanPeer) { p.NetBirdIP = "fe80::1%eth0" },
		func(p *OrphanPeer) { p.Attribution = "guess" },
	} {
		p := peer
		p.PeerID = "valid2"
		mut(&p)
		if err := db.RecordOrphanPeer(p); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%+v: %v, want ErrInvalid", p, err)
		}
	}
	window := peer
	window.PeerID, window.Attribution = "peer2", AttributionTimeWindow
	if err := db.RecordOrphanPeer(window); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	db2 := openOfferDB(t, dir, clk)
	list, err := db2.OrphanPeers()
	if err != nil || len(list) != 2 {
		t.Fatalf("orphans after restart: %d, %v", len(list), err)
	}
	if got := list[0]; got.PeerID != peer.PeerID || got.PeerName != peer.PeerName || got.NetBirdIP != peer.NetBirdIP ||
		got.Attribution != AttributionSetupKey || got.OfferIDHash != n.IDHash || !got.RecordedAt.Equal(clk.Now()) ||
		got.Decision != "" {
		t.Fatalf("orphan %+v", got)
	}
	if err := db2.DecideOrphanPeer(peer.PeerID, "maybe"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("bad decision: %v, want ErrInvalid", err)
	}
	if err := db2.DecideOrphanPeer("nope", OrphanPeerDeleted); !errors.Is(err, ErrOrphanPeerNotFound) {
		t.Fatalf("unknown peer: %v, want ErrOrphanPeerNotFound", err)
	}
	if err := db2.DecideOrphanPeer(peer.PeerID, OrphanPeerDeleted); err != nil {
		t.Fatal(err)
	}
	if err := db2.DecideOrphanPeer(peer.PeerID, OrphanPeerKept); !errors.Is(err, ErrOrphanPeerDecided) {
		t.Fatalf("second decision: %v, want ErrOrphanPeerDecided", err)
	}
	list, err = db2.OrphanPeers()
	if err != nil || len(list) != 1 || list[0].PeerID != "peer2" {
		t.Fatalf("undecided orphans: %+v, %v", list, err)
	}
	// An offer with an undecided orphan is not deleted.
	if _, err := db2.sql.Exec(`DELETE FROM enroll_offers WHERE id_hash = ?`, n.IDHash[:]); err == nil {
		t.Fatal("offer with orphan peers deleted")
	}
}

// TestSetupKeyErrorsCarryNoSecret: errors from the setup-key store name
// the offer by its 8-hex prefix only and never carry the sealed secret.
func TestSetupKeyErrorsCarryNoSecret(t *testing.T) {
	db, clk := offerDB(t)
	n := pendingNetBird(t, db)
	clk.Add(OfferLifetime)
	err := db.OpenNetBirdOffer(n.IDHash, "abc", n.secret, n.script)
	if err == nil {
		t.Fatal("open after expiry succeeded")
	}
	msg := err.Error()
	full := hex.EncodeToString(n.IDHash[:])
	for _, s := range []string{full, n.key, hex.EncodeToString(n.secret.Sealed), fmt.Sprintf("%x", n.secret.Sealed[:8])} {
		if strings.Contains(msg, s) {
			t.Fatalf("error %q carries a secret or the full ID hash", msg)
		}
	}
	if !strings.Contains(msg, full[:8]) {
		t.Fatalf("error %q does not name the offer", msg)
	}
}

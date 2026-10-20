// SPDX-License-Identifier: AGPL-3.0-or-later

package executordb

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/events"
)

func TestEventsAreAppendOnly(t *testing.T) {
	db := openT(t, privateDir(t))
	chain := events.NewChain(db, ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32)))
	for i := 0; i < 3; i++ {
		if _, err := chain.Append("x", map[string]string{"i": string(rune('a' + i))}); err != nil {
			t.Fatal(err)
		}
	}
	recs, err := db.Events(0, 10)
	if err != nil || len(recs) != 3 {
		t.Fatal(len(recs), err)
	}
	if err := events.Verify(chain.PublicKey(), recs, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := db.sql.Exec(`UPDATE events SET body = x'00' WHERE seq = 2`); err == nil {
		t.Fatal("event updated")
	}
	if _, err := db.sql.Exec(`DELETE FROM events WHERE seq = 3`); err == nil {
		t.Fatal("event deleted")
	}
	// Only the next sequence number is accepted.
	r := recs[2]
	r.Seq = 7
	if err := db.InsertEvent(r); err == nil {
		t.Fatal("gap accepted")
	}
	if got, err := db.EventAt(2); err != nil || !bytes.Equal(got.Hash, recs[1].Hash) {
		t.Fatal(err)
	}
	if _, err := db.EventAt(99); !errors.Is(err, ErrEventNotFound) {
		t.Fatal(err)
	}
	if seq, hash, err := db.LastEvent(); err != nil || seq != 3 || !bytes.Equal(hash, recs[2].Hash) {
		t.Fatal(seq, err)
	}
}

// A new event key takes over from the next event; the old events still
// verify with the key that signed them.
func TestEventKeyHistory(t *testing.T) {
	dir := privateDir(t)
	db := openT(t, dir)
	k1 := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32))
	k2 := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, 32))
	c1 := events.NewChain(db, k1)
	// Events before any key was recorded (an install from M10-1).
	_, _ = c1.Append("a", nil)
	_, _ = c1.Append("b", nil)
	if added, prev, err := db.RegisterEventKey(c1.PublicKey()); err != nil || !added || prev != nil {
		t.Fatal(added, prev, err)
	}
	if added, _, _ := db.RegisterEventKey(c1.PublicKey()); added {
		t.Fatal("registered twice")
	}
	c2 := events.NewChain(db, k2)
	added, prev, err := db.RegisterEventKey(c2.PublicKey())
	if err != nil || !added || !bytes.Equal(prev, c1.PublicKey()) {
		t.Fatal(added, err)
	}
	_, _ = c2.Append("c", nil)
	keys, err := db.EventKeys()
	if err != nil || len(keys) != 2 || keys[0].FirstSeq != 1 || keys[1].FirstSeq != 3 {
		t.Fatalf("%+v %v", keys, err)
	}
	recs, _ := db.Events(0, 10)
	if err := events.VerifyKeys(keys, recs, nil); err != nil {
		t.Fatal(err)
	}
	// One key for all of them does not verify.
	if err := events.Verify(c2.PublicKey(), recs, nil); err == nil {
		t.Fatal("old events verified with the new key")
	}
	if _, err := db.sql.Exec(`DELETE FROM event_keys`); err == nil {
		t.Fatal("key history deleted")
	}
	if _, _, err := db.RegisterEventKey([]byte("short")); err == nil {
		t.Fatal("bad key accepted")
	}
}

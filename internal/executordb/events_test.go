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

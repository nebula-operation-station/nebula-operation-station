// SPDX-License-Identifier: AGPL-3.0-or-later

package events

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// testKey returns a deterministic Ed25519 key whose seed is filled with b.
func testKey(b byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{b}, ed25519.SeedSize))
}

func pubOf(k ed25519.PrivateKey) ed25519.PublicKey {
	return k.Public().(ed25519.PublicKey)
}

// keyedChain is a chain over st signed with key and a fixed clock.
func keyedChain(st *memStore, key ed25519.PrivateKey) *Chain {
	c := NewChain(st, key)
	c.now = func() time.Time { return time.Unix(1_800_000_000, 0).UTC() }
	return c
}

// twoKeyChain returns events 1-2 signed by k1 and events 3-4 signed by k2,
// the key switch at FirstSeq 3.
func twoKeyChain(t *testing.T, k1, k2 ed25519.PrivateKey) *memStore {
	t.Helper()
	st := &memStore{}
	for i := 0; i < 2; i++ {
		if _, err := keyedChain(st, k1).Append("first", nil); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 2; i++ {
		if _, err := keyedChain(st, k2).Append("second", nil); err != nil {
			t.Fatal(err)
		}
	}
	return st
}

// signedRecord builds a record with the given sequence number and body,
// linked to prev and signed by key. The body's own seq may differ from
// recSeq; that is what the tests need to build.
func signedRecord(t *testing.T, key ed25519.PrivateKey, recSeq int64, body Body, prev []byte) Record {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	r := Record{Seq: recSeq, Body: raw, PrevHash: prev}
	r.Hash = hashOf(prev, raw)
	r.Sig = ed25519.Sign(key, r.Hash)
	return r
}

func decodeBody(t *testing.T, r Record) Body {
	t.Helper()
	var b Body
	if err := json.Unmarshal(r.Body, &b); err != nil {
		t.Fatal(err)
	}
	return b
}

func TestVerifyKeysAcceptsKeySwitchAtFirstSeq(t *testing.T) {
	k1, k2 := testKey(1), testKey(2)
	st := twoKeyChain(t, k1, k2)
	keys := []Key{{FirstSeq: 1, PublicKey: pubOf(k1)}, {FirstSeq: 3, PublicKey: pubOf(k2)}}

	if err := VerifyKeys(keys, st.recs, nil); err != nil {
		t.Fatalf("whole chain: %v", err)
	}
	// A page starting at the switch verifies against the hash before it.
	if err := VerifyKeys(keys, st.recs[2:], st.recs[1].Hash); err != nil {
		t.Fatalf("page at FirstSeq: %v", err)
	}
	// A page ending right before the switch verifies with the first key only.
	if err := VerifyKeys(keys[:1], st.recs[:2], nil); err != nil {
		t.Fatalf("page before FirstSeq: %v", err)
	}
}

func TestVerifyKeysRejectsWrongKeyForRange(t *testing.T) {
	k1, k2 := testKey(1), testKey(2)
	p1, p2 := pubOf(k1), pubOf(k2)
	st := twoKeyChain(t, k1, k2)

	// Event 2 is signed by k1 but the range starting at 2 names k2.
	// The range check is the only thing that can catch this: the hashes and
	// links are all correct.
	if err := VerifyKeys([]Key{{FirstSeq: 1, PublicKey: p1}, {FirstSeq: 2, PublicKey: p2}}, st.recs, nil); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("event 2 under key 2: got %v, want ErrBadSignature", err)
	}
	// Event 3 is signed by k2, but the switch to k2 comes only at 5, so
	// event 3 is checked against k1.
	if err := VerifyKeys([]Key{{FirstSeq: 1, PublicKey: p1}, {FirstSeq: 5, PublicKey: p2}}, st.recs, nil); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("event 3 under key 1: got %v, want ErrBadSignature", err)
	}
}

func TestVerifyKeysRejectsEventBeforeFirstRange(t *testing.T) {
	k1, k2 := testKey(1), testKey(2)
	st := twoKeyChain(t, k1, k2)
	// No range covers events 1 and 2, so there is no key to check them with.
	keys := []Key{{FirstSeq: 3, PublicKey: pubOf(k2)}}
	if err := VerifyKeys(keys, st.recs, nil); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("got %v, want ErrBadSignature", err)
	}
}

func TestVerifyKeysRejectsSeqMismatchInBody(t *testing.T) {
	k1, k2 := testKey(1), testKey(2)
	st := twoKeyChain(t, k1, k2)
	keys := []Key{{FirstSeq: 1, PublicKey: pubOf(k1)}, {FirstSeq: 3, PublicKey: pubOf(k2)}}

	// Event 2 with a correct hash and a valid signature, but a body that
	// says seq 7. The check that the body carries Record.Seq must catch it.
	body := decodeBody(t, st.recs[1])
	body.Seq = 7
	forged := signedRecord(t, k1, 2, body, st.recs[0].Hash)
	if err := VerifyKeys(keys, []Record{st.recs[0], forged}, nil); !errors.Is(err, ErrBadHash) {
		t.Fatalf("got %v, want ErrBadHash", err)
	}
}

func TestVerifyKeysRejectsFirstEventWithPrevHash(t *testing.T) {
	k1, k2 := testKey(1), testKey(2)
	st := twoKeyChain(t, k1, k2)
	keys := []Key{{FirstSeq: 1, PublicKey: pubOf(k1)}, {FirstSeq: 3, PublicKey: pubOf(k2)}}

	// Event 1 is correctly hashed and signed, but it claims a predecessor.
	// Event 1 has no predecessor, so its PrevHash must be zeros.
	prev := bytes.Repeat([]byte{0xff}, sha256.Size)
	first := signedRecord(t, k1, 1, decodeBody(t, st.recs[0]), prev)
	if err := VerifyKeys(keys, []Record{first}, nil); !errors.Is(err, ErrBrokenChain) {
		t.Fatalf("got %v, want ErrBrokenChain", err)
	}
}

func TestVerifyKeysRejectsBrokenLinkAcrossKeySwitch(t *testing.T) {
	k1, k2 := testKey(1), testKey(2)
	st := twoKeyChain(t, k1, k2)
	keys := []Key{{FirstSeq: 1, PublicKey: pubOf(k1)}, {FirstSeq: 3, PublicKey: pubOf(k2)}}

	// Event 3 is correctly signed by k2 and hashed, but it links to zeros
	// instead of to event 2.
	zeros := make([]byte, sha256.Size)
	third := signedRecord(t, k2, 3, decodeBody(t, st.recs[2]), zeros)
	if err := VerifyKeys(keys, []Record{st.recs[0], st.recs[1], third}, nil); !errors.Is(err, ErrBrokenChain) {
		t.Fatalf("got %v, want ErrBrokenChain", err)
	}
}

func TestVerifyKeysRejectsChangedRecord(t *testing.T) {
	k1, k2 := testKey(1), testKey(2)
	st := twoKeyChain(t, k1, k2)
	keys := []Key{{FirstSeq: 1, PublicKey: pubOf(k1)}, {FirstSeq: 3, PublicKey: pubOf(k2)}}
	base := func() []Record { return append([]Record(nil), st.recs...) }

	cases := []struct {
		name   string
		mutate func(rs []Record) []Record
		want   error
	}{
		{"body byte changed", func(rs []Record) []Record {
			rs[2].Body = bytes.Replace(rs[2].Body, []byte("second"), []byte("evils"), 1)
			return rs
		}, ErrBadHash},
		{"hash changed", func(rs []Record) []Record {
			rs[1].Hash = append([]byte(nil), rs[1].Hash...)
			rs[1].Hash[0] ^= 1
			return rs
		}, ErrBadHash},
		{"signature changed", func(rs []Record) []Record {
			rs[3].Sig = append([]byte(nil), rs[3].Sig...)
			rs[3].Sig[0] ^= 1
			return rs
		}, ErrBadSignature},
		{"events reordered", func(rs []Record) []Record {
			rs[1], rs[2] = rs[2], rs[1]
			return rs
		}, ErrBrokenChain},
		{"event dropped", func(rs []Record) []Record {
			return append(rs[:1:1], rs[2:]...)
		}, ErrBrokenChain},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rs := tc.mutate(base())
			if err := VerifyKeys(keys, rs, nil); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

func TestVerifyKeysRejectsUnorderedRanges(t *testing.T) {
	k1, k2 := testKey(1), testKey(2)
	st := twoKeyChain(t, k1, k2)
	p1, p2 := pubOf(k1), pubOf(k2)
	for name, keys := range map[string][]Key{
		"descending":    {{FirstSeq: 3, PublicKey: p2}, {FirstSeq: 1, PublicKey: p1}},
		"duplicate seq": {{FirstSeq: 1, PublicKey: p1}, {FirstSeq: 1, PublicKey: p2}},
	} {
		err := VerifyKeys(keys, st.recs, nil)
		if err == nil || !strings.Contains(err.Error(), "key ranges are not in order") {
			t.Errorf("%s: got %v, want the key-range order error", name, err)
		}
	}
}

func TestKeysOrFallsBackToCurrentKey(t *testing.T) {
	pub := pubOf(testKey(9))

	for name, in := range map[string][]Key{"nil": nil, "empty": {}} {
		got := KeysOr(in, pub)
		if len(got) != 1 || got[0].FirstSeq != 1 || !bytes.Equal(got[0].PublicKey, pub) {
			t.Errorf("%s: got %+v, want one key from event 1", name, got)
		}
	}

	given := []Key{{FirstSeq: 1, PublicKey: pubOf(testKey(1))}, {FirstSeq: 4, PublicKey: pubOf(testKey(2))}}
	got := KeysOr(given, pub)
	if len(got) != len(given) || &got[0] != &given[0] {
		t.Fatalf("non-empty list was not returned unchanged: %+v", got)
	}
}

func TestKeysOrVerifiesChainWithCurrentKey(t *testing.T) {
	k := testKey(3)
	st := &memStore{}
	if _, err := keyedChain(st, k).Append("x", nil); err != nil {
		t.Fatal(err)
	}
	if err := VerifyKeys(KeysOr(nil, pubOf(k)), st.recs, nil); err != nil {
		t.Fatalf("own key: %v", err)
	}
	if err := VerifyKeys(KeysOr(nil, pubOf(testKey(4))), st.recs, nil); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("other key: got %v, want ErrBadSignature", err)
	}
}

func TestAppendAttrCountLimitIsExact(t *testing.T) {
	for _, n := range []int{MaxAttrs, MaxAttrs + 1} {
		c, st := newChain(t)
		attrs := make(map[string]string, n)
		for i := 0; i < n; i++ {
			attrs[fmt.Sprintf("k%02d", i)] = "v"
		}
		if _, err := c.Append("limit", attrs); err != nil {
			t.Fatal(err)
		}
		b := decodeBody(t, st.recs[0])
		_, marked := b.Attrs["_truncated"]
		if wantMarked := n > MaxAttrs; marked != wantMarked {
			t.Fatalf("%d attrs: _truncated present=%v, want %v", n, marked, wantMarked)
		}
		wantLen := n
		if n > MaxAttrs {
			wantLen = MaxAttrs + 1 // MaxAttrs kept plus the marker
		}
		if len(b.Attrs) != wantLen {
			t.Fatalf("%d attrs: stored %d, want %d", n, len(b.Attrs), wantLen)
		}
		if n > MaxAttrs {
			// Keys are kept in sorted order: k00..k31 stay, k32 is dropped.
			if _, ok := b.Attrs[fmt.Sprintf("k%02d", MaxAttrs-1)]; !ok {
				t.Fatalf("last kept key missing")
			}
			if _, ok := b.Attrs[fmt.Sprintf("k%02d", MaxAttrs)]; ok {
				t.Fatalf("key beyond the limit was stored")
			}
		}
	}
}

func TestAppendAttrValueLimitIsExact(t *testing.T) {
	cases := []struct {
		name  string
		value string
		want  string
	}{
		{"exactly MaxAttrValue bytes", strings.Repeat("a", MaxAttrValue), strings.Repeat("a", MaxAttrValue)},
		{"MaxAttrValue+1 bytes", strings.Repeat("a", MaxAttrValue+1), strings.Repeat("a", MaxAttrValue)},
		// 2-byte runes: 512 of them are exactly 1024 bytes and stay whole;
		// 513 are 1026 bytes and are cut at a rune boundary (512 runes).
		{"exactly MaxAttrValue bytes of 2-byte runes", strings.Repeat("é", MaxAttrValue/2), strings.Repeat("é", MaxAttrValue/2)},
		{"one rune over, multi-byte", strings.Repeat("é", MaxAttrValue/2+1), strings.Repeat("é", MaxAttrValue/2)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, st := newChain(t)
			if _, err := c.Append("limit", map[string]string{"v": tc.value}); err != nil {
				t.Fatal(err)
			}
			got := decodeBody(t, st.recs[0]).Attrs["v"]
			if got != tc.want {
				t.Fatalf("stored %d bytes, want %d bytes equal to the prefix", len(got), len(tc.want))
			}
		})
	}
}

// FuzzVerifyKeys checks two things. Arbitrary records and keys never panic.
// A valid two-key chain with one byte changed never verifies.
func FuzzVerifyKeys(f *testing.F) {
	f.Add([]byte("seed"), uint(1), byte(1), uint(0), uint(0))
	f.Add([]byte{}, uint(3), byte(0xff), uint(2), uint(31))
	f.Add(bytes.Repeat([]byte{0xab}, 300), uint(17), byte(0x80), uint(1), uint(7))

	f.Fuzz(func(t *testing.T, data []byte, at uint, mask byte, field, pos uint) {
		// Part 1: arbitrary input must not panic and must not crash on
		// odd key sizes or unordered ranges.
		seedA := sha256.Sum256(data)
		arbKeys := []Key{
			{FirstSeq: int64(at%4) + 1, PublicKey: data},
			{FirstSeq: int64(at%3) + 2, PublicKey: seedA[:]},
		}
		arb := []Record{{Seq: int64(at), Body: data, PrevHash: data, Hash: seedA[:], Sig: data}}
		_ = VerifyKeys(arbKeys, arb, data)
		_ = VerifyKeys(nil, nil, nil)

		// Part 2: a valid chain verifies; one changed byte never does.
		k1 := ed25519.NewKeyFromSeed(seedA[:])
		seedB := sha256.Sum256(seedA[:])
		k2 := ed25519.NewKeyFromSeed(seedB[:])
		st := &memStore{}
		for i := 0; i < 2; i++ {
			if _, err := keyedChain(st, k1).Append("fuzz", map[string]string{"v": string(data)}); err != nil {
				t.Fatal(err)
			}
		}
		for i := 0; i < 2; i++ {
			if _, err := keyedChain(st, k2).Append("fuzz", map[string]string{"v": string(data)}); err != nil {
				t.Fatal(err)
			}
		}
		keys := []Key{{FirstSeq: 1, PublicKey: pubOf(k1)}, {FirstSeq: 3, PublicKey: pubOf(k2)}}
		if err := VerifyKeys(keys, st.recs, nil); err != nil {
			t.Fatalf("valid chain does not verify: %v", err)
		}

		m := mask
		if m == 0 {
			m = 1 // XOR with 0 would change nothing
		}
		idx := int(at % uint(len(st.recs)))
		rs := append([]Record(nil), st.recs...)
		r := rs[idx]
		var target *[]byte
		switch field % 4 {
		case 0:
			target = &r.Body
		case 1:
			target = &r.PrevHash
		case 2:
			target = &r.Hash
		default:
			target = &r.Sig
		}
		changed := append([]byte(nil), (*target)...)
		changed[int(pos%uint(len(changed)))] ^= m
		*target = changed
		rs[idx] = r
		if err := VerifyKeys(keys, rs, nil); err == nil {
			t.Fatalf("record %d with a changed byte verified (field %d, pos %d)", idx, field%4, pos)
		}
	})
}

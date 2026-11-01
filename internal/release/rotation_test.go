// SPDX-License-Identifier: AGPL-3.0-or-later

package release

import (
	"errors"
	"sort"
	"testing"
)

type rotDoc struct {
	seq    int64
	prev   string
	add    map[string]*testSK
	revoke []string
}

func (d rotDoc) bytes(t *testing.T) []byte {
	t.Helper()
	adds := []any{}
	ids := make([]string, 0, len(d.add))
	for id := range d.add {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		adds = append(adds, map[string]any{"id": id, "public_key": FormatRootKey(d.add[id].pub)})
	}
	rev := []any{}
	for _, r := range d.revoke {
		rev = append(rev, r)
	}
	return canon(t, map[string]any{"format": RotationFormat, "sequence": d.seq, "previous_sha256": d.prev, "add": adds, "revoke": rev})
}

func bootstrapWith(t *testing.T, k *testSK) RootState {
	t.Helper()
	s, err := Bootstrap([]Anchor{{ID: "root-1", Key: k.pub}, {ID: "root-2"}})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// The documented path: root-1 enrolls the backup root-2; the backup can
// later revoke the primary and add a replacement; the revoked primary
// can no longer admit releases, even an old manifest.
func TestRotationEnrollRevokeReplace(t *testing.T) {
	r1, r2, r3 := newTestSK(t), newTestSK(t), newTestSK(t)
	s0 := bootstrapWith(t, r1)

	doc1 := rotDoc{seq: 1, prev: ZeroDigest, add: map[string]*testSK{"root-2": r2}}.bytes(t)
	s1, rot1, err := s0.ApplyRotation(doc1, r1.sign(t, doc1))
	if err != nil {
		t.Fatal(err)
	}
	if rot1.SignedBy.ID != "root-1" || len(s1.Active()) != 2 || s1.Sequence != 1 || s1.Digest != hexSum(doc1) {
		t.Fatalf("after enrollment: %+v", s1)
	}
	if len(s0.Active()) != 1 {
		t.Fatal("ApplyRotation modified the input state")
	}

	man, _ := defaultRelease(t)
	raw := canon(t, man)
	oldSig := r1.sign(t, raw)

	doc2 := rotDoc{seq: 2, prev: s1.Digest, add: map[string]*testSK{"root-3": r3}, revoke: []string{"root-1"}}.bytes(t)
	s2, _, err := s1.ApplyRotation(doc2, r2.sign(t, doc2))
	if err != nil {
		t.Fatal(err)
	}
	act := s2.Active()
	if len(act) != 2 || act[0].ID != "root-2" || act[1].ID != "root-3" {
		t.Fatalf("after replacement: %+v", act)
	}
	if _, err := VerifyManifest(act, raw, oldSig); !errors.Is(err, ErrUntrusted) {
		t.Fatalf("revoked root admitted an old manifest: %v", err)
	}
	if _, err := VerifyManifest(act, raw, r3.sign(t, raw)); err != nil {
		t.Fatalf("replacement root: %v", err)
	}
	// The state round-trips through Validate (persisted form).
	if err := s2.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestRotationRejects(t *testing.T) {
	r1, r2, r3 := newTestSK(t), newTestSK(t), newTestSK(t)
	s0 := bootstrapWith(t, r1)
	doc1 := rotDoc{seq: 1, prev: ZeroDigest, add: map[string]*testSK{"root-2": r2}}.bytes(t)
	s1, _, err := s0.ApplyRotation(doc1, r1.sign(t, doc1))
	if err != nil {
		t.Fatal(err)
	}
	five := map[string]*testSK{"root-3": newTestSK(t), "root-4": newTestSK(t), "root-5": newTestSK(t)}

	for name, tc := range map[string]struct {
		state  RootState
		doc    rotDoc
		signer *testSK
		want   error
	}{
		"self-enrollment":       {s0, rotDoc{seq: 1, prev: ZeroDigest, add: map[string]*testSK{"root-2": r2}}, r2, ErrUntrusted},
		"replay":                {s1, rotDoc{seq: 1, prev: ZeroDigest, add: map[string]*testSK{"root-2": r2}}, r1, ErrRotation},
		"skipped sequence":      {s1, rotDoc{seq: 3, prev: s1.Digest, add: map[string]*testSK{"root-3": r3}}, r1, ErrRotation},
		"wrong predecessor":     {s1, rotDoc{seq: 2, prev: ZeroDigest, add: map[string]*testSK{"root-3": r3}}, r1, ErrRotation},
		"reused id":             {s1, rotDoc{seq: 2, prev: s1.Digest, add: map[string]*testSK{"root-2": r3}}, r1, ErrRotation},
		"reused key":            {s1, rotDoc{seq: 2, prev: s1.Digest, add: map[string]*testSK{"root-3": r2}}, r1, ErrRotation},
		"unknown revocation":    {s1, rotDoc{seq: 2, prev: s1.Digest, revoke: []string{"root-9"}}, r1, ErrRotation},
		"add revoke overlap":    {s1, rotDoc{seq: 2, prev: s1.Digest, add: map[string]*testSK{"root-2": r3}, revoke: []string{"root-2"}}, r1, ErrRotation},
		"revoke all":            {s1, rotDoc{seq: 2, prev: s1.Digest, revoke: []string{"root-1", "root-2"}}, r1, ErrRotation},
		"more than four active": {s1, rotDoc{seq: 2, prev: s1.Digest, add: five}, r1, ErrRotation},
		"empty change":          {s1, rotDoc{seq: 2, prev: s1.Digest}, r1, ErrFormat},
		"untrusted signer":      {s1, rotDoc{seq: 2, prev: s1.Digest, revoke: []string{"root-2"}}, r3, ErrUntrusted},
	} {
		t.Run(name, func(t *testing.T) {
			raw := tc.doc.bytes(t)
			if _, _, err := tc.state.ApplyRotation(raw, tc.signer.sign(t, raw)); !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}

	// A revoked root's ID or key can never come back.
	doc2 := rotDoc{seq: 2, prev: s1.Digest, revoke: []string{"root-1"}}.bytes(t)
	s2, _, err := s1.ApplyRotation(doc2, r2.sign(t, doc2))
	if err != nil {
		t.Fatal(err)
	}
	for name, add := range map[string]map[string]*testSK{
		"revoked key again": {"root-7": r1},
		"revoked id again":  {"root-1": r3},
	} {
		raw := rotDoc{seq: 3, prev: s2.Digest, add: add}.bytes(t)
		if _, _, err := s2.ApplyRotation(raw, r2.sign(t, raw)); !errors.Is(err, ErrRotation) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	// A rotation is not a manifest and vice versa (format separates them).
	if _, err := VerifyManifest(s1.Active(), doc1, r1.sign(t, doc1)); !errors.Is(err, ErrFormat) {
		t.Fatalf("rotation accepted as manifest: %v", err)
	}
	man, _ := defaultRelease(t)
	mraw := canon(t, man)
	if _, _, err := s1.ApplyRotation(mraw, r1.sign(t, mraw)); !errors.Is(err, ErrFormat) {
		t.Fatalf("manifest accepted as rotation: %v", err)
	}
}

func TestRootStateValidateRejectsTampering(t *testing.T) {
	r1 := newTestSK(t)
	good := bootstrapWith(t, r1)
	for name, mut := range map[string]func(s *RootState){
		"no roots":           func(s *RootState) { s.Roots = nil },
		"bad digest":         func(s *RootState) { s.Digest = "x" },
		"seq without digest": func(s *RootState) { s.Sequence = 1 },
		"revoked all": func(s *RootState) {
			s.Sequence, s.Digest = 1, hexSum([]byte("x"))
			s.Roots[0].RevokedSequence = 1
		},
		"future add": func(s *RootState) { s.Roots[0].AddedSequence = 5 },
		"bad key":    func(s *RootState) { s.Roots[0].PublicKey = "ssh-ed25519 AAAA" },
		"bad id":     func(s *RootState) { s.Roots[0].ID = "root-0" },
	} {
		s := good
		s.Roots = append([]RootRecord(nil), good.Roots...)
		mut(&s)
		if err := s.Validate(); !errors.Is(err, ErrFormat) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

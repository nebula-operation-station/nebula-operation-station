// SPDX-License-Identifier: AGPL-3.0-or-later

package release

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// RotationFormat is the "format" of a root rotation document.
const RotationFormat = "nebula-root-rotation-v1"

// Rotation limits (spec 10, root rotation and revocation).
const (
	// MaxRotation bounds root-rotation.json.
	MaxRotation = 16 << 10
	// MaxRotationEntries bounds add and revoke, each.
	MaxRotationEntries = 4
	// MaxSequence is the largest rotation sequence (2^53 - 1).
	MaxSequence = 1<<53 - 1
	// MaxRotations bounds the rotation records an executor keeps; more
	// needs a reviewed capacity change, never dropped evidence.
	MaxRotations = 1024
)

// ZeroDigest is previous_sha256 of the first rotation (bootstrap
// sequence 0).
var ZeroDigest = strings.Repeat("0", 64)

// RootRecord is one root ever enrolled: by a compiled anchor (sequence 0)
// or by a rotation. Records are never removed, so a revoked or replaced
// ID or key can never be enrolled again.
type RootRecord struct {
	// ID is the root label.
	ID string `json:"id"`
	// PublicKey is the key as FormatRootKey writes it.
	PublicKey string `json:"public_key"`
	// AddedSequence is the rotation sequence that enrolled the root; 0
	// for a bootstrap anchor.
	AddedSequence int64 `json:"added_sequence"`
	// RevokedSequence is the rotation that revoked it; 0 while active.
	RevokedSequence int64 `json:"revoked_sequence"`
}

// RootState is the executor's durable root state. It is persisted
// atomically with every applied rotation, survives restart, downgrade and
// software replacement, and is never reset from a downloaded bundle.
type RootState struct {
	// Sequence is the last applied rotation sequence; 0 at bootstrap.
	Sequence int64 `json:"sequence"`
	// Digest is the SHA-256 of the last applied canonical rotation
	// document; ZeroDigest at bootstrap.
	Digest string `json:"digest"`
	// Roots are all roots ever enrolled, sorted by ID.
	Roots []RootRecord `json:"roots"`
}

// Bootstrap returns the initial root state of a fresh installation from
// the compiled anchors. An installation that already has root state must
// load it instead; missing state there blocks admission.
func Bootstrap(anchors []Anchor) (RootState, error) {
	s := RootState{Digest: ZeroDigest}
	for _, a := range anchors {
		if a.Key == nil {
			continue
		}
		s.Roots = append(s.Roots, RootRecord{ID: a.ID, PublicKey: FormatRootKey(a.Key)})
	}
	sort.Slice(s.Roots, func(i, j int) bool { return s.Roots[i].ID < s.Roots[j].ID })
	if err := s.Validate(); err != nil {
		return RootState{}, err
	}
	return s, nil
}

// Validate checks a loaded root state for internal consistency.
func (s RootState) Validate() error {
	bad := func(why string) error { return fmt.Errorf("%w: root state %s", ErrFormat, why) }
	if s.Sequence < 0 || s.Sequence > MaxRotations || !validSHA256(s.Digest) || (s.Sequence == 0) != (s.Digest == ZeroDigest) {
		return bad("has an invalid sequence or digest")
	}
	keys := map[string]bool{}
	active := 0
	for i, r := range s.Roots {
		if !ValidRootID(r.ID) || (i > 0 && s.Roots[i-1].ID >= r.ID) {
			return bad("has invalid or unsorted root IDs")
		}
		k, err := ParseRootKey(r.PublicKey)
		if err != nil || keys[string(k.Marshal())] {
			return bad("has an invalid or duplicate key")
		}
		keys[string(k.Marshal())] = true
		if r.AddedSequence < 0 || r.AddedSequence > s.Sequence || r.RevokedSequence < 0 || r.RevokedSequence > s.Sequence ||
			(r.RevokedSequence != 0 && r.RevokedSequence <= r.AddedSequence) {
			return bad("has inconsistent root sequences")
		}
		if r.RevokedSequence == 0 {
			active++
		}
	}
	if active == 0 || active > MaxActiveRoots {
		return bad(fmt.Sprintf("needs 1 to %d active roots", MaxActiveRoots))
	}
	return nil
}

// Active returns the currently trusted, non-revoked roots.
func (s RootState) Active() []Root {
	var out []Root
	for _, r := range s.Roots {
		if r.RevokedSequence != 0 {
			continue
		}
		if k, err := ParseRootKey(r.PublicKey); err == nil {
			out = append(out, Root{ID: r.ID, Key: k})
		}
	}
	return out
}

// Rotation is an applied rotation document.
type Rotation struct {
	// Sequence is the document's sequence.
	Sequence int64
	// Digest is the SHA-256 of the exact document bytes.
	Digest string
	// Added are the enrolled roots; Revoked the revoked root IDs.
	Added   []Root
	Revoked []string
	// SignedBy is the pre-rotation root that authorized it.
	SignedBy Root

	previous string
}

// ApplyRotation verifies a signed rotation against s (the state before
// the document) and returns the new state. A newly added key cannot
// authorize its own enrollment. Replays, skipped sequences, wrong
// predecessors, reuse of an ID or key, unknown revocations, overlap and
// an active-root count outside 1..4 are rejected. s is not modified.
func (s RootState) ApplyRotation(raw, sig []byte) (RootState, Rotation, error) {
	if err := s.Validate(); err != nil {
		return RootState{}, Rotation{}, err
	}
	if len(raw) == 0 || len(raw) > MaxRotation {
		return RootState{}, Rotation{}, fmt.Errorf("%w: rotation must be 1 to %d bytes", ErrFormat, MaxRotation)
	}
	signer, err := verifyDocument(s.Active(), raw, sig)
	if err != nil {
		return RootState{}, Rotation{}, err
	}
	doc, err := decodeCanonical(raw, MaxRotation)
	if err != nil {
		return RootState{}, Rotation{}, err
	}
	rot, err := parseRotation(doc)
	if err != nil {
		return RootState{}, Rotation{}, fmt.Errorf("%w: rotation: %v", ErrFormat, err)
	}
	sum := sha256.Sum256(raw)
	rot.Digest = hex.EncodeToString(sum[:])
	rot.SignedBy = signer
	reject := func(why string) (RootState, Rotation, error) {
		return RootState{}, Rotation{}, fmt.Errorf("%w: %s", ErrRotation, why)
	}
	if rot.Sequence != s.Sequence+1 {
		return reject(fmt.Sprintf("sequence %d does not follow %d", rot.Sequence, s.Sequence))
	}
	if rot.Sequence > MaxRotations {
		return reject(fmt.Sprintf("more than %d rotations need a reviewed capacity change", MaxRotations))
	}
	if rot.previous != s.Digest {
		return reject("previous_sha256 does not match the last applied rotation")
	}
	next := RootState{Sequence: rot.Sequence, Digest: rot.Digest, Roots: append([]RootRecord(nil), s.Roots...)}
	byID := map[string]int{}
	keys := map[string]bool{}
	for i, r := range next.Roots {
		byID[r.ID] = i
		if k, err := ParseRootKey(r.PublicKey); err == nil {
			keys[string(k.Marshal())] = true
		}
	}
	for _, id := range rot.Revoked {
		i, ok := byID[id]
		if !ok || next.Roots[i].RevokedSequence != 0 {
			return reject(fmt.Sprintf("revoke names %s, which is not an active root", id))
		}
		next.Roots[i].RevokedSequence = rot.Sequence
	}
	revoking := map[string]bool{}
	for _, id := range rot.Revoked {
		revoking[id] = true
	}
	for _, a := range rot.Added {
		if revoking[a.ID] {
			return reject(fmt.Sprintf("%s is both added and revoked", a.ID))
		}
		if _, ok := byID[a.ID]; ok {
			return reject(fmt.Sprintf("root ID %s was enrolled before", a.ID))
		}
		blob := string(a.Key.Marshal())
		if keys[blob] {
			return reject(fmt.Sprintf("the key for %s was enrolled before", a.ID))
		}
		keys[blob] = true
		next.Roots = append(next.Roots, RootRecord{ID: a.ID, PublicKey: FormatRootKey(a.Key), AddedSequence: rot.Sequence})
	}
	sort.Slice(next.Roots, func(i, j int) bool { return next.Roots[i].ID < next.Roots[j].ID })
	if n := len(next.Active()); n == 0 || n > MaxActiveRoots {
		return reject(fmt.Sprintf("the rotation leaves %d active roots; 1 to %d are allowed", n, MaxActiveRoots))
	}
	if err := next.Validate(); err != nil {
		return RootState{}, Rotation{}, err
	}
	return next, rot, nil
}

func parseRotation(doc map[string]any) (Rotation, error) {
	top, err := fields(doc, "format", "sequence", "previous_sha256", "add", "revoke")
	if err != nil {
		return Rotation{}, err
	}
	if f, err := str(top, "format"); err != nil || f != RotationFormat {
		return Rotation{}, fmt.Errorf("format must be %q", RotationFormat)
	}
	var r Rotation
	if r.Sequence, err = integer(top, "sequence", 1, MaxSequence); err != nil {
		return Rotation{}, err
	}
	if r.previous, err = sha256Hex(top, "previous_sha256"); err != nil {
		return Rotation{}, err
	}
	adds, err := array(top, "add", 0, MaxRotationEntries)
	if err != nil {
		return Rotation{}, err
	}
	revs, err := array(top, "revoke", 0, MaxRotationEntries)
	if err != nil {
		return Rotation{}, err
	}
	if len(adds) == 0 && len(revs) == 0 {
		return Rotation{}, fmt.Errorf("add or revoke must be nonempty")
	}
	var ids []string
	for i, v := range adds {
		o, err := fields(v, "id", "public_key")
		if err != nil {
			return Rotation{}, fmt.Errorf("add[%d]: %v", i, err)
		}
		id, err := str(o, "id")
		if err != nil || !ValidRootID(id) {
			return Rotation{}, fmt.Errorf("add[%d]: id must be root-<n>, at most 32 bytes", i)
		}
		pk, err := str(o, "public_key")
		if err != nil {
			return Rotation{}, fmt.Errorf("add[%d]: %v", i, err)
		}
		k, err := ParseRootKey(pk)
		if err != nil {
			return Rotation{}, fmt.Errorf("add[%d]: %v", i, err)
		}
		for _, prev := range r.Added {
			if bytes.Equal(prev.Key.Marshal(), k.Marshal()) {
				return Rotation{}, fmt.Errorf("add[%d]: duplicate key", i)
			}
		}
		ids = append(ids, id)
		r.Added = append(r.Added, Root{ID: id, Key: k})
	}
	if !sortedUnique(ids) {
		return Rotation{}, fmt.Errorf("add must be sorted by id without duplicates")
	}
	for i, v := range revs {
		id, ok := v.(string)
		if !ok || !ValidRootID(id) {
			return Rotation{}, fmt.Errorf("revoke[%d]: must be a root ID", i)
		}
		r.Revoked = append(r.Revoked, id)
	}
	if !sortedUnique(r.Revoked) {
		return Rotation{}, fmt.Errorf("revoke must be sorted without duplicates")
	}
	return r, nil
}

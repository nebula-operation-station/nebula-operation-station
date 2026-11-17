// SPDX-License-Identifier: AGPL-3.0-or-later

package registrymeta

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"strings"
)

// ErrNotComparable is returned by CompareTags when two tags cannot be compared
// at all: a digest reference, a floating tag such as latest, a date tag, or a
// tag without a numeric version. It is a refusal, never "no major change".
var ErrNotComparable = errors.New("registrymeta: tags not comparable")

// ErrVariantChange is returned by CompareTags when both tags are versions but
// their variant suffixes differ, for example 1.2.3-alpine to 1.2.3-slim. It is
// a refusal: a variant change is a different image, not an upgrade.
var ErrVariantChange = errors.New("registrymeta: variant change")

// TagComparison is the verdict for one tag change under a Policy.
type TagComparison struct {
	// PolicyVersion is the version of the policy that was applied
	// (DefaultPolicyVersion when the policy does not name one).
	PolicyVersion string
	// PolicyDigest is PolicyDigest of the policy that was applied.
	PolicyDigest string
	// MajorChange reports that the major numbers of the two tags differ, in
	// either direction.
	MajorChange bool
}

// policyDigestDomain separates the policy encoding from any other SHA-256
// input and carries the encoding's own version.
const policyDigestDomain = "nos.registrymeta.Policy/v1"

// CompareTags compares the old and new tag of one image under policy. It
// reuses the tag parser, the variant family and the policy checks of
// LatestStable; it is pure and never mutates its arguments.
//
// It returns an error wrapping ErrNotComparable when either tag is not a
// comparable version, and an error wrapping ErrVariantChange when both are
// versions with different variant suffixes. Both are refusals. An invalid
// policy returns an error wrapping ErrInvalidPolicy. On error the returned
// TagComparison is the zero value. Error messages name the rule, never the
// tag.
func CompareTags(oldTag, newTag string, policy Policy) (TagComparison, error) {
	if err := checkPolicy(policy); err != nil {
		return TagComparison{}, err
	}
	if _, err := compileAll(policy.Include, "include"); err != nil {
		return TagComparison{}, err
	}
	if _, err := compileAll(policy.Exclude, "exclude"); err != nil {
		return TagComparison{}, err
	}

	oldP := parseTag(oldTag)
	newP := parseTag(newTag)
	if rule, ok := notComparableRule(oldTag, oldP); ok {
		return TagComparison{}, fmt.Errorf("%w: %s", ErrNotComparable, rule)
	}
	if rule, ok := notComparableRule(newTag, newP); ok {
		return TagComparison{}, fmt.Errorf("%w: %s", ErrNotComparable, rule)
	}

	// familyOf reports ok for every kindVersion tag, so the family is the old
	// tag's variant suffix; the new tag must be in the same family.
	family, _ := familyOf(oldP, policy)
	if newP.variant != family {
		return TagComparison{}, fmt.Errorf("%w: the variant suffix differs", ErrVariantChange)
	}

	return TagComparison{
		PolicyVersion: policyVersion(policy),
		PolicyDigest:  PolicyDigest(policy),
		MajorChange:   oldP.major != newP.major,
	}, nil
}

// notComparableRule reports why a tag cannot take part in a comparison, as a
// fixed rule text. ok is false when the tag is a numeric version.
func notComparableRule(tag string, p parsedTag) (rule string, ok bool) {
	if p.kind == kindVersion {
		return "", false
	}
	switch {
	case p.kind == kindDate:
		return "date tags are not comparable with version tags", true
	case isDigest(strings.TrimSpace(tag)):
		return "digest references are not comparable", true
	case strings.EqualFold(strings.TrimSpace(tag), "latest"):
		return "floating tags are not comparable", true
	default:
		return "a tag without a numeric version is not comparable", true
	}
}

// PolicyDigest returns the lowercase hex SHA-256 of the canonical encoding of
// policy, so that a stored verdict names the exact policy it was made under.
// The encoding is field by field, in a fixed order, each field length-prefixed
// (big-endian uint64 for lengths, counts and integers; one byte for booleans),
// behind a domain separator. The version is the effective one, so the zero
// Policy and the same policy with DefaultPolicyVersion written out share one
// digest. Every other field change changes the digest.
func PolicyDigest(policy Policy) string {
	h := sha256.New()
	writeString(h, policyDigestDomain)
	writeString(h, policyVersion(policy))
	writeList(h, policy.Include)
	writeList(h, policy.Exclude)
	writeInt(h, int64(policy.MaxMajor))
	writeString(h, policy.ExplicitStable)
	writeBool(h, policy.AllowDates)
	return hex.EncodeToString(h.Sum(nil))
}

// writeString writes a length-prefixed string. hash.Hash writes never fail.
func writeString(h hash.Hash, s string) {
	writeInt(h, int64(len(s)))
	_, _ = h.Write([]byte(s))
}

// writeList writes the element count and then each element.
func writeList(h hash.Hash, items []string) {
	writeInt(h, int64(len(items)))
	for _, s := range items {
		writeString(h, s)
	}
}

// writeInt writes an integer as eight big-endian bytes.
func writeInt(h hash.Hash, n int64) {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(n))
	_, _ = h.Write(b[:])
}

// writeBool writes one byte: 1 for true, 0 for false.
func writeBool(h hash.Hash, v bool) {
	b := byte(0)
	if v {
		b = 1
	}
	_, _ = h.Write([]byte{b})
}

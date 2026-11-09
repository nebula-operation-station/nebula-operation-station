// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnfinding

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"hash"
)

// KeyDomainTag separates finding keys from every other hash NOS computes.
// A change of the encoding needs a new tag, never a silent change.
const KeyDomainTag = "nos-vuln-finding-v1"

// Key is the finding_key of ADR 0011 D2: the SHA-256 over the canonical
// tuple (subject_kind, subject_ref, ecosystem, source package or model,
// vuln_id). It is the idempotency key of the finding store.
type Key [sha256.Size]byte

// String returns the key as lower-case hex.
func (k Key) String() string { return hex.EncodeToString(k[:]) }

// encodeKey computes the key over already validated fields. Encoding: the
// domain tag, then each field in the order above, each written as a 4-byte
// big-endian byte length followed by its UTF-8 bytes. No separators, so no
// field content can move a field boundary.
//
// subjectRef is the encoded subject reference (see subjectRefBytes).
func encodeKey(subjectKind string, subjectRef []byte, ecosystem, pkg, vulnID string) Key {
	h := sha256.New()
	writeField(h, []byte(KeyDomainTag))
	writeField(h, []byte(subjectKind))
	writeField(h, subjectRef)
	writeField(h, []byte(ecosystem))
	writeField(h, []byte(pkg))
	writeField(h, []byte(vulnID))
	var k Key
	h.Sum(k[:0])
	return k
}

// subjectRefBytes encodes the subject reference as one key field. Hosts
// and devices use the inventory ID. Images use the host ID and the platform
// digest, each with its own 4-byte length prefix inside the field.
func subjectRefBytes(kind SubjectKind, ref SubjectRef) []byte {
	if kind != SubjectImage {
		return []byte(ref.ID)
	}
	out := make([]byte, 0, 8+len(ref.ID)+len(ref.ImageDigest))
	out = appendField(out, []byte(ref.ID))
	return appendField(out, []byte(ref.ImageDigest))
}

// keyOf computes the key of a validated record.
func keyOf(r *Record) Key {
	pkg := r.Component.SourcePackage
	if r.SubjectKind == SubjectDevice {
		pkg = r.Component.Model
	}
	return encodeKey(string(r.SubjectKind), subjectRefBytes(r.SubjectKind, r.SubjectRef), r.Ecosystem, pkg, r.Vuln.ID)
}

func writeField(h hash.Hash, b []byte) {
	var n [4]byte
	// Field lengths are bounded by validation far below 2^32.
	binary.BigEndian.PutUint32(n[:], uint32(len(b)))
	h.Write(n[:])
	h.Write(b)
}

func appendField(out, b []byte) []byte {
	out = binary.BigEndian.AppendUint32(out, uint32(len(b)))
	return append(out, b...)
}

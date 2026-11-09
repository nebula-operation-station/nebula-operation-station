// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnfinding

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

// TestKeyEncodingMatchesSpec rebuilds the canonical byte string by hand
// (ADR 0011 D2: domain tag, then subject_kind, subject_ref, ecosystem,
// source package, vuln_id, each with a 4-byte big-endian length prefix) and
// checks the key NOS computes is its SHA-256.
func TestKeyEncodingMatchesSpec(t *testing.T) {
	f, err := ParseRecord([]byte(validHostJSON))
	if err != nil {
		t.Fatalf("ParseRecord: %v", err)
	}
	enc := "\x00\x00\x00\x13nos-vuln-finding-v1" +
		"\x00\x00\x00\x04host" +
		"\x00\x00\x00\x05web01" +
		"\x00\x00\x00\x0fdebian:bookworm" +
		"\x00\x00\x00\x07openssl" +
		"\x00\x00\x00\x0eCVE-2024-12345"
	want := Key(sha256.Sum256([]byte(enc)))
	if f.Key != want {
		t.Fatalf("key = %s, want %s", f.Key, want)
	}
}

// TestKeyEncodingImageSubjectRef pins the nested encoding of the image
// subject reference (host ID and platform digest, each length-prefixed).
func TestKeyEncodingImageSubjectRef(t *testing.T) {
	f, err := ParseRecord([]byte(validImageJSON))
	if err != nil {
		t.Fatalf("ParseRecord: %v", err)
	}
	digest := "sha256:" + strings.Repeat("ab", 32)
	ref := "\x00\x00\x00\x06dock01" + "\x00\x00\x00\x47" + digest // 4+6+4+71 = 85 bytes
	enc := "\x00\x00\x00\x13nos-vuln-finding-v1" +
		"\x00\x00\x00\x05image" +
		"\x00\x00\x00\x55" + ref +
		"\x00\x00\x00\x0balpine:3.20" +
		"\x00\x00\x00\x04musl" +
		"\x00\x00\x00\x0dCVE-2025-1111"
	want := Key(sha256.Sum256([]byte(enc)))
	if f.Key != want {
		t.Fatalf("key = %s, want %s", f.Key, want)
	}
}

// Golden keys of the reference records, computed outside Go with printf and
// sha256sum over the hand-written encoding.
const (
	goldenHostKey   = "355ae62bf858227c68327851cf17d236cdc68db9da6409a07e5f398779f8d611"
	goldenImageKey  = "97fee8f43d553b9aa0d636db2dbc3c30b305b86271f3febb1b81e862d18b1e12"
	goldenDeviceKey = "791582dc40810f95f0d309a0e12e096d653a16af79e0b7445a65a2b806a07db9"
)

// TestKeyIsStable pins the key of the reference records as hex values. A
// change here breaks idempotency of every stored finding and needs a new
// domain tag, never an edited golden value.
func TestKeyIsStable(t *testing.T) {
	cases := []struct {
		name string
		json string
		want string
	}{
		{"host", validHostJSON, goldenHostKey},
		{"image", validImageJSON, goldenImageKey},
		{"device", validDeviceJSON, goldenDeviceKey},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for i := 0; i < 3; i++ {
				f, err := ParseRecord([]byte(tc.json))
				if err != nil {
					t.Fatalf("ParseRecord: %v", err)
				}
				if got := f.Key.String(); got != tc.want {
					t.Fatalf("key = %s, want %s", got, tc.want)
				}
			}
		})
	}
}

// TestKeyIgnoresNonKeyFields checks that values outside the canonical tuple
// (versions, aliases, fix, scores, evidence, assessment, JSON key order and
// whitespace) never change the key, so a finding upserts in place.
func TestKeyIgnoresNonKeyFields(t *testing.T) {
	base := mustParse(t, validHostJSON)
	variants := map[string]func(r *Record){
		"source version":  func(r *Record) { r.Component.SourceVersion = "3.0.16-1~deb12u1" },
		"binaries":        func(r *Record) { r.Component.Binaries = []Binary{{Name: "libssl3", Version: "3.0.16-1~deb12u1"}} },
		"aliases":         func(r *Record) { r.Vuln.Aliases = []string{"DSA-9999-1"} },
		"fix":             func(r *Record) { r.Fix = Fix{State: FixFixed, Version: "3.0.17-1~deb12u1"} },
		"scores":          func(r *Record) { r.Scores = Scores{} },
		"assessment":      func(r *Record) { r.Assessment = Assessment{Text: "other", ExploitPublic: true} },
		"matcher version": func(r *Record) { r.Evidence.MatcherVersion = "9.9.9" },
		"basis sources": func(r *Record) {
			r.Evidence.BasisSources = []BasisSource{{SourceID: "osv", SnapshotID: "snap-2", Integrity: IntegrityNone}}
		},
	}
	for name, mutate := range variants {
		t.Run(name, func(t *testing.T) {
			r := base.Record
			mutate(&r)
			f, err := Validate(r)
			if err != nil {
				t.Fatalf("Validate: %v", err)
			}
			if f.Key != base.Key {
				t.Fatalf("key changed: %s != %s", f.Key, base.Key)
			}
		})
	}
	reordered := mustParse(t, validHostJSONReordered)
	if reordered.Key != base.Key {
		t.Fatalf("reordered JSON changed the key")
	}
}

// TestKeyChangesWithEachKeyField checks that every field of the canonical
// tuple contributes to the key.
func TestKeyChangesWithEachKeyField(t *testing.T) {
	base := mustParse(t, validHostJSON)
	variants := map[string]func(r *Record){
		"subject kind": func(r *Record) {
			r.SubjectKind = SubjectImage
			r.SubjectRef.ImageDigest = "sha256:" + strings.Repeat("0", 64)
		},
		"subject ref":    func(r *Record) { r.SubjectRef.ID = "web02" },
		"ecosystem":      func(r *Record) { r.Ecosystem = "debian:trixie" },
		"source package": func(r *Record) { r.Component.SourcePackage = "openssl3" },
		"vuln id":        func(r *Record) { r.Vuln.ID = "CVE-2024-12346" },
	}
	seen := map[Key]string{base.Key: "base"}
	for name, mutate := range variants {
		t.Run(name, func(t *testing.T) {
			r := base.Record
			mutate(&r)
			f, err := Validate(r)
			if err != nil {
				t.Fatalf("Validate: %v", err)
			}
			if prev, dup := seen[f.Key]; dup {
				t.Fatalf("key equals the one of %s", prev)
			}
			seen[f.Key] = name
		})
	}
}

// TestKeyFieldBoundariesAreUnambiguous checks that moving bytes between
// adjacent fields yields a different key (no separator ambiguity).
func TestKeyFieldBoundariesAreUnambiguous(t *testing.T) {
	a := encodeKey("host", []byte("ab"), "c", "pkg", "ID-1")
	b := encodeKey("host", []byte("a"), "bc", "pkg", "ID-1")
	if a == b {
		t.Fatalf("shifted field boundary produced the same key")
	}
	c := encodeKey("host", []byte("x"), "y", "pkg", "ID-1")
	d := encodeKey("hostx", []byte(""), "y", "pkg", "ID-1")
	if c == d {
		t.Fatalf("shifted field boundary produced the same key")
	}
}

// TestKeyCanonicalisesCVECase checks that CVE IDs in another letter case map
// to the same finding.
func TestKeyCanonicalisesCVECase(t *testing.T) {
	base := mustParse(t, validHostJSON)
	r := base.Record
	r.Vuln.ID = "cve-2024-12345"
	f, err := Validate(r)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if f.Key != base.Key || f.Record.Vuln.ID != "CVE-2024-12345" {
		t.Fatalf("lower-case CVE not canonicalised: id %q", f.Record.Vuln.ID)
	}
}

func TestKeyStringIsLowerHex(t *testing.T) {
	f := mustParse(t, validHostJSON)
	s := f.Key.String()
	if len(s) != 64 || strings.ToLower(s) != s {
		t.Fatalf("key string %q", s)
	}
	if _, err := hex.DecodeString(s); err != nil {
		t.Fatalf("key string not hex: %v", err)
	}
}

func mustParse(t *testing.T, s string) Finding {
	t.Helper()
	f, err := ParseRecord([]byte(s))
	if err != nil {
		t.Fatalf("ParseRecord: %v", err)
	}
	return f
}

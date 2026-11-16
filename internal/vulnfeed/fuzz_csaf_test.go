// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnfeed

import (
	"bytes"
	"encoding/hex"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// fuzzPinnedKeyBlock returns one armored public key block holding n
// throw-away EdDSA keys. Keys are generated at test time; no key material
// is committed.
func fuzzPinnedKeyBlock(tb testing.TB, n int) []byte {
	tb.Helper()
	var buf bytes.Buffer
	w, err := armor.Encode(&buf, openpgp.PublicKeyType, nil)
	if err != nil {
		tb.Fatal(err)
	}
	for i := 0; i < n; i++ {
		ent, err := openpgp.NewEntity("CSAF fuzz seed", "", "csaf-fuzz@example.invalid", &packet.Config{
			Algorithm: packet.PubKeyAlgoEdDSA,
			Time:      func() time.Time { return csafNow.Add(-time.Hour) },
		})
		if err != nil {
			tb.Fatal(err)
		}
		if err := ent.Serialize(w); err != nil {
			tb.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		tb.Fatal(err)
	}
	return buf.Bytes()
}

// checkCSAFAdvisoryBounds asserts the documented limits and the text rules
// of an accepted advisory.
func checkCSAFAdvisoryBounds(t *testing.T, adv CSAFAdvisory) {
	t.Helper()
	if n := len(adv.Products); n > MaxCSAFProducts {
		t.Fatalf("%d products, limit %d", n, MaxCSAFProducts)
	}
	if n := len(adv.Vulnerabilities); n > MaxCSAFVulnerabilities {
		t.Fatalf("%d vulnerabilities, limit %d", n, MaxCSAFVulnerabilities)
	}
	texts := []string{adv.TrackingID, adv.Version, adv.Title}
	for _, v := range adv.Vulnerabilities {
		for _, refs := range [][]string{v.Affected, v.Fixed, v.NotAffected} {
			if n := len(refs); n > MaxCSAFProductRefs {
				t.Fatalf("%d product refs, limit %d", n, MaxCSAFProductRefs)
			}
		}
		texts = append(texts, v.CVE)
	}
	for _, p := range adv.Products {
		texts = append(texts, p.ProductID, p.Name, p.Vendor, p.Product, p.Version, p.VersionRange, p.Train, p.Ecosystem)
	}
	for _, s := range texts {
		if len(s) > MaxCSAFTextBytes {
			t.Fatalf("text of %d bytes, limit %d", len(s), MaxCSAFTextBytes)
		}
		if !utf8.ValidString(s) {
			t.Fatalf("invalid UTF-8 in accepted advisory: %q", s)
		}
	}
}

// FuzzParseCSAFAdvisory: no panic, limits and text rules hold for accepted
// documents, and parsing is deterministic.
func FuzzParseCSAFAdvisory(f *testing.F) {
	f.Add(readFixture(f, "csaf", "cisco-sa-test-ios-2026.json"))
	f.Add(readFixture(f, "csaf", "pan-sa-2026-0001.json"))
	f.Add([]byte(`{"document":{"category":"csaf_security_advisory","csaf_version":"2.0","title":"t","tracking":{"id":"x-1","version":"1","status":"final","current_release_date":"2026-11-11T00:00:00Z"}},"product_tree":{}}`))
	f.Add([]byte(`{"document":{"category":"csaf_security_advisory","csaf_version":"2.0","title":"Test \xff","tracking":{"id":"x-1","version":"1","status":"final","current_release_date":"2026-11-11T00:00:00Z"}},"product_tree":{}}`))
	f.Add([]byte(`{"document":{"csaf_version":"2.0","title":"t","tracking":{"id":"x-1","version":"1.0.0-rc.1","status":"interim","current_release_date":"2026-11-11T00:00:00Z"}},"product_tree":{"full_product_names":[{"product_id":"P","name":"p"}]},"vulnerabilities":[{"cve":"CVE-2026-20001","product_status":{"fixed":["P"]}}]}`))
	f.Fuzz(func(t *testing.T, doc []byte) {
		for _, vendor := range []CSAFVendor{CSAFVendorCisco, CSAFVendorPaloAlto} {
			adv, err := ParseCSAFAdvisory(doc, vendor)
			again, err2 := ParseCSAFAdvisory(doc, vendor)
			if (err == nil) != (err2 == nil) || (err != nil && err.Error() != err2.Error()) {
				t.Fatalf("%s: nondeterministic error: %v vs %v", vendor, err, err2)
			}
			if err != nil {
				if !errors.Is(err, ErrCSAFMalformed) {
					t.Fatalf("%s: unexpected error class: %v", vendor, err)
				}
				continue
			}
			checkCSAFAdvisoryBounds(t, adv)
			if !reflect.DeepEqual(adv, again) {
				t.Fatalf("%s: nondeterministic result", vendor)
			}
		}
	})
}

// FuzzCompareCSAFVersion: without error the comparison is reflexive and
// antisymmetric, and validity does not depend on the argument order.
func FuzzCompareCSAFVersion(f *testing.F) {
	for _, s := range [][2]string{
		{"1", "1"}, {"2", "10"}, {"10", "9"}, {"1.9.0", "1.10.0"},
		{"1.0.0-alpha", "1.0.0"}, {"1.0.0-alpha.1", "1.0.0-alpha.beta"},
		{"1.0.0-2", "1.0.0-10"}, {"1.0.0+build1", "1.0.0+build2"},
		{"1", "1.0.0"}, {"01", "1"}, {"", "1"}, {"1.0", "1.0.0"},
	} {
		f.Add(s[0], s[1])
	}
	f.Fuzz(func(t *testing.T, a, b string) {
		ab, errAB := compareCSAFVersion(a, b)
		ba, errBA := compareCSAFVersion(b, a)
		if (errAB == nil) != (errBA == nil) {
			t.Fatalf("validity depends on order: %q,%q: %v / %v", a, b, errAB, errBA)
		}
		if errAB != nil {
			if !errors.Is(errAB, ErrCSAFMalformed) {
				t.Fatalf("unexpected error class: %v", errAB)
			}
			return
		}
		aa, errAA := compareCSAFVersion(a, a)
		if errAA != nil || aa != 0 {
			t.Fatalf("compare(%q,%q) = %d, %v; want 0, nil", a, a, aa, errAA)
		}
		if ab != -ba {
			t.Fatalf("compare(%q,%q) = %d but compare(%q,%q) = %d", a, b, ab, b, a, ba)
		}
	})
}

// FuzzParseChecksum: a digest is returned only for sha256 (32 bytes) and
// sha512 (64 bytes), and it is the hex decoding of the first field.
func FuzzParseChecksum(f *testing.F) {
	const name = "feed.json"
	f.Add([]byte(strings.Repeat("ab", 32)+"  "+name+"\n"), name)
	f.Add([]byte(strings.Repeat("0f", 32)+" *"+name+"\n"), name)
	f.Add([]byte(strings.Repeat("ab", 64)+"  "+name+"\n"), name)
	f.Add([]byte(strings.Repeat("ab", 16)+"\n"), name)
	f.Add([]byte("zz"+strings.Repeat("ab", 31)+"\n"), name)
	f.Fuzz(func(t *testing.T, in []byte, want string) {
		fields := strings.Fields(string(in))
		for _, alg := range []ChecksumAlg{ChecksumSHA256, ChecksumSHA512, "md5", ""} {
			got, err := parseChecksum(in, alg, want)
			if err != nil {
				if !errors.Is(err, ErrChecksumMalformed) {
					t.Fatalf("%q: unexpected error class: %v", alg, err)
				}
				continue
			}
			size := map[ChecksumAlg]int{ChecksumSHA256: 32, ChecksumSHA512: 64}[alg]
			if size == 0 {
				t.Fatalf("digest accepted for unknown algorithm %q", alg)
			}
			if len(got) != size {
				t.Fatalf("%s: digest of %d bytes, want %d", alg, len(got), size)
			}
			exp, err := hex.DecodeString(fields[0])
			if err != nil || !bytes.Equal(exp, got) {
				t.Fatalf("%s: digest %x is not the first field %q", alg, got, fields[0])
			}
		}
	})
}

// FuzzParseCSAFKeyring: no panic on untrusted configuration bytes; accepted
// keyrings hold between one and MaxCSAFPinnedKeys keys.
func FuzzParseCSAFKeyring(f *testing.F) {
	f.Add(fuzzPinnedKeyBlock(f, 1))
	f.Add(fuzzPinnedKeyBlock(f, 2))
	f.Add([]byte("-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nAAAA\n-----END PGP PUBLIC KEY BLOCK-----\n"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, in []byte) {
		kr, err := ParseCSAFKeyring(in)
		if err != nil {
			if !errors.Is(err, ErrCSAFKeyring) {
				t.Fatalf("unexpected error class: %v", err)
			}
			return
		}
		if n := len(kr.Fingerprints()); n < 1 || n > MaxCSAFPinnedKeys {
			t.Fatalf("%d pinned keys, limit %d", n, MaxCSAFPinnedKeys)
		}
	})
}

// TestParseCSAFKeyringKeyCountLimit: a single block may not carry more than
// MaxCSAFPinnedKeys keys (the limit is on keys, not on blocks).
func TestParseCSAFKeyringKeyCountLimit(t *testing.T) {
	if _, err := ParseCSAFKeyring(fuzzPinnedKeyBlock(t, MaxCSAFPinnedKeys)); err != nil {
		t.Fatalf("%d keys in one block: %v", MaxCSAFPinnedKeys, err)
	}
	if _, err := ParseCSAFKeyring(fuzzPinnedKeyBlock(t, MaxCSAFPinnedKeys+1)); !errors.Is(err, ErrCSAFKeyring) {
		t.Fatalf("%d keys in one block: err = %v, want ErrCSAFKeyring", MaxCSAFPinnedKeys+1, err)
	}
}

// TestParseChecksumUnknownAlgorithmRejected: a digest is never accepted for
// an algorithm the feed table does not know.
func TestParseChecksumUnknownAlgorithmRejected(t *testing.T) {
	const name = "feed.json"
	in := []byte(strings.Repeat("ab", 32) + "  " + name + "\n")
	if _, err := parseChecksum(in, "md5", name); !errors.Is(err, ErrChecksumMalformed) {
		t.Fatalf("unknown algorithm: err = %v, want ErrChecksumMalformed", err)
	}
}

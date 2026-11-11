// SPDX-License-Identifier: AGPL-3.0-or-later

package pairing

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math/big"
	"strings"
	"testing"
)

// testKeyBlob returns the SSH wire format of a deterministic ed25519 key.
func testKeyBlob(t testing.TB, seedTag string) []byte {
	t.Helper()
	seed := sha256.Sum256([]byte(seedTag))
	pub := ed25519.NewKeyFromSeed(seed[:]).Public().(ed25519.PublicKey)
	return wireBlob("ssh-ed25519", pub)
}

func wireBlob(algo string, key []byte) []byte {
	var b []byte
	b = binary.BigEndian.AppendUint32(b, uint32(len(algo)))
	b = append(b, algo...)
	b = binary.BigEndian.AppendUint32(b, uint32(len(key)))
	return append(b, key...)
}

func testSalt(tag string) []byte {
	s := sha256.Sum256([]byte(tag))
	return s[:]
}

// referenceCode computes the code independently of the package with
// math/big over the full 120-bit value, as written in ADR 0013 D3.
func referenceCode(salt, blob []byte) string {
	h := sha256.New()
	h.Write([]byte("nos-enroll-pair-v1"))
	h.Write([]byte{0})
	h.Write(salt)
	h.Write(blob)
	d := h.Sum(nil)
	v := new(big.Int).SetBytes(d[:15])
	const data = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	const check = data + "*~$=U"
	out := make([]byte, 0, 29)
	for i := 0; i < 24; i++ {
		shift := uint(115 - 5*i)
		g := new(big.Int).Rsh(v, shift)
		out = append(out, data[g.Uint64()&31])
	}
	m := new(big.Int).Mod(v, big.NewInt(37))
	out = append(out, check[m.Uint64()])
	var sb strings.Builder
	for i, c := range out {
		if i > 0 && i%5 == 0 {
			sb.WriteByte('-')
		}
		sb.WriteByte(c)
	}
	return sb.String()
}

func TestTwoToTheSixtyModThirtySevenIsTen(t *testing.T) {
	m := new(big.Int).Mod(new(big.Int).Lsh(big.NewInt(1), 60), big.NewInt(37))
	if m.Int64() != 10 {
		t.Fatalf("2^60 mod 37 = %d, want 10", m.Int64())
	}
}

func TestComputeMatchesReference(t *testing.T) {
	for i := 0; i < 200; i++ {
		tag := string(rune('a'+i%26)) + strings.Repeat("x", i)
		salt := testSalt("salt-" + tag)
		blob := testKeyBlob(t, "key-"+tag)
		c, err := Compute(salt, blob)
		if err != nil {
			t.Fatalf("Compute: %v", err)
		}
		if got, want := c.String(), referenceCode(salt, blob); got != want {
			t.Fatalf("vector %d: got %s, want %s", i, got, want)
		}
	}
}

func TestCodeFormat(t *testing.T) {
	c, err := Compute(testSalt("s"), testKeyBlob(t, "k"))
	if err != nil {
		t.Fatal(err)
	}
	s := c.String()
	if len(s) != 29 {
		t.Fatalf("len %d, want 29: %q", len(s), s)
	}
	for i, ch := range s {
		isSep := i%6 == 5
		if isSep != (ch == '-') {
			t.Fatalf("separator at wrong place in %q", s)
		}
	}
	if strings.ContainsAny(s[:28], "*~$=U") {
		t.Fatalf("check-only symbol in data part: %q", s)
	}
}

func TestComputeRejectsBadSalt(t *testing.T) {
	blob := testKeyBlob(t, "k")
	for _, n := range []int{0, 16, 31, 33, 64} {
		_, err := Compute(make([]byte, n), blob)
		if !errors.Is(err, ErrSaltSize) {
			t.Errorf("salt len %d: err = %v, want ErrSaltSize", n, err)
		}
	}
}

func TestComputeRejectsNonEd25519Keys(t *testing.T) {
	good := testKeyBlob(t, "k")
	key := good[19:]
	cases := map[string][]byte{
		"empty":              nil,
		"rsa":                wireBlob("ssh-rsa", bytes.Repeat([]byte{1}, 32)),
		"ecdsa":              wireBlob("ecdsa-sha2-nistp256", bytes.Repeat([]byte{1}, 32)),
		"sk-ed25519":         wireBlob("sk-ssh-ed25519@openssh.com", key),
		"short key":          wireBlob("ssh-ed25519", key[:31]),
		"long key":           wireBlob("ssh-ed25519", append(append([]byte{}, key...), 0)),
		"trailing bytes":     append(append([]byte{}, good...), 0),
		"truncated":          good[:len(good)-1],
		"algo length lies":   append([]byte{0, 0, 0, 12}, good[4:]...),
		"key length lies":    append(append(append([]byte{}, good[:15]...), 0, 0, 0, 33), key...),
		"raw key no wire":    key,
		"uppercase algo":     wireBlob("SSH-ED25519", key),
		"huge length prefix": append([]byte{0xff, 0xff, 0xff, 0xff}, good[4:]...),
	}
	for name, blob := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Compute(testSalt("s"), blob)
			if !errors.Is(err, ErrNotEd25519) {
				t.Fatalf("err = %v, want ErrNotEd25519", err)
			}
		})
	}
}

func TestParseRoundTrip(t *testing.T) {
	c, err := Compute(testSalt("s"), testKeyBlob(t, "k"))
	if err != nil {
		t.Fatal(err)
	}
	s := c.String()
	plain := strings.ReplaceAll(s, "-", "")
	variants := []string{
		s,
		strings.ToLower(s),
		plain,
		strings.ToLower(plain),
		" " + strings.ReplaceAll(s, "-", " ") + " ",
		strings.Join(strings.Split(plain, ""), "-"),
		"--" + plain[:3] + " - " + plain[3:] + "--",
	}
	for _, v := range variants {
		got, err := Parse(v)
		if err != nil {
			t.Fatalf("Parse(%q): %v", v, err)
		}
		if !Equal(got, c) {
			t.Fatalf("Parse(%q) = %s, want %s", v, got, c)
		}
	}
}

// validCode builds a valid canonical 25-character code (no separators)
// from 24 data characters by appending the right check character.
func validCode(t *testing.T, data string) string {
	t.Helper()
	if len(data) != 24 {
		t.Fatalf("data len %d", len(data))
	}
	var hi, lo uint64
	for i := 0; i < 24; i++ {
		v := uint64(strings.IndexByte(dataAlphabet, data[i]))
		if i < 12 {
			hi = hi<<5 | v
		} else {
			lo = lo<<5 | v
		}
	}
	return data + string(checkAlphabet[checkValue(hi, lo)])
}

func TestParseFolding(t *testing.T) {
	canon := validCode(t, "0123456789ABCDEFGHJKMNPQ")
	want, err := Parse(canon)
	if err != nil {
		t.Fatalf("Parse(%q): %v", canon, err)
	}
	folded := []string{
		"O123456789ABCDEFGHJKMNPQ" + canon[24:],
		"o123456789abcdefghjkmnpq" + strings.ToLower(canon[24:]),
		"0I23456789ABCDEFGHJKMNPQ" + canon[24:],
		"0i23456789ABCDEFGHJKMNPQ" + canon[24:],
		"0L23456789ABCDEFGHJKMNPQ" + canon[24:],
		"0l23456789ABCDEFGHJKMNPQ" + canon[24:],
	}
	for _, in := range folded {
		got, err := Parse(in)
		if err != nil {
			t.Fatalf("Parse(%q): %v", in, err)
		}
		if !Equal(got, want) {
			t.Fatalf("Parse(%q) = %s, want %s", in, got, want)
		}
	}
}

func TestParseFoldsCheckCharacter(t *testing.T) {
	// Find data whose check value is 0, 1 or the check-only 'U' (36) and
	// verify the folded and lower-case forms of the check character parse.
	found := map[byte]bool{}
	for i := 0; i < 5000 && len(found) < 3; i++ {
		c, err := Compute(testSalt("fold"+strings.Repeat("y", i)), testKeyBlob(t, "k"))
		if err != nil {
			t.Fatal(err)
		}
		s := strings.ReplaceAll(c.String(), "-", "")
		var alts []string
		switch s[24] {
		case '0':
			alts = []string{"O", "o"}
		case '1':
			alts = []string{"I", "i", "L", "l"}
		case 'U':
			alts = []string{"u"}
		default:
			continue
		}
		found[s[24]] = true
		for _, a := range alts {
			got, err := Parse(s[:24] + a)
			if err != nil {
				t.Fatalf("Parse(%q): %v", s[:24]+a, err)
			}
			if !Equal(got, c) {
				t.Fatalf("Parse(%q) = %s, want %s", s[:24]+a, got, c)
			}
		}
	}
	if len(found) != 3 {
		t.Fatalf("did not find all check characters to test: %v", found)
	}
}

func TestParseRejectsMalformed(t *testing.T) {
	good := validCode(t, "0123456789ABCDEFGHJKMNPQ")
	// A check character that is wrong for good.
	wrongCheck := string(checkAlphabet[(strings.IndexByte(checkAlphabet, good[24])+1)%37])
	cases := []struct {
		name string
		in   string
		kind MalformedKind
	}{
		{"empty", "", KindLength},
		{"only separators", "----- -----", KindLength},
		{"24 chars", good[:24], KindLength},
		{"26 chars", good + "0", KindLength},
		{"30 chars", good + "00000", KindLength},
		{"overlong input", strings.Repeat("-", MaxInputLen+1), KindLength},
		{"overlong but valid after separators", strings.Repeat(" ", MaxInputLen) + good, KindLength},
		{"wrong check", good[:24] + wrongCheck, KindCheck},
		{"swapped data chars", good[1:2] + good[0:1] + good[2:], KindCheck},
		{"one data char changed", "1" + good[1:], KindCheck},
		{"U in data", "U" + good[1:], KindAlphabet},
		{"u in data", "u" + good[1:], KindAlphabet},
		{"* in data", good[:5] + "*" + good[6:], KindAlphabet},
		{"~ in data", good[:23] + "~" + good[24:], KindAlphabet},
		{"$ in data", good[:12] + "$" + good[13:], KindAlphabet},
		{"= in data", "=" + good[1:], KindAlphabet},
		{"underscore", good[:24] + "_", KindAlphabet},
		{"tab separator", good[:5] + "\t" + good[5:], KindAlphabet},
		{"newline", good + "\n", KindAlphabet},
		{"dot", good[:5] + "." + good[5:], KindAlphabet},
		{"non-ASCII", "Ö" + good[1:], KindAlphabet},
		{"invalid UTF-8", "\xff" + good[1:], KindAlphabet},
		{"NUL", good[:24] + "\x00", KindAlphabet},
		{"fullwidth digit", "０" + good[1:], KindAlphabet},
		{"bad check symbol", good[:24] + "#", KindAlphabet},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse(tc.in)
			if !errors.Is(err, ErrMalformed) {
				t.Fatalf("Parse(%q) err = %v, want ErrMalformed", tc.in, err)
			}
			var me *MalformedError
			if !errors.As(err, &me) {
				t.Fatalf("err %v is not *MalformedError", err)
			}
			if me.Kind != tc.kind {
				t.Fatalf("kind = %v, want %v (%v)", me.Kind, tc.kind, err)
			}
			if tc.in != "" && len(tc.in) > 3 && strings.Contains(err.Error(), tc.in) {
				t.Fatalf("error echoes input: %v", err)
			}
		})
	}
}

func TestEqual(t *testing.T) {
	a, err := Compute(testSalt("s"), testKeyBlob(t, "k"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := Parse(strings.ToLower(a.String()))
	if err != nil {
		t.Fatal(err)
	}
	other, err := Compute(testSalt("s2"), testKeyBlob(t, "k"))
	if err != nil {
		t.Fatal(err)
	}
	if !Equal(a, b) {
		t.Fatal("equal codes compare unequal")
	}
	if Equal(a, other) {
		t.Fatal("different codes compare equal")
	}
	var zero Code
	if Equal(zero, zero) {
		t.Fatal("zero codes must never compare equal")
	}
	if Equal(a, zero) || Equal(zero, a) {
		t.Fatal("zero code compares equal to a valid code")
	}
	if zero.String() != "" {
		t.Fatalf("zero code String = %q, want empty", zero.String())
	}
}

func TestComputeDoesNotModifyInputs(t *testing.T) {
	salt := testSalt("s")
	blob := testKeyBlob(t, "k")
	s0, b0 := append([]byte{}, salt...), append([]byte{}, blob...)
	if _, err := Compute(salt, blob); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(salt, s0) || !bytes.Equal(blob, b0) {
		t.Fatal("Compute modified its inputs")
	}
}

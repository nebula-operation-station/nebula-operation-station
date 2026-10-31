// SPDX-License-Identifier: AGPL-3.0-or-later

package release

import (
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestCompiledAnchors(t *testing.T) {
	a, err := Anchors()
	if err != nil {
		t.Fatal(err)
	}
	if len(a) != 2 || a[0].ID != "root-1" || a[0].Key == nil || a[1].ID != "root-2" || a[1].Key != nil {
		t.Fatalf("anchors = %+v", a)
	}
	if got := (Root{Key: a[0].Key}).Fingerprint(); got != "SHA256:DMcoE6ngofND0L6+vT1OIPrvzDFSRmBNDPrR3hpy1MY" {
		t.Fatalf("root-1 fingerprint %s", got)
	}
	s, err := Bootstrap(a)
	if err != nil {
		t.Fatal(err)
	}
	// The empty root-2 placeholder never becomes a trusted root.
	if act := s.Active(); len(act) != 1 || act[0].ID != "root-1" || s.Sequence != 0 || s.Digest != ZeroDigest {
		t.Fatalf("bootstrap state %+v", s)
	}
}

func TestParseAnchorsRejects(t *testing.T) {
	k := newTestSK(t)
	line := "root-1 " + FormatRootKey(k.pub) + " comment\n"
	for name, raw := range map[string]string{
		"empty":         "",
		"only comments": "# x\n",
		"only empty":    "root-2 -\n",
		"bad id":        "root-01 " + FormatRootKey(k.pub) + "\n",
		"dup id":        line + "root-1 -\n",
		"dup key":       line + "root-3 " + FormatRootKey(k.pub) + "\n",
		"crlf":          strings.ReplaceAll(line, "\n", "\r\n"),
		"plain ed25519": "root-1 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\n",
		"missing key":   "root-1 sk-ssh-ed25519@openssh.com\n",
	} {
		if _, err := ParseAnchors([]byte(raw)); !errors.Is(err, ErrFormat) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	if a, err := ParseAnchors([]byte(line + "root-2 -\n")); err != nil || len(a) != 2 {
		t.Fatalf("valid anchors: %v", err)
	}
}

func TestParseRootKey(t *testing.T) {
	k := newTestSK(t)
	good := FormatRootKey(k.pub)
	if got, err := ParseRootKey(good); err != nil || string(got.Marshal()) != string(k.pub.Marshal()) {
		t.Fatalf("valid key: %v", err)
	}
	plain, _ := ssh.NewPublicKey(k.priv.Public())
	b64 := strings.TrimPrefix(good, ssh.KeyAlgoSKED25519+" ")
	for name, s := range map[string]string{
		"comment":          good + " root",
		"newline":          good + "\n",
		"unpadded":         ssh.KeyAlgoSKED25519 + " " + strings.TrimRight(b64, "="),
		"type mismatch":    "ssh-ed25519 " + b64,
		"plain key":        "ssh-ed25519 " + strings.TrimPrefix(FormatRootKey(plain), "ssh-ed25519 "),
		"plain blob as sk": ssh.KeyAlgoSKED25519 + " " + strings.TrimPrefix(FormatRootKey(plain), "ssh-ed25519 "),
		"wrong app":        FormatRootKey(newTestSKApp(t, "ssh:other").pub),
		"too long":         good + strings.Repeat("A", MaxPublicKey),
		"empty":            "",
	} {
		if _, err := ParseRootKey(s); !errors.Is(err, ErrFormat) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func TestVerifyManifest(t *testing.T) {
	k := newTestSK(t)
	man, _ := defaultRelease(t)
	raw := canon(t, man)
	m, err := VerifyManifest([]Root{k.root("root-1")}, raw, k.sign(t, raw))
	if err != nil {
		t.Fatal(err)
	}
	if m.ReleaseVersion != "1.4.0" || len(m.Modules) != 2 || m.Modules[1].Name != "os-debian" || m.Bundle().Name != BundleArtifact ||
		m.Digest != hexSum(raw) || m.SignedBy.ID != "root-1" {
		t.Fatalf("manifest = %+v", m)
	}
}

func TestVerifyManifestRejectsSignatures(t *testing.T) {
	k := newTestSK(t)
	other := newTestSK(t)
	man, _ := defaultRelease(t)
	raw := canon(t, man)
	roots := []Root{k.root("root-1")}
	_, plainPriv, _ := genPlain(t)
	for name, tc := range map[string]struct {
		roots []Root
		sig   []byte
		want  error
	}{
		"untrusted key":          {roots, other.sign(t, raw), ErrUntrusted},
		"empty placeholder only": {[]Root{{ID: "root-2"}}, k.sign(t, raw), ErrUntrusted},
		"no roots":               {nil, k.sign(t, raw), ErrUntrusted},
		"wrong namespace":        {roots, k.signNS(t, "nebula-module", 1, raw), ErrSignature},
		"no user presence":       {roots, k.signNS(t, Namespace, 0, raw), ErrSignature},
		"other document":         {roots, k.sign(t, append([]byte{}, raw[:len(raw)-1]...)), ErrSignature},
		"plain ed25519 signer":   {roots, plainSign(t, plainPriv, raw), ErrUntrusted},
		"garbage":                {roots, []byte("x"), ErrFormat},
		"oversized":              {roots, []byte(strings.Repeat("A", MaxSignature+1)), ErrFormat},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := VerifyManifest(tc.roots, raw, tc.sig); !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestParseManifestRejects(t *testing.T) {
	type mut func(m map[string]any)
	mod := func(i int) func(m map[string]any) map[string]any {
		return func(m map[string]any) map[string]any { return m["modules"].([]any)[i].(map[string]any) }
	}
	art := func(m map[string]any) map[string]any { return m["artifacts"].([]any)[0].(map[string]any) }
	cases := map[string]mut{
		"format":           func(m map[string]any) { m["format"] = RotationFormat },
		"unknown field":    func(m map[string]any) { m["extra"] = 1 },
		"missing field":    func(m map[string]any) { delete(m, "release_version") },
		"leading v":        func(m map[string]any) { m["release_version"] = "v1.4.0" },
		"semver two parts": func(m map[string]any) { m["release_version"] = "1.4" },
		"semver leading 0": func(m map[string]any) { m["release_version"] = "01.4.0" },
		"semver big":       func(m map[string]any) { m["release_version"] = "1000000.0.0" },
		"semver pre 0lead": func(m map[string]any) { m["release_version"] = "1.4.0-rc.01" },
		"semver empty pre": func(m map[string]any) { m["release_version"] = "1.4.0-" },
		"semver too long":  func(m map[string]any) { m["release_version"] = "1.4.0-" + strings.Repeat("a", 60) },
		"no modules":       func(m map[string]any) { m["modules"] = []any{} },
		"no bundle":        func(m map[string]any) { art(m)["name"] = "aaa.tar" },
		"two bundles": func(m map[string]any) {
			m["artifacts"] = append([]any{map[string]any{"name": BundleArtifact, "size": 1, "sha256": hexSum(nil)}}, m["artifacts"].([]any)...)
		},
		"artifact slash":  func(m map[string]any) { art(m)["name"] = "a/b" },
		"artifact dotdot": func(m map[string]any) { art(m)["name"] = ".." },
		"artifact url":    func(m map[string]any) { art(m)["name"] = "https://x" },
		"size zero":       func(m map[string]any) { art(m)["size"] = 0 },
		"size float":      func(m map[string]any) { art(m)["size"] = 1.5 },
		"size string":     func(m map[string]any) { art(m)["size"] = "1" },
		"artifact too big": func(m map[string]any) {
			m["artifacts"].([]any)[1].(map[string]any)["size"] = int64(MaxArtifactSize) + 1
		},
		"bundle too big":    func(m map[string]any) { art(m)["size"] = MaxBundle + 1 },
		"sha upper":         func(m map[string]any) { art(m)["sha256"] = strings.ToUpper(hexSum(nil)) },
		"sha short":         func(m map[string]any) { art(m)["sha256"] = "abc" },
		"modules unsorted":  func(m map[string]any) { a := m["modules"].([]any); a[0], a[1] = a[1], a[0] },
		"module dup":        func(m map[string]any) { a := m["modules"].([]any); m["modules"] = []any{a[0], a[0]} },
		"module name":       func(m map[string]any) { mod(0)(m)["name"] = "Docker" },
		"module version":    func(m map[string]any) { mod(0)(m)["version"] = "1.2.0-rc1" },
		"module version 0s": func(m map[string]any) { mod(0)(m)["version"] = "1.02.0" },
		"module tar big":    func(m map[string]any) { mod(0)(m)["size"] = MaxModuleTar + 1 },
		"module extra":      func(m map[string]any) { mod(0)(m)["path"] = "x" },
		"null":              func(m map[string]any) { mod(0)(m)["sha256"] = nil },
	}
	for name, f := range cases {
		t.Run(name, func(t *testing.T) {
			man, _ := defaultRelease(t)
			f(man)
			if _, err := ParseManifest(canon(t, man)); !errors.Is(err, ErrFormat) {
				t.Fatalf("err = %v", err)
			}
		})
	}
}

func TestParseManifestRejectsNoncanonicalBytes(t *testing.T) {
	man, _ := defaultRelease(t)
	raw := canon(t, man)
	for name, b := range map[string][]byte{
		"trailing newline": append(append([]byte{}, raw...), '\n'),
		"leading space":    append([]byte(" "), raw...),
		"bom":              append([]byte{0xEF, 0xBB, 0xBF}, raw...),
		"reordered":        []byte(strings.Replace(string(raw), `{"artifacts"`, `{"format":"x","artifacts"`, 1)),
		"duplicate key":    []byte(strings.Replace(string(raw), `{"artifacts"`, `{"artifacts":[],"artifacts"`, 1)),
		"escaped char":     []byte(strings.Replace(string(raw), `"1.4.0"`, `"1.4.\u0030"`, 1)),
		"invalid utf8":     []byte(strings.Replace(string(raw), `"1.4.0"`, "\"1.4.0\xff\"", 1)),
		"array top":        []byte(`[]`),
		"trailing data":    append(append([]byte{}, raw...), []byte(`{}`)...),
		"too large":        append(raw, make([]byte, MaxManifest)...),
	} {
		if _, err := ParseManifest(b); !errors.Is(err, ErrFormat) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

// Hostile nesting is rejected before any recursive processing.
func TestDecodeCanonicalBoundsDepth(t *testing.T) {
	deep := []byte(`{"a":` + strings.Repeat("[", MaxManifest-10))
	if _, err := ParseManifest(deep); !errors.Is(err, ErrFormat) {
		t.Fatalf("deep nesting: %v", err)
	}
	five := []byte(`{"a":[[[{}]]]}`)
	if _, err := decodeCanonical(five, MaxManifest); err == nil || !strings.Contains(err.Error(), "nesting") {
		t.Fatalf("depth 5: %v", err)
	}
	four := []byte(`{"a":[[{}]]}`)
	if _, err := decodeCanonical(four, MaxManifest); err != nil {
		t.Fatalf("depth 4: %v", err)
	}
}

func FuzzParseManifest(f *testing.F) {
	f.Add([]byte(`{"artifacts":[],"format":"nebula-release-v1","modules":[],"release_version":"1.0.0"}`))
	f.Add([]byte(`{"a":[[[[[[`))
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = ParseManifest(b)
	})
}

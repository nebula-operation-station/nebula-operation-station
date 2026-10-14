// SPDX-License-Identifier: AGPL-3.0-or-later

package totp

import (
	"strings"
	"testing"
	"time"
)

// RFC 6238 appendix B, SHA-1, 8 digits.
func TestRFC6238Vectors(t *testing.T) {
	secret := []byte("12345678901234567890")
	for _, v := range []struct {
		unix int64
		code string
	}{
		{59, "94287082"},
		{1111111109, "07081804"},
		{1111111111, "14050471"},
		{1234567890, "89005924"},
		{2000000000, "69279037"},
		{20000000000, "65353130"},
	} {
		if got := codeAt(secret, StepAt(time.Unix(v.unix, 0)), 8); got != v.code {
			t.Errorf("T=%d: %s, want %s", v.unix, got, v.code)
		}
	}
	// 6 digits are the low six of the 8-digit value.
	if got := Code(secret, time.Unix(59, 0)); got != "287082" {
		t.Errorf("6 digits: %s", got)
	}
}

func TestVerifyWindowAndReplay(t *testing.T) {
	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	for _, d := range []time.Duration{-Step, 0, Step} {
		if _, err := Verify(secret, Code(secret, now.Add(d)), now, 0); err != nil {
			t.Errorf("offset %v rejected", d)
		}
	}
	for _, d := range []time.Duration{-2 * Step, 2 * Step} {
		if _, err := Verify(secret, Code(secret, now.Add(d)), now, 0); err == nil {
			t.Errorf("offset %v accepted", d)
		}
	}
	step, err := Verify(secret, Code(secret, now), now, 0)
	if err != nil || step != StepAt(now) {
		t.Fatalf("verify: %d %v", step, err)
	}
	if _, err := Verify(secret, Code(secret, now), now, step); err == nil {
		t.Fatal("code accepted twice")
	}
	// An older code after a newer one was used is refused too.
	if _, err := Verify(secret, Code(secret, now.Add(-Step)), now, step); err == nil {
		t.Fatal("older code accepted after a newer one")
	}
	for _, bad := range []string{"", "12345", "1234567", "12a456", "１２３４５６"} {
		if _, err := Verify(secret, bad, now, 0); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestURI(t *testing.T) {
	u := URI([]byte("12345678901234567890"), "Nebula", "admin@nebula.example.org")
	for _, want := range []string{"otpauth://totp/Nebula:admin@nebula.example.org?", "secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", "issuer=Nebula", "digits=6", "period=30"} {
		if !strings.Contains(u, want) {
			t.Errorf("URI %s missing %s", u, want)
		}
	}
}

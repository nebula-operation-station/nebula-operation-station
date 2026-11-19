// SPDX-License-Identifier: AGPL-3.0-or-later

package secretguard

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// Fixtures are obviously fake. They have the shape of each class and carry
// no key material.
const (
	fakePrivateKey = "-----BEGIN OPENSSH PRIVATE KEY-----\nFAKEFAKEFAKE\n-----END OPENSSH PRIVATE KEY-----"
	fakeAgeKey     = "AGE-SECRET-KEY-1FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE"
	fakeOTPAuth    = "otpauth://totp/Example:fake?secret=FAKEFAKE"
)

// fakeNOSToken has the shape the server issues: "nos_" and 43 characters of
// the URL-safe base64 alphabet (see cmd/nebula-server/apitoken.go).
var fakeNOSToken = "nos_" + strings.Repeat("x-_0", 10) + "x-_"

// marker is part of every fixture. It must never appear in an error, a
// Class or a formatted value.
const marker = "MARKER-7f3a9c"

func TestCheckRejectsEachClassAtEveryPosition(t *testing.T) {
	t.Parallel()
	fixtures := []struct {
		name  string
		value string
		class Class
	}{
		{"private key block", fakePrivateKey, ClassPrivateKeyBlock},
		{"private key block, mixed case", "-----beGIN RSA PRIVATE KEY-----", ClassPrivateKeyBlock},
		{"age secret key", fakeAgeKey, ClassAgeSecretKey},
		{"age secret key, mixed case", "age-Secret-kEY-1FAKE", ClassAgeSecretKey},
		{"NOS token", fakeNOSToken, ClassNOSToken},
		{"otpauth URI", fakeOTPAuth, ClassOTPAuthURI},
		{"otpauth URI, mixed case", "OtpAuth://totp/x", ClassOTPAuthURI},
	}
	positions := map[string]func(v string) string{
		"start":          func(v string) string { return v + " is my question" },
		"middle":         func(v string) string { return "please check " + v + " for me" },
		"end":            func(v string) string { return "my question ends with " + v },
		"indented line":  func(v string) string { return "first line\n    " + v + "\nthird line" },
		"last of lines":  func(v string) string { return "a\nb\nc\n" + v },
		"only the value": func(v string) string { return v },
	}
	for _, fx := range fixtures {
		for pos, build := range positions {
			t.Run(fx.name+" at "+pos, func(t *testing.T) {
				t.Parallel()
				q := build(fx.value)
				err := Check(q)
				if !errors.Is(err, ErrLooksLikeSecret) {
					t.Fatalf("Check = %v, want ErrLooksLikeSecret", err)
				}
				c, ok := ClassOf(err)
				if !ok || c != fx.class {
					t.Fatalf("ClassOf = %v, %v; want %v, true", c, ok, fx.class)
				}
			})
		}
	}
}

func TestCheckRejectsSecretsSpreadOverLines(t *testing.T) {
	t.Parallel()
	q := "here is my config:\n" + fakePrivateKey + "\nplease help"
	if err := Check(q); !errors.Is(err, ErrLooksLikeSecret) {
		t.Fatalf("Check = %v, want ErrLooksLikeSecret", err)
	}
}

func TestCheckAcceptsHarmlessNeighbours(t *testing.T) {
	t.Parallel()
	tests := map[string]string{
		"BEGIN without dashes":        "the BEGIN command in SQL",
		"dashes without BEGIN":        "-----END marks the end",
		"otpauth without ://":         "what does the otpauth module do",
		"AGE-SECRET-KEY without dash": "AGE-SECRET-KEY is a name",
		"the word age":                "the age of the host is two years",
		"age-secret-key in words":     "the age secret key rotation policy",
		"nos_ with a short body":      "nos_" + strings.Repeat("a", 42),
		"nos_ alone":                  "nos_ is a prefix",
		"NOS token with a space":      "nos_" + strings.Repeat("a", 20) + " " + strings.Repeat("a", 22),
		"empty question":              "",
		"ordinary question":           "How do I add a host to the inventory?",
	}
	for name, q := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if err := Check(q); err != nil {
				t.Fatalf("Check(%q) = %v, want nil", q, err)
			}
		})
	}
}

func TestCheckNOSTokenFormatMatchesServerIssue(t *testing.T) {
	t.Parallel()
	// Same construction as cmd/nebula-server/apitoken.go: "nos_" plus
	// base64.RawURLEncoding of 32 random bytes.
	for i := 0; i < 20; i++ {
		var b [32]byte
		if _, err := rand.Read(b[:]); err != nil {
			t.Fatal(err)
		}
		tok := "nos_" + base64.RawURLEncoding.EncodeToString(b[:])
		if len(tok) != 47 {
			t.Fatalf("issued token length = %d, want 47", len(tok))
		}
		if err := Check("token: " + tok); !errors.Is(err, ErrLooksLikeSecret) {
			t.Fatalf("issued token not refused: %v", err)
		}
	}
}

func TestCheckLengthLimit(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		size    int
		wantErr error
	}{
		"exactly 2 KiB":  {MaxQuestionBytes, nil},
		"2 KiB plus one": {MaxQuestionBytes + 1, ErrTooLong},
		"empty":          {0, nil},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			q := strings.Repeat("a", tc.size)
			if err := Check(q); !errors.Is(err, tc.wantErr) && err != tc.wantErr {
				t.Fatalf("Check(len %d) = %v, want %v", tc.size, err, tc.wantErr)
			}
		})
	}
}

func TestCheckLengthIsCheckedBeforeSecrets(t *testing.T) {
	t.Parallel()
	q := fakeAgeKey + strings.Repeat("a", MaxQuestionBytes)
	if err := Check(q); !errors.Is(err, ErrTooLong) {
		t.Fatalf("Check = %v, want ErrTooLong", err)
	}
}

func TestCheckRejectsInvalidUTF8(t *testing.T) {
	t.Parallel()
	for name, q := range map[string]string{
		"lone continuation byte": "hello \x80 world",
		"truncated sequence":     "abc \xe2\x82",
		"surrogate encoding":     "\xed\xa0\x80",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if err := Check(q); !errors.Is(err, ErrInvalidText) {
				t.Fatalf("Check = %v, want ErrInvalidText", err)
			}
		})
	}
}

func TestErrorsDoNotNameTheFinding(t *testing.T) {
	t.Parallel()
	cases := []string{
		"-----BEGIN " + marker + "-----",
		"AGE-SECRET-KEY-" + marker,
		"otpauth://" + marker,
		"nos_" + marker + strings.Repeat("a", 43-len(marker)),
	}
	for _, q := range cases {
		err := Check("before " + q + " after")
		if err == nil {
			t.Fatalf("Check(%q) accepted a secret", q)
		}
		values := []string{
			err.Error(),
			fmt.Sprintf("%v", err),
			fmt.Sprintf("%+v", err),
			fmt.Sprintf("%#v", err),
		}
		if c, ok := ClassOf(err); ok {
			values = append(values, c.String(), fmt.Sprintf("%v %+v %#v", c, c, c))
		}
		for _, v := range values {
			if strings.Contains(v, marker) {
				t.Fatalf("formatted value %q contains the finding marker", v)
			}
		}
	}
}

func TestClassStringNamesOnlyTheClass(t *testing.T) {
	t.Parallel()
	want := map[Class]string{
		ClassPrivateKeyBlock: "private key block",
		ClassAgeSecretKey:    "age secret key",
		ClassNOSToken:        "NOS API token",
		ClassOTPAuthURI:      "otpauth URI",
	}
	for c, s := range want {
		if got := c.String(); got != s {
			t.Errorf("%d.String() = %q, want %q", c, got, s)
		}
	}
}

func TestClassOfReportsNothingForOtherErrors(t *testing.T) {
	t.Parallel()
	for _, err := range []error{nil, ErrTooLong, ErrInvalidText, errors.New("other")} {
		if c, ok := ClassOf(err); ok {
			t.Errorf("ClassOf(%v) = %v, true; want false", err, c)
		}
	}
}

func TestFixedErrorTexts(t *testing.T) {
	t.Parallel()
	want := map[error]string{
		ErrTooLong:         "question is longer than 2 KiB",
		ErrInvalidText:     "question is not valid UTF-8 text",
		ErrLooksLikeSecret: "this looks like a secret; remove it",
	}
	for err, text := range want {
		if err.Error() != text {
			t.Errorf("error text = %q, want %q", err.Error(), text)
		}
	}
}

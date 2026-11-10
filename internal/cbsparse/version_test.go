// SPDX-License-Identifier: AGPL-3.0-or-later

package cbsparse

import (
	"errors"
	"os"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"github.com/nebula-operation-station/nebula-operation-station/internal/netdevcontract"
)

type testHelper interface {
	Helper()
	Fatalf(format string, args ...any)
}

// The fixtures in testdata are SYNTHETIC: placeholder serials
// (PSZ0000000x), fictional 3.x firmware releases and no real addresses.
// They are not captured from lab devices; ND-03 records the real lab
// fixtures before any of them is relied on.
func syntheticFixture(t testHelper, name string) []byte {
	t.Helper()
	in, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return in
}

func TestParseVersion(t *testing.T) {
	cbs250 := syntheticFixture(t, "version_cbs250.txt")
	cbs350 := syntheticFixture(t, "version_cbs350.txt")

	tests := []struct {
		name    string
		in      []byte
		want    Version
		wantErr error // if non-nil, the error must match it via errors.Is
		// wantErrAny requires an error without checking which one.
		wantErrAny bool
	}{
		{
			name: "cbs250 synthetic fixture",
			in:   cbs250,
			want: Version{Model: "CBS250-8T", Firmware: "3.1.0.10", Serial: "PSZ00000000"},
		},
		{
			name: "cbs350 synthetic fixture",
			in:   cbs350,
			want: Version{Model: "CBS350-24T-4G", Firmware: "3.2.1.5", Serial: "PSZ00000001"},
		},
		{
			name: "empty input is incomplete, not an error",
			in:   []byte{},
			want: Version{Incomplete: true},
		},
		{
			name: "missing fields are incomplete, not an error",
			in:   []byte("Model : CBS250-8T\n"),
			want: Version{Model: "CBS250-8T", Incomplete: true},
		},
		{
			name: "key without value counts as missing",
			in:   []byte("Model : CBS250-8T\nSerial Number :\nFirmware Version : 3.1.0.10\n"),
			want: Version{Model: "CBS250-8T", Firmware: "3.1.0.10", Incomplete: true},
		},
		{
			name: "spacing tolerated around key, colon and value",
			in:   []byte("  Model    :   CBS250-8T\nSerial Number:PSZ00000000\nFirmware Version   3.2.1.5\n"),
			want: Version{Model: "CBS250-8T", Firmware: "3.2.1.5", Serial: "PSZ00000000"},
		},
		{
			name: "unknown lines are ignored",
			in: []byte(
				"Cisco IOS Software, C250 Software, Version 3.1.0.10, RELEASE SOFTWARE (synthetic)\n" +
					"System uptime is 1 week, 2 days, 3 hours, 4 minutes\n" +
					"Model : CBS250-8T\n" +
					"Serial Number : PSZ00000000\n" +
					"Firmware Version : 3.1.0.10\n" +
					"some other line with no known key\n"),
			want: Version{Model: "CBS250-8T", Firmware: "3.1.0.10", Serial: "PSZ00000000"},
		},
		{
			name:    "oversize output is refused",
			in:      bytesRepeat('a', netdevcontract.MaxCBSCommandOutputBytes+1),
			wantErr: netdevcontract.ErrOverLimit,
		},
		{
			name:    "line over the line limit is refused",
			in:      append([]byte("Model : "+strings.Repeat("a", netdevcontract.MaxLineBytes+1)), '\n'),
			wantErr: netdevcontract.ErrOverLimit,
		},
		{
			name:    "10000 character value is refused",
			in:      []byte("Model : " + strings.Repeat("a", 10000)),
			wantErr: netdevcontract.ErrOverLimit,
		},
		{
			name:    "value over the label limit is refused",
			in:      []byte("Model : " + strings.Repeat("a", netdevcontract.MaxLabelBytes+1)),
			wantErr: netdevcontract.ErrOverLimit,
		},
		{
			name:       "invalid UTF-8 is refused",
			in:         []byte("Model : CBS250-8T\xff\xfe\n"),
			wantErrAny: true,
		},
		{
			name:       "control character in a line is refused",
			in:         []byte("Model : CBS250-8T\nSerial Number : PSZ00000000\x07\n"),
			wantErrAny: true,
		},
		{
			name:       "embedded carriage return is refused",
			in:         []byte("Model : CB\rS250-8T\n"),
			wantErrAny: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseVersion(tt.in)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("ParseVersion error = %v, want errors.Is %v", err, tt.wantErr)
				}
				return
			}
			if tt.wantErrAny {
				if err == nil {
					t.Fatalf("ParseVersion error = nil, want an error")
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseVersion unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("ParseVersion = %+v, want %+v", got, tt.want)
			}
		})
	}
}

// TestParseVersionKeyMatching pins whole-key matching: a known key is only
// recognised when it is the complete key of the line, never as a prefix of
// a longer key.
func TestParseVersionKeyMatching(t *testing.T) {
	const realKeys ="Model : CBS250-8T\nSerial Number : PSZ00000000\nFirmware Version : 3.1.0.10\n"
	want := Version{Model: "CBS250-8T", Firmware: "3.1.0.10", Serial: "PSZ00000000"}
	tests := []struct {
		name string
		in   string
		want Version
	}{
		{"longer firmware key before real key", "Firmware Date : 2020\n" + realKeys, want},
		{"longer model key before real key", "Model Number : X\n" + realKeys, want},
		{"longer serial key before real key", "Serial No. : S\n" + realKeys, want},
		{"longer keys alone fill nothing", "Firmware Date : 2020\nModel Number : X\nSerial No. : S\n", Version{Incomplete: true}},
		{"key glued to a longer word is ignored", "ModelX : y\n", Version{Incomplete: true}},
		{"key glued to a longer word before real key", "ModelX : y\n" + realKeys, want},
		{"longer key in column layout is ignored", "Firmware Date    2020\nModel Number    X\n", Version{Incomplete: true}},
		{"single space is not a column gap", "Model CBS250-8T\n", Version{Incomplete: true}},
		{"tab is a column gap", "Model\tCBS250-8T\n", Version{Model: "CBS250-8T", Incomplete: true}},
		{"space before colon tolerated", "Serial Number    :   PSZ00000000\n", Version{Serial: "PSZ00000000", Incomplete: true}},
		{"value may contain a colon", "Firmware Version : 3.1.0.10 (build: 7)\n", Version{Firmware: "3.1.0.10 (build: 7)", Incomplete: true}},
		{"keys are case sensitive", "model : CBS250-8T\n", Version{Incomplete: true}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseVersion([]byte(tt.in))
			if err != nil {
				t.Fatalf("ParseVersion unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("ParseVersion = %+v, want %+v", got, tt.want)
			}
		})
	}
}

// TestParseVersionKeyPrecedence pins how keys for the same field resolve:
// the most specific key wins regardless of line order, and among repeated
// keys of the same specificity the first occurrence (the active image
// block on CBS output) wins.
func TestParseVersionKeyPrecedence(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want Version
	}{
		{"firmware version after generic version", "Version : 9.9.9\nFirmware Version : 3.1.0.10\n", Version{Firmware: "3.1.0.10", Incomplete: true}},
		{"firmware version before generic version", "Firmware Version : 3.1.0.10\nVersion : 9.9.9\n", Version{Firmware: "3.1.0.10", Incomplete: true}},
		{"firmware version after bare firmware", "Firmware : 1.0\nFirmware Version : 3.1.0.10\n", Version{Firmware: "3.1.0.10", Incomplete: true}},
		{"bare firmware after generic version", "Version : 9.9.9\nFirmware : 1.0\n", Version{Firmware: "1.0", Incomplete: true}},
		{"serial number after bare serial", "Serial : S1\nSerial Number : PSZ00000000\n", Version{Serial: "PSZ00000000", Incomplete: true}},
		{"serial number before bare serial", "Serial Number : PSZ00000000\nSerial : S1\n", Version{Serial: "PSZ00000000", Incomplete: true}},
		{"generic version fallback alone", "Version : 3.1.0.10\n", Version{Firmware: "3.1.0.10", Incomplete: true}},
		{"bare firmware fallback alone", "Firmware : 3.1.0.10\n", Version{Firmware: "3.1.0.10", Incomplete: true}},
		{"bare serial fallback alone", "Serial : PSZ00000000\n", Version{Serial: "PSZ00000000", Incomplete: true}},
		{
			"repeated version in active and inactive image blocks: first wins",
			"Active-image: flash://system/images/a.bin\n  Version: 3.1.0.10\nInactive-image: flash://system/images/b.bin\n  Version: 3.0.0.61\n",
			Version{Firmware: "3.1.0.10", Incomplete: true},
		},
		{"repeated specific key: first wins", "Model : CBS250-8T\nModel : CBS350-8T\n", Version{Model: "CBS250-8T", Incomplete: true}},
		{"empty specific key does not hide fallback", "Firmware Version :\nVersion : 3.1.0.10\n", Version{Firmware: "3.1.0.10", Incomplete: true}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseVersion([]byte(tt.in))
			if err != nil {
				t.Fatalf("ParseVersion unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("ParseVersion = %+v, want %+v", got, tt.want)
			}
		})
	}
}

// TestParseVersionRejectsInvalidValueText pins that field values follow
// the netdevcontract text rule; an invalid value is an error, not a
// silently filled or silently dropped field.
func TestParseVersionRejectsInvalidValueText(t *testing.T) {
	tests := []struct {
		name string
		in   string
	}{
		{"tab inside value", "Model : CBS\t250\n"},
		{"replacement character in value", "Serial Number : PSZ�0\n"},
		{"tab inside fallback value", "Version : 3.1\t.0\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseVersion([]byte(tt.in))
			if !errors.Is(err, ErrInvalidValue) {
				t.Fatalf("ParseVersion error = %v, want errors.Is ErrInvalidValue", err)
			}
		})
	}
}

// TestParseVersionAcceptsInvalidTextInUnknownLines pins that the value
// rule applies to field values only: U+FFFD in an ignored line is fine.
func TestParseVersionAcceptsInvalidTextInUnknownLines(t *testing.T) {
	got, err := ParseVersion([]byte("Banner �\tx\nModel : CBS250-8T\n"))
	if err != nil {
		t.Fatalf("ParseVersion unexpected error: %v", err)
	}
	if want := (Version{Model: "CBS250-8T", Incomplete: true}); got != want {
		t.Fatalf("ParseVersion = %+v, want %+v", got, want)
	}
}

func TestParseVersionLineLimit(t *testing.T) {
	atLimit := strings.Repeat("x\n", versionMaxLines-1) + "Model : CBS250-8T\n"
	got, err := ParseVersion([]byte(atLimit))
	if err != nil {
		t.Fatalf("ParseVersion at line limit: unexpected error: %v", err)
	}
	if got.Model != "CBS250-8T" {
		t.Fatalf("ParseVersion at line limit: Model = %q", got.Model)
	}
	overLimit := strings.Repeat("x\n", versionMaxLines) + "Model : CBS250-8T\n"
	if _, err := ParseVersion([]byte(overLimit)); !errors.Is(err, netdevcontract.ErrOverLimit) {
		t.Fatalf("ParseVersion over line limit: error = %v, want ErrOverLimit", err)
	}
}

// TestParseVersionValueAtLabelLimit pins the boundary: exactly
// MaxLabelBytes is accepted.
func TestParseVersionValueAtLabelLimit(t *testing.T) {
	v := strings.Repeat("a", netdevcontract.MaxLabelBytes)
	got, err := ParseVersion([]byte("Model : " + v + "\n"))
	if err != nil {
		t.Fatalf("ParseVersion unexpected error: %v", err)
	}
	if got.Model != v {
		t.Fatalf("ParseVersion Model has %d bytes, want %d", len(got.Model), len(v))
	}
}

func bytesRepeat(c byte, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = c
	}
	return b
}

// FuzzParseVersion: the parser must never panic on arbitrary bytes, and a
// successful parse only returns values that satisfy the netdevcontract
// text rule with a consistent Incomplete flag; an error returns the zero
// Version.
func FuzzParseVersion(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte("Model : CBS250-8T\nSerial Number : PSZ00000000\nFirmware Version : 3.1.0.10\n"))
	f.Add(syntheticFixture(f, "version_cbs250.txt"))
	f.Add(syntheticFixture(f, "version_cbs350.txt"))
	f.Add([]byte("Model : " + strings.Repeat("a", 300)))
	f.Add([]byte("Firmware Date : 2020\nModelX : y\nVersion : 1\nFirmware Version : 2\n"))
	f.Add([]byte("Model : CBS\t250\nSerial\tPSZ�\n"))
	f.Fuzz(func(t *testing.T, in []byte) {
		got, err := ParseVersion(in)
		if err != nil {
			if got != (Version{}) {
				t.Fatalf("ParseVersion error %v with non-zero result %+v", err, got)
			}
			return
		}
		for name, val := range map[string]string{"Model": got.Model, "Firmware": got.Firmware, "Serial": got.Serial} {
			if val == "" {
				continue
			}
			if len(val) > netdevcontract.MaxLabelBytes {
				t.Fatalf("%s has %d bytes, over MaxLabelBytes", name, len(val))
			}
			if !utf8.ValidString(val) || strings.ContainsFunc(val, func(r rune) bool {
				return r == '\t' || r == utf8.RuneError || !unicode.IsPrint(r)
			}) {
				t.Fatalf("%s %q violates the text rule", name, val)
			}
			if val != strings.TrimSpace(val) {
				t.Fatalf("%s %q has surrounding space", name, val)
			}
		}
		wantIncomplete := got.Model == "" || got.Firmware == "" || got.Serial == ""
		if got.Incomplete != wantIncomplete {
			t.Fatalf("Incomplete = %v for %+v", got.Incomplete, got)
		}
	})
}

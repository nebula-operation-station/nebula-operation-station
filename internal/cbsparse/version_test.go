// SPDX-License-Identifier: AGPL-3.0-or-later

package cbsparse

import (
	"errors"
	"os"
	"strings"
	"testing"

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

func bytesRepeat(c byte, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = c
	}
	return b
}

// FuzzParseVersion: the parser must never panic on arbitrary bytes.
func FuzzParseVersion(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte("Model : CBS250-8T\nSerial Number : PSZ00000000\nFirmware Version : 3.1.0.10\n"))
	f.Add(syntheticFixture(f, "version_cbs250.txt"))
	f.Add(syntheticFixture(f, "version_cbs350.txt"))
	f.Add([]byte("Model : " + strings.Repeat("a", 300)))
	f.Fuzz(func(t *testing.T, in []byte) {
		_, _ = ParseVersion(in)
	})
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package helpfacts

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseLiteralsRecognisesOnlyLiteralShapes(t *testing.T) {
	tests := []struct {
		name     string
		question string
		want     []string // literal keys: "a:<ip>", "c:<net>", "n:<name>"
	}{
		{"ipv4 address with sentence period", "192.168.22.1.", []string{"a:192.168.22.1"}},
		{"ipv6 address", "fe80::1", []string{"a:fe80::1"}},
		{"ipv6 address with trailing colon", "2001:db8::10:", []string{"a:2001:db8::10"}},
		{"ipv4 cidr", "10.0.0.0/8", []string{"c:10.0.0.0/8"}},
		{"ipv6 cidr", "2001:db8::/32", []string{"c:2001:db8::/32"}},
		{"invalid prefix is not a literal", "10.0.0.1/33", nil},
		{"name and id literals", "pve1 web-2.lan", []string{"n:pve1", "n:web-2.lan"}},
		{"url is one token and not a literal", "http://evil.example/x", nil},
		{"duplicates collapse", "pve1 pve1 PVE1", []string{"n:pve1"}},
		{"punctuation only yields nothing", "??? !!! ---", nil},
		{"non-ascii splits tokens", "pveé1", []string{"n:pve", "n:1"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			lits, truncated := parseLiterals(tc.question)
			if truncated {
				t.Fatal("unexpected truncation")
			}
			var got []string
			for _, l := range lits {
				got = append(got, l.key())
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("literals = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestParseLiteralsStopsAtLimit(t *testing.T) {
	var b strings.Builder
	for i := 0; i <= MaxLiterals; i++ {
		b.WriteString("host" + string(rune('a'+i%26)) + string(rune('a'+i/26)) + " ")
	}
	lits, truncated := parseLiterals(b.String())
	if len(lits) != MaxLiterals || !truncated {
		t.Fatalf("got %d literals truncated=%v, want %d and true", len(lits), truncated, MaxLiterals)
	}
}

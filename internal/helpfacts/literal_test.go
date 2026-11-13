// SPDX-License-Identifier: AGPL-3.0-or-later

package helpfacts

import (
	"fmt"
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
		{"ipv4 cidr", "10.0.0.0/16", []string{"c:10.0.0.0/16"}},
		{"ipv6 cidr", "2001:db8::/32", []string{"c:2001:db8::/32"}},
		{"invalid prefix is not a literal", "10.0.0.1/33", nil},
		{"name and id literals", "pve1 web-2.lan", []string{"n:pve1", "n:web-2.lan"}},
		{"url host part is a literal", "http://evil.example/x", []string{"n:evil.example"}},
		{"url with port and ip host", "https://10.0.0.5:8006/api", []string{"a:10.0.0.5"}},
		{"host:port with ip", "10.0.0.1:22", []string{"a:10.0.0.1"}},
		{"host:port with name", "pve1:22", []string{"n:pve1"}},
		{"host:port with invalid port is not a literal", "pve1:99999", nil},
		{"separators split tokens", "(pve1),pve2;[10.0.0.1]\"web\"<x>", []string{"n:pve1", "n:pve2", "a:10.0.0.1", "n:web", "n:x"}},
		{"only one trailing mark is removed", "pve1..", nil},
		{"trailing question and exclamation marks", "is pve1? pve2!", []string{"n:is", "n:pve1", "n:pve2"}},
		{"duplicates collapse", "pve1 pve1 PVE1", []string{"n:pve1"}},
		{"punctuation only yields nothing", "??? !!! ---", nil},
		{"non-ascii is not a separator", "pveé1", nil},
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

func TestParseLiteralsStopsAtAddressLimit(t *testing.T) {
	var b strings.Builder
	for i := 0; i <= MaxLiterals; i++ {
		fmt.Fprintf(&b, "10.0.0.%d ", i+1)
	}
	lits, truncated := parseLiterals(b.String())
	if len(lits) != MaxLiterals || !truncated {
		t.Fatalf("got %d literals truncated=%v, want %d and true", len(lits), truncated, MaxLiterals)
	}
}

func TestNameLiteralsDoNotUseAddressBudget(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 200; i++ {
		fmt.Fprintf(&b, "word%d ", i)
	}
	b.WriteString("10.9.9.9")
	lits, truncated := parseLiterals(b.String())
	if truncated {
		t.Fatal("ordinary words set truncated")
	}
	last := lits[len(lits)-1]
	if last.kind != litAddress || last.ip.String() != "10.9.9.9" {
		t.Fatalf("address after many words was dropped; last literal = %q", last.key())
	}
}

func TestBroadCIDRIsRefusedAndReported(t *testing.T) {
	for _, q := range []string{"0.0.0.0/0", "::/0", "10.0.0.0/8", "2001:db8::/31"} {
		lits, truncated := parseLiterals("what about " + q + "?")
		for _, l := range lits {
			if l.kind == litCIDR || l.kind == litAddress {
				t.Fatalf("%s: broad block became literal %s", q, l.key())
			}
		}
		if !truncated {
			t.Fatalf("%s: truncated = false, want true", q)
		}
	}
}

func TestNonLiteralTokensOnlyFillNothing(t *testing.T) {
	lits, truncated := parseLiterals("ünïcode 2001:db8::/32x 1.2.3.4.5 a..b")
	if truncated {
		t.Fatal("non-literal tokens set truncated")
	}
	for _, l := range lits {
		if l.kind == litCIDR {
			t.Fatalf("malformed CIDR accepted: %s", l.key())
		}
	}
}

func TestParseQuestionHostValuesMatchesProjectorMatcher(t *testing.T) {
	v := ParseQuestionHostValues("pve1:22 https://10.0.0.5/x 2001:db8::/32, Foo.lan.")
	if !reflect.DeepEqual(v.Addresses, []string{"10.0.0.5"}) ||
		!reflect.DeepEqual(v.CIDRs, []string{"2001:db8::/32"}) ||
		!reflect.DeepEqual(v.Names, []string{"pve1", "foo.lan"}) || v.Truncated {
		t.Fatalf("values = %+v", v)
	}
}

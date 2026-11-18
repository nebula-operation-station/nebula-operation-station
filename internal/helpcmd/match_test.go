// SPDX-License-Identifier: AGPL-3.0-or-later

package helpcmd

import (
	"errors"
	"reflect"
	"testing"
)

// TestMatchShapeRules checks each rule of ADR 0014 D4, "Matching (V3)", with
// one row per case. A row with wantErr nil must match; a row with ErrNoMatch
// or ErrUnbalancedQuote must fail with that error.
func TestMatchShapeRules(t *testing.T) {
	tests := []struct {
		name          string
		doc           string
		cmd           string
		wantErr       error
		wantUnchanged bool
		wantHosts     []string
	}{
		// Token count, order and byte equality.
		{name: "identical without placeholder matches", doc: "nebula status", cmd: "nebula status"},
		{name: "fewer command tokens do not match", doc: "nebula pve list", cmd: "nebula pve", wantErr: ErrNoMatch},
		{name: "more command tokens do not match", doc: "nebula pve", cmd: "nebula pve list", wantErr: ErrNoMatch},
		{name: "reordered tokens do not match", doc: "a b", cmd: "b a", wantErr: ErrNoMatch},
		{name: "one byte difference does not match", doc: "nebula status", cmd: "nebula Status", wantErr: ErrNoMatch},
		{name: "runs of spaces match a single space", doc: "a b", cmd: "a    b"},
		{name: "quotes in plain text must be byte-equal", doc: `echo "x"`, cmd: `echo x`, wantErr: ErrNoMatch},
		{name: "command is not expanded", doc: `echo $HOME`, cmd: `echo /root`, wantErr: ErrNoMatch},

		// Host class: value shape and whole-token IPv6.
		{name: "host placeholder takes an IPv4 address", doc: "nebula pve add <host>", cmd: "nebula pve add 10.0.0.1", wantHosts: []string{"10.0.0.1"}},
		{name: "host placeholder takes a DNS name", doc: "nebula pve add <host>", cmd: "nebula pve add pve1.lab.example", wantHosts: []string{"pve1.lab.example"}},
		{name: "host placeholder takes an IPv6 literal as whole token", doc: "<host>", cmd: "2001:db8::1", wantHosts: []string{"2001:db8::1"}},
		{name: "IPv6 literal inside a token is refused", doc: "--ep=<host>", cmd: "--ep=2001:db8::1", wantErr: ErrNoMatch},
		{name: "host value with a slash is refused", doc: "ssh <host>", cmd: "ssh evil.example/x", wantErr: ErrNoMatch},
		{name: "host value with userinfo is refused", doc: "ssh <host>", cmd: "ssh root@10.0.0.1", wantErr: ErrNoMatch},
		{name: "host value with a query is refused", doc: "curl <host>", cmd: "curl a.example?x", wantErr: ErrNoMatch},
		{name: "host label starting with a dash is refused", doc: "ssh <host>", cmd: "ssh -a.example", wantErr: ErrNoMatch},
		{name: "two host placeholders list both values", doc: "copy <host> <ip>", cmd: "copy 10.0.0.1 10.0.0.2", wantHosts: []string{"10.0.0.1", "10.0.0.2"}},
		{name: "host value with a trailing dot is refused", doc: "ssh <host>", cmd: "ssh 10.0.0.1.", wantErr: ErrNoMatch},
		{name: "dotted quad out of range is refused", doc: "ssh <host>", cmd: "ssh 999.1.1.1", wantErr: ErrNoMatch},
		{name: "three numeric labels are a valid DNS name", doc: "ssh <host>", cmd: "ssh 10.0.0", wantHosts: []string{"10.0.0"}},

		// Prefix and suffix around the placeholder: literal text, value in the middle.
		{name: "quoted host keeps its quotes", doc: `"<host>"`, cmd: `"10.0.0.1"`, wantHosts: []string{"10.0.0.1"}},
		{name: "quoted host needs the quotes", doc: `"<host>"`, cmd: `10.0.0.1`, wantErr: ErrNoMatch},
		{name: "text before and after the value must be literal", doc: "https://<digest>/x", cmd: "https://abc123/x"},
		{name: "text after the value must be literal", doc: "https://<digest>/x", cmd: "https://abc123/y", wantErr: ErrNoMatch},
		{name: "scheme is taken from the doc", doc: "https://<digest>/x", cmd: "http://abc123/x", wantErr: ErrNoMatch},
		{name: "empty value is refused", doc: "--x=<id>", cmd: "--x=", wantErr: ErrNoMatch},
		{name: "prefix and suffix may not overlap the value", doc: "a<id>a", cmd: "aa", wantErr: ErrNoMatch},
		{name: "overlapping prefix and suffix on a one-byte command do not panic", doc: "a<id>a", cmd: "a", wantErr: ErrNoMatch},
		{name: "command shorter than the literal prefix is refused", doc: "--x=<id>", cmd: "--x", wantErr: ErrNoMatch},

		// At most one placeholder per token.
		{name: "two placeholders in one token do not match", doc: "<host>:<date>", cmd: "10.0.0.1:2026-01-01", wantErr: ErrNoMatch},
		{name: "two placeholders in one token refused even when unchanged", doc: "<host>:<host>", cmd: "<host>:<host>", wantErr: ErrNoMatch},
		{name: "one placeholder per token is fine across tokens", doc: "x <date> <version>", cmd: "x 2026-11-18 1.4.0"},

		// Unknown placeholder names match nothing.
		{name: "unknown name does not match a value", doc: "nebula x <foo>", cmd: "nebula x bar", wantErr: ErrNoMatch},
		{name: "unknown name does not match itself", doc: "nebula x <foo>", cmd: "nebula x <foo>", wantErr: ErrNoMatch},
		{name: "name with a capital letter is not a placeholder", doc: "<Host>", cmd: "<Host>"},
		{name: "name is matched exactly, no suffix rule", doc: "<host-x>", cmd: "<host-x>", wantErr: ErrNoMatch},

		// id: no dot and no colon, so never a DNS name.
		{name: "id accepts a plain identifier", doc: "nebula x <id>", cmd: "nebula x abc_DEF-1"},
		{name: "id refuses a DNS name", doc: "nebula x <id>", cmd: "nebula x example.com", wantErr: ErrNoMatch},
		{name: "id refuses an IP literal", doc: "nebula x <id>", cmd: "nebula x 10.0.0.1", wantErr: ErrNoMatch},
		{name: "digest refuses a colon", doc: "nebula x <digest>", cmd: "nebula x a:b", wantErr: ErrNoMatch},
		{name: "id refuses quoted value", doc: "nebula x <id>", cmd: `nebula x "a"`, wantErr: ErrNoMatch},

		// version: the prerelease is one word plus at most one digits part.
		{name: "version accepts a release version", doc: "nebula v <version>", cmd: "nebula v 1.4.0"},
		{name: "version accepts a numeric prerelease part", doc: "nebula v <version>", cmd: "nebula v 1.4.0-rc.1"},
		{name: "version refuses a DNS-like prerelease", doc: "nebula v <version>", cmd: "nebula v 1.4.0-evil.example", wantErr: ErrNoMatch},
		{name: "version refuses two dotted prerelease parts", doc: "nebula v <version>", cmd: "nebula v 1.4.0-rc.1.2", wantErr: ErrNoMatch},

		// date: shape only.
		{name: "date accepts YYYY-MM-DD", doc: "nebula d <date>", cmd: "nebula d 2026-11-18"},
		{name: "date refuses a short month", doc: "nebula d <date>", cmd: "nebula d 2026-1-18", wantErr: ErrNoMatch},

		// Unchanged placeholders: the copied token matches and is reported.
		{name: "unchanged host matches and is reported", doc: "nebula pve add <host>", cmd: "nebula pve add <host>", wantUnchanged: true},
		{name: "unchanged quoted placeholder matches and is reported", doc: `echo '<digest>'`, cmd: `echo '<digest>'`, wantUnchanged: true},
		{name: "unchanged host is not a host value", doc: "ssh <host>", cmd: "ssh <host>", wantUnchanged: true},
		{name: "unchanged and filled placeholders mix", doc: "copy <host> <id>", cmd: "copy 10.0.0.1 <id>", wantUnchanged: true, wantHosts: []string{"10.0.0.1"}},

		// Unbalanced quote is a tokenizer error, reported as such.
		{name: "unbalanced quote in the command is red", doc: "echo a", cmd: `echo "a`, wantErr: ErrUnbalancedQuote},
		{name: "unbalanced quote in the doc is red", doc: `echo "a`, cmd: "echo a", wantErr: ErrUnbalancedQuote},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := MatchShape(tt.doc, tt.cmd)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("MatchShape(%q, %q) error = %v; want %v", tt.doc, tt.cmd, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("MatchShape(%q, %q) error = %v; want match", tt.doc, tt.cmd, err)
			}
			if got.Unchanged() != tt.wantUnchanged {
				t.Errorf("Unchanged() = %v; want %v", got.Unchanged(), tt.wantUnchanged)
			}
			if !reflect.DeepEqual(got.HostValues(), tt.wantHosts) {
				t.Errorf("HostValues() = %q; want %q", got.HostValues(), tt.wantHosts)
			}
		})
	}
}

// TestMatchShapeBindings checks the token index, name, class and value of a
// binding, which V5 and the messages use.
func TestMatchShapeBindings(t *testing.T) {
	got, err := MatchShape(`nebula x --ep "<host>" --id <id>`, `nebula x --ep "pve1.lab.example" --id abc`)
	if err != nil {
		t.Fatalf("MatchShape error = %v", err)
	}
	want := []Binding{
		{Token: 3, Name: "host", Class: ClassHost, Value: "pve1.lab.example"},
		{Token: 5, Name: "id", Class: ClassID, Value: "abc"},
	}
	if !reflect.DeepEqual(got.Bindings, want) {
		t.Errorf("Bindings = %+v; want %+v", got.Bindings, want)
	}
}

// TestMatchShapeUnchangedBindingValue checks that an Unchanged binding carries
// the placeholder text itself, not the whole doc token, so a caller can build
// the "replace <…>" message from Value.
func TestMatchShapeUnchangedBindingValue(t *testing.T) {
	tests := []struct {
		name string
		doc  string
		cmd  string
		want Binding
	}{
		{
			name: "whole token placeholder",
			doc:  "ssh <host>",
			cmd:  "ssh <host>",
			want: Binding{Token: 1, Name: "host", Class: ClassHost, Value: "<host>", Unchanged: true},
		},
		{
			name: "placeholder with literal prefix keeps only the placeholder",
			doc:  "--x=<id>",
			cmd:  "--x=<id>",
			want: Binding{Token: 0, Name: "id", Class: ClassID, Value: "<id>", Unchanged: true},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := MatchShape(tt.doc, tt.cmd)
			if err != nil {
				t.Fatalf("MatchShape(%q, %q) error = %v; want match", tt.doc, tt.cmd, err)
			}
			if len(got.Bindings) != 1 {
				t.Fatalf("Bindings = %+v; want one binding", got.Bindings)
			}
			if !reflect.DeepEqual(got.Bindings[0], tt.want) {
				t.Errorf("Bindings[0] = %+v; want %+v", got.Bindings[0], tt.want)
			}
		})
	}
}

// TestMatchShapeNoMatchWrapsSentinel checks that every rule failure is
// ErrNoMatch and carries the token index, so callers can branch on it.
func TestMatchShapeNoMatchWrapsSentinel(t *testing.T) {
	_, err := MatchShape("ssh <host>", "ssh a/b")
	if !errors.Is(err, ErrNoMatch) {
		t.Fatalf("error = %v; want ErrNoMatch", err)
	}
	if !errors.Is(err, ErrPlaceholderValue) {
		t.Errorf("error = %v; want it to also wrap ErrPlaceholderValue", err)
	}
}

// TestHasPlaceholder checks the `<name>` shape check used for unchanged
// placeholders in a command.
func TestHasPlaceholder(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{"nebula status", false},
		{"nebula pve add <host>", true},
		{"nebula x <Host>", false},
		{"nebula x <a b>", false},
		{"nebula x <unknown-name>", true},
		{"<<host>>", true},
	}
	for _, tt := range tests {
		if got := HasPlaceholder(tt.in); got != tt.want {
			t.Errorf("HasPlaceholder(%q) = %v; want %v", tt.in, got, tt.want)
		}
	}
}

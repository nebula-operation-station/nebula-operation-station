// SPDX-License-Identifier: AGPL-3.0-or-later

package softwarecat

import (
	"strings"
	"testing"
)

// FuzzNormalizers fuzzes every normalizer with the same untrusted input.
func FuzzNormalizers(f *testing.F) {
	f.Add("docker.io/library/postgres:16")
	f.Add("ghcr.io/foo/bar@sha256:0123456789abcdef")
	f.Add("netbirdio/netbird")
	f.Add("")
	f.Add("@")
	f.Add(":")
	f.Add("/")
	f.Add("localhost:5000/a/b")
	f.Add("foo:bar")
	f.Add(strings.Repeat("a", 300))
	f.Add("\x00\xff docker.io/library/Postgres:16")
	f.Add("\u212Aeycloak")
	f.Add("postgresql@16.service")
	f.Add("nvidia-driver-550.54.15")
	f.Fuzz(func(t *testing.T, in string) {
		for _, n := range normalizers {
			checkResult(t, n.name, in, n.fn)
		}
	})
}

// checkResult asserts the invariants every normalizer result must hold.
func checkResult(t *testing.T, name, in string, fn func(string) Result) {
	t.Helper()
	a, b := fn(in), fn(in)
	if a != b {
		t.Fatalf("%s not deterministic: %v vs %v", name, a, b)
	}
	if _, err := NewKey(string(a.Key)); err != nil {
		t.Fatalf("%s(%q) produced invalid key %q: %v", name, in, a.Key, err)
	}
	if a.Known && a.Display == "" {
		t.Fatalf("%s(%q): known result without display name", name, in)
	}
	if !a.Known && a.Display != "" {
		t.Fatalf("%s(%q): unknown result with display name %q", name, in, a.Display)
	}
}

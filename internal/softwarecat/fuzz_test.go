// SPDX-License-Identifier: AGPL-3.0-or-later

package softwarecat

import (
	"strings"
	"testing"
)

func FuzzFromImage(f *testing.F) {
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
	f.Fuzz(func(t *testing.T, in string) {
		a := FromImage(in)
		b := FromImage(in)
		if a != b {
			t.Fatalf("FromImage not deterministic: %v vs %v", a, b)
		}
		if _, err := NewKey(string(a.Key)); err != nil {
			t.Fatalf("FromImage(%q) produced invalid key %q: %v", in, a.Key, err)
		}
		if len(a.Key) > maxKeyLen {
			t.Fatalf("FromImage(%q) produced key longer than %d: %q", in, maxKeyLen, a.Key)
		}
		if a.Known && a.Display == "" {
			t.Fatalf("FromImage(%q): known result without display name", in)
		}
		if !a.Known && a.Display != "" {
			t.Fatalf("FromImage(%q): unknown result with display name %q", in, a.Display)
		}
	})
}

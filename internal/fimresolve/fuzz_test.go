// SPDX-License-Identifier: AGPL-3.0-or-later

package fimresolve

import (
	"bytes"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/fimscan"
)

// FuzzResolve checks that Resolve never panics, always returns, and returns
// only absolute paths of at most fimscan.MaxPathBytes bytes without "."
// or ".." components. The lookup answers every path: names starting with
// "l" are symlinks to the fuzzed target, names ending in "f" are files, all
// others are directories.
func FuzzResolve(f *testing.F) {
	f.Add([]byte("/etc/ssh/l/../x"), []byte("/srv/a/b"))
	f.Add([]byte("/"), []byte("/"))
	f.Add([]byte("/l/l/l"), []byte("/l"))
	f.Add([]byte("/la/../../etc/"), []byte("../lb"))
	f.Add([]byte("/lf/."), []byte("f"))
	f.Add([]byte("etc"), []byte("/"))
	f.Add([]byte("/l//l/"), []byte(""))
	f.Add([]byte("//x/./l/../"), []byte("//l/"))
	f.Fuzz(func(t *testing.T, path, target []byte) {
		lookup := func(p []byte) (fimscan.Record, bool) {
			base := p[bytes.LastIndexByte(p, '/')+1:]
			switch {
			case bytes.HasPrefix(base, []byte("l")):
				return fimscan.Record{Path: p, Type: fimscan.TypeSymlink, Link: target}, true
			case bytes.HasSuffix(base, []byte("f")):
				return fimscan.Record{Path: p, Type: fimscan.TypeFile}, true
			default:
				return fimscan.Record{Path: p, Type: fimscan.TypeDir}, true
			}
		}
		got, err := Resolve(lookup, path)
		if err != nil {
			if got != nil {
				t.Fatalf("Resolve(%q) returned %q together with error %v", path, got, err)
			}
			return
		}
		if len(got) == 0 || got[0] != '/' {
			t.Fatalf("Resolve(%q) = %q, not absolute", path, got)
		}
		if len(got) > fimscan.MaxPathBytes {
			t.Fatalf("Resolve(%q) = %d bytes, above MaxPathBytes", path, len(got))
		}
		if len(got) > 1 {
			for _, c := range bytes.Split(got[1:], []byte("/")) {
				if len(c) == 0 || string(c) == "." || string(c) == ".." {
					t.Fatalf("Resolve(%q) = %q has an empty, . or .. component", path, got)
				}
			}
		}
	})
}

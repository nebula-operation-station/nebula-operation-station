// SPDX-License-Identifier: AGPL-3.0-or-later

package modules

import (
	"path"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/modulelock"
)

// A module pack is an uploaded archive from a module author: unpacking
// never panics, and what it accepts is a bounded set of regular files with
// plain relative names (review m103, finding 3).
func FuzzUnpack(f *testing.F) {
	f.Add(demo(f, "1.0.0", true))
	good := tgz(f, entry{name: "a/b.sh", body: []byte("echo hi\n")}, entry{name: "./c", body: []byte("x")})
	f.Add(good)
	f.Add(good[:len(good)/2])
	f.Add(tgz(f, entry{name: "a/../../b", body: []byte("x")}))
	f.Add(tgz(f, entry{name: "l", typ: '2'}))
	f.Add([]byte("not gzip"))
	f.Fuzz(func(t *testing.T, archive []byte) {
		files, err := unpack(archive)
		if err != nil {
			return
		}
		if len(files) > MaxEntries {
			t.Fatalf("%d files", len(files))
		}
		total := 0
		for name, b := range files {
			if name == "" || strings.HasPrefix(name, "/") || path.Clean(name) != name || name == ".." || strings.HasPrefix(name, "../") {
				t.Fatalf("name %q", name)
			}
			if len(b) > modulelock.MaxScript {
				t.Fatalf("%q has %d bytes", name, len(b))
			}
			total += len(b)
		}
		if total > MaxUnpacked {
			t.Fatalf("%d bytes unpacked", total)
		}
	})
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package backup

import (
	"bytes"
	"testing"
)

// An archive may come from anywhere: reading never panics and only
// returns files with backup paths.
func FuzzRead(f *testing.F) {
	var b bytes.Buffer
	_ = Write(&b, Manifest{Schemas: map[string]int{"server": 1, "executor": 1}}, []File{{Path: ServerDB, Data: []byte("x")}}, nil)
	f.Add(b.Bytes())
	f.Add([]byte("age-encryption.org/v1\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, files, err := Read(bytes.NewReader(data), nil)
		if err != nil {
			return
		}
		for _, fl := range files {
			if !ValidPath(fl.Path) {
				t.Fatalf("path %q", fl.Path)
			}
		}
	})
}

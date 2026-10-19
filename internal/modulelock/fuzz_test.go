// SPDX-License-Identifier: AGPL-3.0-or-later

package modulelock

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// A lock comes from a module author: parsing never panics, and whatever
// parses is exactly its canonical bytes and hashes to them.
func FuzzParse(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"format":"nebula-module-v1","name":"x"}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		_, h, err := Parse(raw)
		if err != nil {
			return
		}
		s := sha256.Sum256(raw)
		if h != hex.EncodeToString(s[:]) {
			t.Fatal("the hash is not the hash of the parsed bytes")
		}
	})
}

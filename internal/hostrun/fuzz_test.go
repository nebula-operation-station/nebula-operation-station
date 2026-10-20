// SPDX-License-Identifier: AGPL-3.0-or-later

package hostrun

import "testing"

// The result document is host output: the check never panics.
func FuzzOneJSONDocument(f *testing.F) {
	f.Add([]byte(`{"a":1}`))
	f.Add([]byte(`{"a":1,"a":2}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		_ = oneJSONDocument(b)
	})
}

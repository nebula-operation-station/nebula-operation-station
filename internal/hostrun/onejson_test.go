// SPDX-License-Identifier: AGPL-3.0-or-later

package hostrun

import "testing"

// A result document that names a top-level member twice is not one valid
// result: decoders disagree on which value wins, and a script could shadow
// the prelude's "exit" or "format".
func TestOneJSONDocumentRefusesDuplicateMembers(t *testing.T) {
	for doc, want := range map[string]bool{
		`{"format":"runbook-v1","exit":0}`:                           true,
		`{"format":"runbook-v1","exit":3,"result":{"a":1},"exit":0}`: false,
		`{"a":{"x":1,"x":2}}`:                                        true, // nested duplicates are the script's own result
		`[1,2]`:                                                      true,
		`{"a":1} {"b":2}`:                                            false,
		`{"format":"runbook-v1","phase":"done","exit":0,"result":{"v":1}` + "\n}": true,
	} {
		if got := oneJSONDocument([]byte(doc)); got != want {
			t.Errorf("%s: %v, want %v", doc, got, want)
		}
	}
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package dockerhost

import "testing"

// Results come from managed hosts: no parser panics on any input.
func FuzzParsers(f *testing.F) {
	f.Add([]byte(`{"format":"docker-list-v1","containers":[]}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`[]`))
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = ParseList(b)
		_, _ = ParseLogs(b)
		_, _ = ParseInspect(b)
		_, _ = ParseControl(b)
		_, _ = ParseComposeUpdate(b)
		_, _ = ParseImageUpdates(b)
	})
}

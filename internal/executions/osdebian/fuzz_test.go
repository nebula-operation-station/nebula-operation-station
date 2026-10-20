// SPDX-License-Identifier: AGPL-3.0-or-later

package osdebian

import "testing"

// Results come from managed hosts: no parser panics on any input.
func FuzzParsers(f *testing.F) {
	f.Add([]byte(`{"format":"apt-updates-v1","updates":[]}`))
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = ParseUpdates(b)
		_, _ = ParseInstall(b)
		_, _ = ParseUnits(b)
		_, _ = ParseServiceStatus(b)
	})
}

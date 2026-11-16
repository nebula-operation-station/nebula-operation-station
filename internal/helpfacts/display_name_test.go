// SPDX-License-Identifier: AGPL-3.0-or-later

package helpfacts

import (
	"reflect"
	"testing"
)

// TestCommonWordDoesNotSelectByDisplayName checks that a host whose display
// name is an ordinary word is not selected by every question that contains
// that word. Its untrusted text must not enter unrelated prompts. The host
// is still selected by its ID, and by a display name that is identifier-like.
func TestCommonWordDoesNotSelectByDisplayName(t *testing.T) {
	src := fakeSource{hosts: []Record{
		baseRecord("node-a", "is", "10.0.0.1"),
		baseRecord("node-b", "up", "10.0.0.2"),
		baseRecord("node-c", "Kube-1", "10.0.0.3"),
	}}
	vis := visibleOnly("node-a", "node-b", "node-c")

	tests := []struct {
		name     string
		question string
		want     []string
	}{
		{"common word in display name is not a literal match", "is the database up?", nil},
		{"identifier-like display name selects its host", "is kube-1 healthy?", []string{"node-c"}},
		{"id still selects a host", "is node-a healthy?", []string{"node-a"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := mustProject(t, request(tc.question, src, vis))
			if got := hostIDs(res); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("hosts = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestIdentifierLikeDisplayNameIsCaseFolded checks that an ASCII display
// name is matched case-insensitively when it contains a digit, hyphen,
// dot or underscore.
func TestIdentifierLikeDisplayNameIsCaseFolded(t *testing.T) {
	src := fakeSource{hosts: []Record{baseRecord("h2", "KUBE-1", "10.0.0.2")}}
	res := mustProject(t, request("is kube-1 healthy?", src, visibleOnly("h2")))
	if got := hostIDs(res); !reflect.DeepEqual(got, []string{"h2"}) {
		t.Fatalf("ASCII name hosts = %v, want [h2]", got)
	}
}

// TestUnicodeLookalikeIdentifierDisplayNameDoesNotMatch checks the
// look-alike rule for an identifier-like display name: U+212A KELVIN SIGN
// is not 'k' and must not match.
func TestUnicodeLookalikeIdentifierDisplayNameDoesNotMatch(t *testing.T) {
	src := fakeSource{hosts: []Record{baseRecord("h1", "Kube-1", "10.0.0.1")}}
	res := mustProject(t, request("is kube-1 healthy?", src, visibleOnly("h1")))
	if len(res.Hosts) != 0 {
		t.Fatalf("Unicode look-alike display name matched: %+v", res.Hosts)
	}
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package dockerhost

import "testing"

// The bound control script (G5b) stops with the code container_changed in a
// precheck result. ParseControl must keep it, so the server and the UI can
// tell a binding mismatch from other refusals without reading the reason.
func TestParseControlKeepsPrecheckCode(t *testing.T) {
	cases := []struct {
		name, line, code, reason string
	}{
		{"binding mismatch", `{"format":"docker-control-v1","phase":"precheck","code":"container_changed","reason":"the container ID or image no longer matches the approved binding"}`,
			"container_changed", "the container ID or image no longer matches the approved binding"},
		{"plain refusal has no code", `{"format":"docker-control-v1","phase":"precheck","reason":"Docker is not installed"}`,
			"", "Docker is not installed"},
		{"unknown code is dropped", `{"format":"docker-control-v1","phase":"precheck","code":"something_else","reason":"x"}`,
			"", "x"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := ParseControl([]byte(c.line))
			if err != nil {
				t.Fatal(err)
			}
			if got.Phase != "precheck" || got.Code != c.code || got.Reason != c.reason {
				t.Fatalf("got %+v, want code %q reason %q", got, c.code, c.reason)
			}
		})
	}
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package schedgrant

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
)

// manyTargets returns n distinct, valid targets.
func manyTargets(n int) []canonical.Target {
	out := make([]canonical.Target, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, canonical.Target{HostID: fmt.Sprintf("host%03d", i), HostKeyFingerprint: "SHA256:" + strings.Repeat("A", 43)})
	}
	return out
}

// manyActions returns n distinct, valid actions.
func manyActions(n int) []Action {
	out := make([]Action, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, Action{ActionID: fmt.Sprintf("pkg%03d.list", i), ModuleVersion: "1.0.0",
			ArtifactSHA256: strings.Repeat("a", 64), ParametersHash: strings.Repeat("b", 64)})
	}
	return out
}

// TestParseEnforcesTheLimitBoundaries pins each limit at its exact edge:
// the edge value is accepted and one step beyond it is refused.
func TestParseEnforcesTheLimitBoundaries(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Doc)
		accept bool
	}{
		{"targets at MaxTargets", func(d *Doc) { d.Targets = manyTargets(MaxTargets) }, true},
		{"targets at MaxTargets+1", func(d *Doc) { d.Targets = manyTargets(MaxTargets + 1) }, false},
		{"actions at MaxActions", func(d *Doc) { d.Actions = manyActions(MaxActions) }, true},
		{"actions at MaxActions+1", func(d *Doc) { d.Actions = manyActions(MaxActions + 1) }, false},
		{"interval exactly 15 min", func(d *Doc) { d.MinIntervalS = 900 }, true},
		{"interval 15 min minus 1 s", func(d *Doc) { d.MinIntervalS = 899 }, false},
		{"interval exactly 7 days", func(d *Doc) { d.MinIntervalS = 604800 }, true},
		{"interval 7 days plus 1 s", func(d *Doc) { d.MinIntervalS = 604801 }, false},
		{"expiry exactly now+1h", func(d *Doc) { d.ExpiryUnix = now.Add(time.Hour).Unix() }, true},
		{"expiry now+1h minus 1 s", func(d *Doc) { d.ExpiryUnix = now.Add(time.Hour - time.Second).Unix() }, false},
		{"expiry exactly now+90d", func(d *Doc) { d.ExpiryUnix = now.Add(90 * 24 * time.Hour).Unix() }, true},
		{"expiry now+90d plus 1 s", func(d *Doc) { d.ExpiryUnix = now.Add(90*24*time.Hour + time.Second).Unix() }, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := valid()
			tc.mutate(&d)
			_, _, _, err := Parse(raw(t, d), now)
			switch {
			case tc.accept && err != nil:
				t.Fatalf("refused: %v", err)
			case !tc.accept && !errors.Is(err, ErrInvalid):
				t.Fatalf("want ErrInvalid, got %v", err)
			}
		})
	}
}

// TestParseRefusesMalformedDocumentShapes covers input that is not exactly
// one grant document: bytes after it, a duplicate member, and a fractional
// expiry. Each must be refused with ErrInvalid.
func TestParseRefusesMalformedDocumentShapes(t *testing.T) {
	doc := string(raw(t, valid()))
	exp := valid().ExpiryUnix
	mutations := map[string]string{
		"object after the document": doc + " {}",
		"junk after the document":   doc + "x",
		"duplicate member":          strings.Replace(doc, `"id":`, `"grant":"read-schedule-v1","id":`, 1),
		"fractional expiry":         strings.Replace(doc, fmt.Sprintf(`"expiry_unix":%d`, exp), fmt.Sprintf(`"expiry_unix":%d.5`, exp), 1),
		"zero-fraction expiry":      strings.Replace(doc, fmt.Sprintf(`"expiry_unix":%d`, exp), fmt.Sprintf(`"expiry_unix":%d.0`, exp), 1),
	}
	for name, s := range mutations {
		t.Run(name, func(t *testing.T) {
			if s == doc {
				t.Fatal("mutation did not change the document")
			}
			if _, _, _, err := Parse([]byte(s), now); !errors.Is(err, ErrInvalid) {
				t.Fatalf("want ErrInvalid, got %v", err)
			}
		})
	}
}

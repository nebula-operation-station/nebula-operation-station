// SPDX-License-Identifier: AGPL-3.0-or-later

package opsnotes

import (
	"testing"
	"unicode/utf8"
)

// FuzzDecode feeds arbitrary bytes to the note decoder and the validator.
// Neither may panic, and an accepted note must respect the byte bounds and
// carry only valid UTF-8 text.
func FuzzDecode(f *testing.F) {
	f.Add([]byte(`{"kind":"fix","ref":"vu:host1:openssl","digest":"d1","summary":"s","steps":[{"action_id":"act.pkg.upgrade","host_id":"host1"}]}`))
	f.Add([]byte(`{"kind":"summary","ref":"2026-11-17","digest":"dig-2026-11-17","text":"Tag."}`))
	f.Add([]byte(`{"kind":"answer","ref":"q1","digest":"x","text":"\ud800"}`))
	f.Add([]byte(`{"kind":"fix","ref":"a","digest":"b","summary":"c","steps":[],"snapshot":"{}"}`))
	f.Add([]byte(`[]`))
	f.Add([]byte("\xff\xfe"))

	r := newFakeResolver()
	f.Fuzz(func(t *testing.T, data []byte) {
		d, err := Decode(data)
		if err != nil {
			return
		}
		if len(data) > MaxNoteBytes {
			t.Fatalf("accepted %d bytes, max %d", len(data), MaxNoteBytes)
		}
		if !utf8.Valid(data) {
			t.Fatalf("accepted invalid UTF-8")
		}
		// Validate must not panic on whatever decoded; if it accepts, every
		// text field is bounded and free of U+FFFD.
		if _, err := Validate(d, r); err == nil {
			for _, s := range []string{d.Summary, d.Text, d.Urgency} {
				if len(s) > MaxTextBytes || !utf8.ValidString(s) {
					t.Fatalf("accepted text of %d bytes or invalid UTF-8", len(s))
				}
			}
		}
	})
}

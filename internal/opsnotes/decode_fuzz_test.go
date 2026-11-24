// SPDX-License-Identifier: AGPL-3.0-or-later

package opsnotes

import (
	"testing"
	"unicode/utf8"
)

// checkAccepted fails the fuzz run if an accepted note carries a text field
// that checkFreeText refuses at its bound, an empty mitigation, or an ID
// that checkToken refuses.
func checkAccepted(t *testing.T, d Draft) {
	t.Helper()
	type textField struct {
		name, s string
		max     int
	}
	free := []textField{
		{"summary", d.Summary, MaxSummaryBytes},
		{"urgency", d.Urgency, MaxUrgencyBytes},
		{"text", d.Text, MaxTextBytes},
	}
	for _, m := range d.Mitigations {
		if m == "" {
			t.Fatalf("accepted an empty mitigation")
		}
		free = append(free, textField{"mitigation", m, MaxMitigationBytes})
	}
	for _, s := range d.Steps {
		free = append(free, textField{"why", s.Why, MaxStepWhyBytes})
		if err := checkToken("action_id", s.ActionID); err != nil {
			t.Fatalf("accepted an action ID: %v", err)
		}
		if err := checkToken("host_id", s.HostID); err != nil {
			t.Fatalf("accepted a host ID: %v", err)
		}
	}
	for _, f := range free {
		if f.s == "" {
			continue
		}
		if err := checkFreeText(f.name, f.s, f.max); err != nil {
			t.Fatalf("accepted %s: %v", f.name, err)
		}
	}
	for _, c := range d.Citations {
		if err := checkCitation("citation", c); err != nil {
			t.Fatalf("accepted a citation: %v", err)
		}
	}
}

// FuzzDecode feeds arbitrary bytes to the note decoder and the validator.
// Neither may panic, and an accepted note must respect the byte bounds and
// carry only valid UTF-8 text.
func FuzzDecode(f *testing.F) {
	f.Add([]byte(`{"kind":"fix","ref":"vu:host1:openssl","digest":"d1","summary":"s","steps":[{"action_id":"package.install_security","host_id":"host1"}]}`))
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
		// Validate must not panic on whatever decoded. If it accepts, every
		// text field must pass the same checks the validator applies, with
		// its own bound, and every ID the token check.
		if _, err := Validate(d, r); err == nil {
			checkAccepted(t, d)
		}
	})
}

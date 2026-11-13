// SPDX-License-Identifier: AGPL-3.0-or-later

package integritystore

import (
	"errors"
	"strings"
	"testing"
)

// TestAcceptRefusesActorsThatDisplayUnsafely: the actor name is stored and
// shown as text, so control, invisible and bidi characters are refused, as
// paths are escaped for display. The format characters are built from code
// points so that the source holds no invisible characters.
func TestAcceptRefusesActorsThatDisplayUnsafely(t *testing.T) {
	bidiOverride := string(rune(0x202E))
	zeroWidth := string(rune(0x200B))
	noBreak := string(rune(0x00A0))
	cases := []struct {
		name  string
		actor string
		ok    bool
	}{
		{"plain name", "ops-admin", true},
		{"ascii space", "Ana Schmidt", true},
		{"unicode letters", "Zoë Müller", true},
		{"empty", "", false},
		{"nul", "ops\x00admin", false},
		{"newline", "ops\nadmin", false},
		{"escape sequence", "ops\x1b[2Jadmin", false},
		{"bidi override", "ops" + bidiOverride + "admin", false},
		{"zero width space", "ops" + zeroWidth + "admin", false},
		{"no-break space", "ops" + noBreak + "admin", false},
		{"invalid utf-8", "ops\xffadmin", false},
		{"too long", strings.Repeat("a", MaxActorBytes+1), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clk := &clock{t: t0}
			s, _ := newTestStore(t, clk)
			subj := mustHost(t, "web-1")
			o := obs(ClassEtcChanged, "/etc/a")
			run := mustBegin(t, s, subj)
			if _, err := s.Record(t.Context(), run.ID, []Observation{o}); err != nil {
				t.Fatal(err)
			}
			finishComplete(t, s, run.ID)
			err := s.Accept(t.Context(), keyOf(subj, o), tc.actor)
			if tc.ok {
				if err != nil {
					t.Fatalf("Accept(%q): %v", tc.actor, err)
				}
				return
			}
			if !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("Accept(%q) = %v, want ErrInvalidInput", tc.actor, err)
			}
			if f, _ := s.Get(t.Context(), keyOf(subj, o)); f.State != StateOpen {
				t.Fatalf("refused Accept changed the state to %s", f.State)
			}
		})
	}
}

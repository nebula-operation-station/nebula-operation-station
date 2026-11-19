// SPDX-License-Identifier: AGPL-3.0-or-later

package ui_test

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/opsnotes"
)

// closedNoteBody has one step that would get a catalog button and one
// mitigation, so a read-only card is compared with a live one.
func closedNoteBody() opsnotes.Body {
	return opsnotes.Body{
		Steps: []opsnotes.StepInput{
			{ActionID: "package.install_security", HostID: "h1", Why: "patch"},
			{ActionID: "docker.update", HostID: "h1", Why: "container"},
		},
		Mitigations: []string{"restrict the port at the firewall"},
	}
}

// A dismissed or superseded note is still reachable from an old link. Its
// detail page shows the content read-only: a marker, no step buttons, no
// dismiss form. A live note keeps both.
func TestAssistantClosedNoteDetailIsReadOnly(t *testing.T) {
	tests := []struct {
		name       string
		dismissed  bool
		superseded bool
		marker     string
	}{
		{name: "dismissed", dismissed: true, marker: "dismissed"},
		{name: "superseded", superseded: true, marker: "superseded"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			note := fixNote(1, time.Unix(0, 0), snapshotOpenSSL, closedNoteBody())
			note.Dismissed = tt.dismissed
			note.Superseded = tt.superseded
			store := &fakeOpsStore{notes: []opsnotes.Note{note}}
			h := assistantServer(t, assistantOps(store, newCatalog()), assistantUser{"root"})

			rec := doAssistant(t, h, http.MethodGet, "/assistant/ops/notes/1", nil)
			if rec.Code != http.StatusOK {
				t.Fatalf("detail: %d, want 200", rec.Code)
			}
			body := rec.Body.String()
			if !strings.Contains(body, "Read only") || !strings.Contains(body, tt.marker) {
				t.Errorf("closed note has no read-only marker naming %q", tt.marker)
			}
			for _, forbidden := range []string{"Open form", "Open container update", "/assistant/ops/notes/1/dismiss", `class="button"`} {
				if strings.Contains(body, forbidden) {
					t.Errorf("closed note contains %q; it must have no action", forbidden)
				}
			}
			if !strings.Contains(body, "patch") || !strings.Contains(body, "restrict the port at the firewall") {
				t.Error("closed note lost its content; it must be shown read-only")
			}
		})
	}
}

// Control: the same note without a close flag keeps its buttons, so the
// read-only test above cannot pass by accident.
func TestAssistantOpenNoteDetailKeepsActions(t *testing.T) {
	store := &fakeOpsStore{notes: []opsnotes.Note{fixNote(1, time.Unix(0, 0), snapshotOpenSSL, closedNoteBody())}}
	h := assistantServer(t, assistantOps(store, newCatalog()), assistantUser{"root"})
	body := doAssistant(t, h, http.MethodGet, "/assistant/ops/notes/1", nil).Body.String()
	for _, want := range []string{"Open form", "Open container update", "/assistant/ops/notes/1/dismiss"} {
		if !strings.Contains(body, want) {
			t.Errorf("open note lacks %q", want)
		}
	}
	if strings.Contains(body, "Read only") {
		t.Error("open note is marked read only")
	}
}

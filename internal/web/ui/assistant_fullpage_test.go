// SPDX-License-Identifier: AGPL-3.0-or-later

package ui_test

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/opsnotes"
)

// A full page of the panel (no htmx) is the panel itself. The layout must
// not add the inline or side Assistant section around it, because that
// section loads a second panel with the same ids.
func TestAssistantFullPageHasExactlyOnePanel(t *testing.T) {
	store := &fakeOpsStore{notes: []opsnotes.Note{fixNote(1, time.Unix(0, 0), snapshotOpenSSL, opsnotes.Body{})}}
	h := assistantServer(t, assistantOps(store, newCatalog()), assistantUser{"root"})
	for _, path := range []string{"/assistant/panel", "/assistant/help", "/assistant/ops"} {
		t.Run(path, func(t *testing.T) {
			rec := doAssistant(t, h, http.MethodGet, path, nil)
			if rec.Code != http.StatusOK {
				t.Fatalf("GET %s: %d, want 200", path, rec.Code)
			}
			body := rec.Body.String()
			if !strings.Contains(body, "<html") {
				t.Fatalf("GET %s without htmx should be a full page", path)
			}
			for _, id := range []string{`id="assistant-panel"`, `id="assistant-body"`} {
				if n := strings.Count(body, id); n != 1 {
					t.Errorf("%s occurs %d times, want 1", id, n)
				}
			}
			for _, unwanted := range []string{`id="assistant-root"`, `class="assistant-open"`, `hx-get="/assistant/panel"`, `hx-trigger="load"`} {
				if strings.Contains(body, unwanted) {
					t.Errorf("full panel page contains %s; the layout must not add a second panel", unwanted)
				}
			}
		})
	}
}

// The Help page keeps its own inline Assistant section: the full-page
// suppression applies to the panel pages only.
func TestAssistantHelpPageStillShowsInlinePanelOnce(t *testing.T) {
	h := assistantServer(t, assistantOps(&fakeOpsStore{}, newCatalog()), assistantUser{""})
	body := doAssistant(t, h, http.MethodGet, "/help", nil).Body.String()
	if n := strings.Count(body, `id="assistant-root"`); n != 1 {
		t.Errorf("/help has %d assistant-root containers, want 1", n)
	}
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package ui

import (
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestRenderErrorAnswers500AndWritesNothing verifies that a template
// execution failure aborts the response with 500 before any partial
// output is written. The broken template emits text before it fails, so
// a handler that streams to the ResponseWriter would leave a partial
// body behind.
func TestRenderErrorAnswers500AndWritesNothing(t *testing.T) {
	broken := template.Must(template.New("").Parse(
		`{{define "layout"}}partial output {{.MissingField.Method}}{{end}}`))
	h := &Handler{
		pages: map[string]*template.Template{"dashboard": broken},
		log:   slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	rec := httptest.NewRecorder()
	h.handleDashboard(rec, httptest.NewRequest(http.MethodGet, "/dashboard", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status %d, want 500", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "partial output") {
		t.Fatalf("partial page written before the render error: %q", rec.Body.String())
	}
}

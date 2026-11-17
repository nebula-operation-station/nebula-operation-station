// SPDX-License-Identifier: AGPL-3.0-or-later

package ui

// The Assistant panel (ADR 0016 D11, ADR 0014 D1): one panel with two tabs.
//
//   - Help ("Hilfe") is shown to every logged-in user and reads only the
//     embedded handbook (help.go). It never reads notes.
//   - Ops is shown to admins only. Its handlers live in assistant_ops.go
//     and read the notes store; they answer 404 to everyone else.
//
// The panel shell is loaded lazily: the side panel fetches
// /assistant/panel when it is first opened, so no page loads hidden
// content. On /help the shell is rendered inline and loads at once.
// This file imports no notes or vulnerability store (import boundary,
// assistant_boundary_test.go).

import (
	"bytes"
	"context"
	"fmt"
	"html/template"
	"net/http"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/nebula-operation-station/nebula-operation-station/web/templates"
)

// assistantTab is one tab of the panel.
type assistantTab struct {
	Label  string
	URL    string
	Active bool
}

// assistantPanelView is what assistant.html shows.
type assistantPanelView struct {
	// Tabs is the tab bar: Help always, Ops only for admins.
	Tabs []assistantTab
}

// assistantFragmentTemplate parses the panel partials without a layout.
var assistantFragmentTemplate = sync.OnceValues(func() (*template.Template, error) {
	t, err := template.New("").Funcs(template.FuncMap{"timeTag": timeTag}).ParseFS(templates.FS, "assistant.html", "assistant_ops_card.html")
	if err != nil {
		return nil, fmt.Errorf("ui: parse template assistant: %w", err)
	}
	return t, nil
})

// assistantPageTemplate parses the layout and the full-page detail view.
var assistantPageTemplate = sync.OnceValues(func() (*template.Template, error) {
	t, err := template.New("").Funcs(template.FuncMap{"timeTag": timeTag}).ParseFS(templates.FS, "layout.html", "assistant_ops_note.html", "assistant_ops_card.html")
	if err != nil {
		return nil, fmt.Errorf("ui: parse template assistant page: %w", err)
	}
	return t, nil
})

// registerAssistant adds the panel routes. Ops routes are registered even
// without Ops configured: they then answer 404 like for a non-admin.
func (h *Handler) registerAssistant(mux *http.ServeMux) {
	mux.HandleFunc("GET /assistant/panel", h.handleAssistantPanel)
	mux.HandleFunc("GET /assistant/help", h.handleAssistantHelp)
	mux.HandleFunc("GET /assistant/ops", h.handleAssistantOps)
	mux.HandleFunc("GET /assistant/ops/notes/{id}", h.handleAssistantOpsNote)
	mux.HandleFunc("POST /assistant/ops/notes/{id}/dismiss", h.handleAssistantOpsDismiss)
}

// handleAssistantPanel renders the panel shell with the Help tab selected.
// The Ops tab appears in the markup only for an admin.
func (h *Handler) handleAssistantPanel(w http.ResponseWriter, r *http.Request) {
	if !helpMethodOK(w, r) {
		return
	}
	v := &assistantPanelView{Tabs: []assistantTab{{Label: "Help", URL: "/assistant/help", Active: true}}}
	if h.assistantOpsAllowed(r) {
		v.Tabs = append(v.Tabs, assistantTab{Label: "Ops", URL: "/assistant/ops"})
	}
	// The body is loaded by a second request to the active tab's URL, so
	// the shell itself carries no handbook data and reads no notes.
	h.renderAssistantFragment(w, "assistant_panel", v)
}

// handleAssistantHelp renders the Help tab body: the handbook search and
// the chapter list. It is the Help backend and reads no notes.
func (h *Handler) handleAssistantHelp(w http.ResponseWriter, r *http.Request) {
	if !helpMethodOK(w, r) {
		return
	}
	book, err := loadHelpBook()
	if err != nil {
		h.log.Error("assistant: load handbook", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	v := helpSearchView(r, book)
	h.renderAssistantFragment(w, "assistant_help", v)
}

// helpSearchView builds the Help tab view from the request's query.
// It mirrors the search of /help (help.go).
func helpSearchView(r *http.Request, book *helpBook) *helpView {
	v := &helpView{}
	if q, ok := r.URL.Query()["q"]; ok && len(q) > 0 {
		v.Searched = true
		v.Query = q[0]
		if len(v.Query) > maxHelpQueryBytes || !utf8.ValidString(v.Query) {
			v.Invalid = true
			v.Query = ""
		} else {
			v.Results, v.Truncated = book.search(v.Query)
		}
	}
	return v
}

// renderAssistantFragment executes one named partial of assistant.html.
func (h *Handler) renderAssistantFragment(w http.ResponseWriter, name string, data any) {
	set, err := assistantFragmentTemplate()
	if err != nil {
		h.log.Error("assistant: template", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	var buf bytes.Buffer
	if err := set.ExecuteTemplate(&buf, name, data); err != nil {
		h.log.Error("assistant: render", "template", name, "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if _, err := w.Write(buf.Bytes()); err != nil {
		h.log.Debug("assistant: write", "template", name, "error", err)
	}
}

// assistantOpsAllowed reports whether the request may see the Ops tab and
// its routes: Ops is configured, there is a logged-in user, and that user
// is an admin. A failing admin check denies.
func (h *Handler) assistantOpsAllowed(r *http.Request) bool {
	if h.assistantOps == nil {
		return false
	}
	user, ok := h.assistantOps.user(r)
	if !ok {
		return false
	}
	ctx, cancel := context.WithTimeout(r.Context(), assistantCallTimeout)
	defer cancel()
	admin, err := h.assistantOps.IsAdmin(ctx, user)
	if err != nil {
		h.log.Error("assistant: admin check", "error", err)
		return false
	}
	return admin
}

// assistantCallTimeout bounds the admin check and the notes reads of one
// request.
const assistantCallTimeout = 5 * time.Second

// assistantPageData is the layout data of the Ops detail page.
func (h *Handler) assistantPageData(r *http.Request, title string) pageData {
	data := pageData{Title: title, Active: "assistant", Content: "assistant_ops_note"}
	data.Theme = themeFromRequest(r)
	data.NavCollapsed = navStateFromRequest(r) == navCollapsed
	data.PVENav = h.pve != nil
	data.DeployEnabled = h.deploy != nil && h.pve != nil && h.pveRemotes != nil
	if h.builtinTrust != nil {
		data.BuiltinTrust = h.builtinTrust.get(r.Context())
	}
	return data
}

// renderAssistantPage renders a full page inside the layout.
func (h *Handler) renderAssistantPage(w http.ResponseWriter, data any) {
	set, err := assistantPageTemplate()
	if err != nil {
		h.log.Error("assistant: page template", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	var buf bytes.Buffer
	if err := set.ExecuteTemplate(&buf, "layout", data); err != nil {
		h.log.Error("assistant: render page", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if _, err := w.Write(buf.Bytes()); err != nil {
		h.log.Debug("assistant: write page", "error", err)
	}
}

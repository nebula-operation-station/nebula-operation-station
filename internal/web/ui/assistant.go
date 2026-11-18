// SPDX-License-Identifier: AGPL-3.0-or-later

package ui

// The Assistant panel (ADR 0016 D11, ADR 0014 D1): one panel with two tabs.
//
//   - Help ("Hilfe") is shown to every logged-in user. Its view is built by
//     internal/web/ui/assistanthelp from the embedded handbook (help.go) and
//     plain request values. It never reads notes.
//   - Ops is shown to admins only. Its handlers live in assistant_ops.go
//     and read the notes store; they answer 404 to everyone else.
//
// The Help routes in this file are a thin adapter: they call
// assistanthelp.Build and never touch h.assistantOps. The boundary tests in
// assistant_boundary_test.go and assistanthelp/boundary_test.go keep it so.
//
// Every panel route answers with the panel fragment when the request comes
// from htmx (HX-Request: true) and with the full layout page otherwise. A
// full page is the panel itself: the layout adds no second Assistant section
// (pageData.AssistantPanel). The side panel fetches /assistant/panel when it
// is first opened.

import (
	"bytes"
	"context"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui/assistanthelp"
	"github.com/nebula-operation-station/nebula-operation-station/web/templates"
)

// Tab keys of the panel.
const (
	assistantTabHelp = "help"
	assistantTabOps  = "ops"
)

// assistantTab is one tab of the panel.
type assistantTab struct {
	Label  string
	URL    string
	Active bool
}

// assistantPanelView is what assistant.html shows. Help and Ops are set
// only for the active tab, so the Ops body is never in the markup of a
// Help response.
type assistantPanelView struct {
	// Tabs is the tab bar: Help always, Ops only for admins.
	Tabs []assistantTab
	// Help is the Help body when the Help tab is active.
	Help *assistanthelp.View
	// Ops is the Ops body when the Ops tab is active.
	Ops *assistantOpsView
}

// assistantPanelPage is the layout data of a full-page panel.
type assistantPanelPage struct {
	pageData
	Panel *assistantPanelView
}

// assistantFragmentTemplate parses the panel partials without a layout.
var assistantFragmentTemplate = sync.OnceValues(func() (*template.Template, error) {
	return parseAssistantSet("assistant", "assistant.html", "assistant_ops_card.html")
})

// assistantPanelPageTemplate parses the layout with the full-page panel.
var assistantPanelPageTemplate = sync.OnceValues(func() (*template.Template, error) {
	return parseAssistantSet("assistant panel page", "layout.html", "assistant.html", "assistant_ops_card.html", "assistant_page.html")
})

// assistantNotePageTemplate parses the layout and the detail page of one card.
var assistantNotePageTemplate = sync.OnceValues(func() (*template.Template, error) {
	return parseAssistantSet("assistant note page", "layout.html", "assistant.html", "assistant_ops_card.html", "assistant_ops_note.html")
})

// parseAssistantSet parses files from the embedded templates.
func parseAssistantSet(what string, files ...string) (*template.Template, error) {
	t, err := template.New("").Funcs(template.FuncMap{"timeTag": timeTag}).ParseFS(templates.FS, files...)
	if err != nil {
		return nil, fmt.Errorf("ui: parse template %s: %w", what, err)
	}
	return t, nil
}

// assistantTabs returns the tab bar with active marked. Ops is listed only
// when showOps is true.
func assistantTabs(active string, showOps bool) []assistantTab {
	tabs := []assistantTab{{Label: "Help", URL: "/assistant/help", Active: active == assistantTabHelp}}
	if showOps {
		tabs = append(tabs, assistantTab{Label: "Ops", URL: "/assistant/ops", Active: active == assistantTabOps})
	}
	return tabs
}

// assistantBook adapts the rendered handbook (help.go) to the Book the Help
// backend reads. It is the only thing the Help routes hand to that backend.
type assistantBook struct {
	b *helpBook
}

// Chapters returns the handbook's table of contents in reading order.
func (a assistantBook) Chapters() []assistanthelp.Chapter {
	out := make([]assistanthelp.Chapter, 0, len(a.b.order))
	for _, c := range a.b.order {
		out = append(out, assistanthelp.Chapter{Title: c.title, URL: c.url})
	}
	return out
}

// Search returns the handbook matches of q and whether more matched.
func (a assistantBook) Search(q string) ([]assistanthelp.Result, bool) {
	matches, truncated := a.b.search(q)
	out := make([]assistanthelp.Result, 0, len(matches))
	for _, m := range matches {
		out = append(out, assistanthelp.Result{Section: m.Section, Page: m.Page, URL: m.URL})
	}
	return out, truncated
}

// handleAssistantPanel renders the panel shell with the Help tab selected
// and its chapter list. It is the target of the side panel and of /help.
func (h *Handler) handleAssistantPanel(w http.ResponseWriter, r *http.Request) {
	h.serveAssistantHelp(w, r, false)
}

// handleAssistantHelp renders the Help tab with the search of the query.
func (h *Handler) handleAssistantHelp(w http.ResponseWriter, r *http.Request) {
	h.serveAssistantHelp(w, r, true)
}

// serveAssistantHelp builds the Help view and writes it. The Ops tab is
// listed for an admin by assistantOpsAllowed, which reads no notes.
func (h *Handler) serveAssistantHelp(w http.ResponseWriter, r *http.Request, withSearch bool) {
	if !helpMethodOK(w, r) {
		return
	}
	book, err := loadHelpBook()
	if err != nil {
		h.log.Error("assistant: load handbook", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	v, err := assistanthelp.Build(assistantBook{b: book}, r.URL.Query(), withSearch)
	if err != nil {
		h.log.Error("assistant: help view", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	view := &assistantPanelView{Tabs: assistantTabs(assistantTabHelp, h.assistantOpsAllowed(r)), Help: v}
	writeAssistantPanel(w, r, h.log, h.assistantPageData, view)
}

// writeAssistantPanel answers with the panel fragment for htmx and with the
// full layout page otherwise. The response depends on HX-Request, so it is
// marked as varying on it. The full page is marked as the panel itself, so
// the layout does not add a second Assistant section.
func writeAssistantPanel(w http.ResponseWriter, r *http.Request, log *slog.Logger, page func(*http.Request, string) pageData, v *assistantPanelView) {
	w.Header().Add("Vary", "HX-Request")
	if r.Header.Get("HX-Request") == "true" {
		renderAssistantTemplate(w, log, assistantFragmentTemplate, "assistant_panel", v)
		return
	}
	// Active "assistant" makes the layout skip its inline and side sections:
	// the full page is the panel, so it holds exactly one (ADR 0016 D11).
	pd := page(r, "Assistant")
	pd.Active = "assistant"
	renderAssistantTemplate(w, log, assistantPanelPageTemplate, "layout", assistantPanelPage{pageData: pd, Panel: v})
}

// renderAssistantTemplate executes one named template of set into w. A
// failure is logged and answered with 500; nothing partial is written.
func renderAssistantTemplate(w http.ResponseWriter, log *slog.Logger, set func() (*template.Template, error), name string, data any) {
	t, err := set()
	if err != nil {
		log.Error("assistant: template", "template", name, "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, name, data); err != nil {
		log.Error("assistant: render", "template", name, "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if _, err := w.Write(buf.Bytes()); err != nil {
		log.Debug("assistant: write", "template", name, "error", err)
	}
}

// assistantOpsAllowed reports whether the request may see the Ops tab and
// its routes: Ops is configured, there is a logged-in user, and that user
// is an admin. A failing admin check denies. It reads no notes.
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

// assistantPageData is the layout data of a full page of the panel.
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

// registerAssistant adds the panel routes. The Help routes read the
// handbook only; the Ops routes are Handler methods that hold the notes
// store. Ops routes are registered even without Ops configured: they then
// answer 404 like for a non-admin.
func (h *Handler) registerAssistant(mux *http.ServeMux) {
	mux.HandleFunc("GET /assistant/panel", h.handleAssistantPanel)
	mux.HandleFunc("GET /assistant/help", h.handleAssistantHelp)
	mux.HandleFunc("GET /assistant/ops", h.handleAssistantOps)
	mux.HandleFunc("GET /assistant/ops/notes/{id}", h.handleAssistantOpsNote)
	mux.HandleFunc("GET /assistant/ops/questions", h.handleAssistantOpsQuestions)
	mux.HandleFunc("POST /assistant/ops/questions", h.handleAssistantOpsAsk)
	mux.HandleFunc("POST /assistant/ops/notes/{id}/dismiss", h.handleAssistantOpsDismiss)
}

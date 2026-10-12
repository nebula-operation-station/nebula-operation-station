// SPDX-License-Identifier: AGPL-3.0-or-later

// Package ui serves the Nebula web UI shell: server-rendered Go
// templates with htmx, no Node build (docs/spec/14).
//
// Pages are rendered with html/template only, and all JavaScript and CSS
// comes from embedded static files, so the strict CSP applied by
// internal/web/middleware (script-src 'self', style-src 'self', no inline
// scripts) holds without any template exception.
//
// Everything a managed host provides (host names, later facts and logs)
// is untrusted input: it is validated by the caller and rendered as text
// only, which html/template escaping enforces here.
package ui

import (
	"context"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"time"

	"google.golang.org/grpc"

	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/middleware"
	"github.com/nebula-operation-station/nebula-operation-station/web/static"
	"github.com/nebula-operation-station/nebula-operation-station/web/templates"
)

// statusCallTimeout bounds the GetStatus call made while rendering the
// dashboard.
const statusCallTimeout = 5 * time.Second

// StatusProvider returns the executor's status.
//
// executorclient.Client satisfies this interface, so the dashboard uses
// the existing GetStatus RPC. The interface keeps the handler testable
// without a live executor.
type StatusProvider interface {
	GetStatus(ctx context.Context, in *pb.GetStatusRequest, opts ...grpc.CallOption) (*pb.GetStatusResponse, error)
}

// Options configure the UI handler.
type Options struct {
	// PublicOrigin is the exact Origin value for this deployment, e.g.
	// "https://nebula.example.org". Required: it is passed to the
	// security middleware, which fails closed without it.
	PublicOrigin string
	// Status provides the executor status for the dashboard. Nil means
	// the dashboard reports the executor as unavailable.
	Status StatusProvider
	// HostNames returns the managed host names shown on the dashboard.
	// Nil means no hosts. Values are untrusted host data and are
	// rendered as text only.
	HostNames func(ctx context.Context) []string
}

// Handler renders the UI pages and serves the embedded static assets.
type Handler struct {
	publicOrigin string
	// pages maps a content name to the parsed template set (layout +
	// that page), so every page can define its own "content" block.
	pages     map[string]*template.Template
	staticFS  fs.FS
	status    StatusProvider
	hostNames func(ctx context.Context) []string
}

// New parses the embedded templates and builds a Handler.
func New(o Options) (*Handler, error) {
	if o.PublicOrigin == "" {
		return nil, errors.New("ui: PublicOrigin is required")
	}
	pages := make(map[string]*template.Template, len(pageFiles))
	for name, file := range pageFiles {
		set, err := template.New("").ParseFS(templates.FS, "layout.html", file)
		if err != nil {
			return nil, fmt.Errorf("ui: parse template %s: %w", name, err)
		}
		pages[name] = set
	}
	staticFS, err := fs.Sub(static.FS, ".")
	if err != nil {
		return nil, fmt.Errorf("ui: static assets: %w", err)
	}
	return &Handler{
		publicOrigin: o.PublicOrigin,
		pages:        pages,
		staticFS:     staticFS,
		status:       o.Status,
		hostNames:    o.HostNames,
	}, nil
}

// pageFiles maps a content name to the template file that defines its
// "content" block.
var pageFiles = map[string]string{
	"dashboard": "dashboard.html",
	"empty":     "empty.html",
}

// Handler returns the UI's http.Handler without the security middleware
// chain. Use Server for a ready-to-serve *http.Server.
func (h *Handler) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", h.handleRoot)
	mux.HandleFunc("/dashboard", h.handleDashboard)
	for _, p := range emptyPages {
		path := p.path
		mux.HandleFunc(path, h.handleEmpty(path))
	}
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(h.staticFS))))
	return mux
}

// Server wraps the UI handler with the security middleware chain
// (response headers, origin check, body limit) and the server timeouts.
func (h *Handler) Server() (*http.Server, error) {
	return middleware.NewServer(middleware.Options{PublicOrigin: h.publicOrigin}, h.Handler())
}

// emptyPages are the shell pages that have no content yet.
var emptyPages = []struct {
	path  string
	title string
}{
	{"/inventory", "Inventory"},
	{"/network", "Network"},
	{"/operations", "Operations"},
	{"/runbooks", "Runbooks / Modules"},
	{"/history", "History"},
	{"/settings", "Settings"},
}

// pageData is the data passed to the layout template.
type pageData struct {
	// Title is the page title, shown in <title> and <h1>.
	Title string
	// Active marks the current navigation item.
	Active string
	// Content is the content template name to render inside the layout.
	Content string
	// Dashboard only:
	Status      *statusView
	StatusError string
	Hosts       []string
}

// statusView is the dashboard's executor status, pre-formatted for
// display.
type statusView struct {
	// LockText is "Locked" or "Unlocked".
	LockText string
	// Session is "none" or "active, expires <UTC time>".
	Session string
}

func (h *Handler) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

func (h *Handler) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	data := pageData{Title: "Dashboard", Active: "dashboard", Content: "dashboard"}
	if h.status != nil {
		ctx, cancel := context.WithTimeout(r.Context(), statusCallTimeout)
		defer cancel()
		st, err := h.status.GetStatus(ctx, &pb.GetStatusRequest{})
		if err != nil {
			data.StatusError = err.Error()
		} else {
			data.Status = viewStatus(st)
		}
	} else {
		data.StatusError = "executor not configured"
	}
	if h.hostNames != nil {
		data.Hosts = h.hostNames(r.Context())
	}
	h.render(w, data)
}

func (h *Handler) handleEmpty(path string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var title string
		for _, p := range emptyPages {
			if p.path == path {
				title = p.title
			}
		}
		h.render(w, pageData{Title: title, Active: path[1:], Content: "empty"})
	}
}

// viewStatus formats a GetStatusResponse for the dashboard.
func viewStatus(st *pb.GetStatusResponse) *statusView {
	lock := "Locked"
	if st.GetUnlocked() {
		lock = "Unlocked"
	}
	session := "none"
	if st.GetPrivilegedSessionActive() {
		exp := time.Unix(st.GetPrivilegedSessionExpiryUnix(), 0).UTC().Format("2006-01-02 15:04:05 MST")
		session = "active, expires " + exp
	}
	return &statusView{LockText: lock, Session: session}
}

func (h *Handler) render(w http.ResponseWriter, data pageData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	set, ok := h.pages[data.Content]
	if !ok {
		http.Error(w, "internal error: unknown page", http.StatusInternalServerError)
		return
	}
	if err := set.ExecuteTemplate(w, "layout", data); err != nil {
		// The response headers are already sent; the connection is
		// aborted by the client. There is no logger here and the error
		// is not actionable, so this is the end of the request.
	}
}

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
	"bytes"
	"context"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
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
	// Log receives executor status errors (the page itself only shows
	// "Executor unavailable"). Nil means slog.Default().
	Log *slog.Logger
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
	log       *slog.Logger
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
	log := o.Log
	if log == nil {
		log = slog.Default()
	}
	return &Handler{
		publicOrigin: o.PublicOrigin,
		pages:        pages,
		staticFS:     staticFS,
		status:       o.Status,
		hostNames:    o.HostNames,
		log:          log,
	}, nil
}

// pageFiles maps a content name to the template file that defines its
// "content" block.
var pageFiles = map[string]string{
	"dashboard": "dashboard.html",
	"empty":     "empty.html",
	"login":     "login.html",
	"setup":     "setup.html",
}

// Handler returns the UI's http.Handler without the security middleware
// chain. Use Server for a ready-to-serve *http.Server.
func (h *Handler) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", h.handleRoot)
	mux.HandleFunc("/dashboard", h.handleDashboard)
	// The login and setup pages only render; the endpoints they call and
	// the session check live in internal/web/auth.
	mux.HandleFunc("/login", h.handleBare("Log in", "login", "login.js"))
	mux.HandleFunc("/setup", h.handleBare("Register a security key", "setup", "setup.js"))
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
	// Bare pages (login, setup) are shown without the navigation.
	Bare bool
	// Scripts are extra files under /static/ loaded after htmx.
	Scripts []string
	// Dashboard only:
	Status *statusView
	Hosts  []string
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
	data := pageData{Title: "Dashboard", Active: "dashboard", Content: "dashboard", Scripts: []string{"webauthn.js", "dashboard.js"}}
	if h.status != nil {
		ctx, cancel := context.WithTimeout(r.Context(), statusCallTimeout)
		defer cancel()
		st, err := h.status.GetStatus(ctx, &pb.GetStatusRequest{})
		if err != nil {
			// The page shows a fixed "Executor unavailable" message;
			// the error detail (which can contain paths or other
			// internal state) goes to the log only.
			h.log.Error("executor status", "error", err)
		} else {
			data.Status = viewStatus(st)
		}
	}
	if h.hostNames != nil {
		data.Hosts = h.hostNames(r.Context())
	}
	h.render(w, data)
}

func (h *Handler) handleBare(title, content, script string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		h.render(w, pageData{Title: title, Content: content, Bare: true, Scripts: []string{"webauthn.js", script}})
	}
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
	set, ok := h.pages[data.Content]
	if !ok {
		http.Error(w, "internal error: unknown page", http.StatusInternalServerError)
		return
	}
	// Render into a buffer first so an execution error answers 500
	// without any partial page having been written.
	var buf bytes.Buffer
	if err := set.ExecuteTemplate(&buf, "layout", data); err != nil {
		h.log.Error("render page", "page", data.Content, "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if _, err := w.Write(buf.Bytes()); err != nil {
		// The client went away; nothing left to do.
		h.log.Debug("write page", "page", data.Content, "error", err)
	}
}

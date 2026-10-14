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
	"strconv"
	"time"

	"google.golang.org/grpc"

	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/middleware"
	"github.com/nebula-operation-station/nebula-operation-station/web/static"
	"github.com/nebula-operation-station/nebula-operation-station/web/templates"
)

// statusCallTimeout bounds the GetStatus call made while rendering the
// dashboard.
const statusCallTimeout = 5 * time.Second

// inventoryCallTimeout bounds the Hosts and HostKeys calls made while
// rendering the inventory page.
const inventoryCallTimeout = 5 * time.Second

// defaultSSHPort is shown for endpoints that omit their port (the
// inventory stores it explicitly, but a zero port means the default).
const defaultSSHPort = 22

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
	// Hosts returns the managed hosts for the inventory page. Nil means
	// no hosts. Values are untrusted host data and are rendered as text
	// only. An error makes the page show "Inventory unavailable"; the
	// error detail goes to the log only.
	Hosts func(ctx context.Context) ([]inventory.Host, error)
	// HostKeys returns the executor's host key pins for the inventory
	// page. Nil (or an error) makes the SSH key column show "executor
	// unavailable"; the error detail goes to the log only.
	HostKeys func(ctx context.Context) ([]*pb.HostKeyPin, error)
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
	hosts     func(ctx context.Context) ([]inventory.Host, error)
	hostKeys  func(ctx context.Context) ([]*pb.HostKeyPin, error)
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
		hosts:        o.Hosts,
		hostKeys:     o.HostKeys,
		log:          log,
	}, nil
}

// pageFiles maps a content name to the template file that defines its
// "content" block.
var pageFiles = map[string]string{
	"dashboard": "dashboard.html",
	"empty":     "empty.html",
	"inventory": "inventory.html",
	"login":     "login.html",
	"setup":     "setup.html",
}

// Handler returns the UI's http.Handler without the security middleware
// chain. Use Server for a ready-to-serve *http.Server.
func (h *Handler) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", h.handleRoot)
	mux.HandleFunc("/dashboard", h.handleDashboard)
	mux.HandleFunc("/inventory", h.handleInventory)
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
	// Inventory page:
	// InventoryUnavailable is true when the hosts could not be listed;
	// the page then shows "Inventory unavailable".
	InventoryUnavailable bool
	// Inventory is the table of managed hosts, in ID order.
	Inventory []hostView
}

// statusView is the dashboard's executor status, pre-formatted for
// display.
type statusView struct {
	// LockText is "Locked" or "Unlocked".
	LockText string
	// Session is "none" or "active, expires <UTC time>".
	Session string
}

// hostView is one row of the inventory table, pre-formatted for
// display. Every field is untrusted host data, rendered as text only.
type hostView struct {
	// ID is the host ID.
	ID string
	// DisplayName is the host's display name.
	DisplayName string
	// Environment is DEV, QA or PROD.
	Environment string
	// Criticality is LOW, MEDIUM, HIGH or CRITICAL.
	Criticality string
	// Endpoints are "address:port" strings in stored order.
	Endpoints []string
	// KeyStatus is the host's SSH key status: "pinned <key type>
	// <fingerprint>", "BLOCKED (host key mismatch)", "not enrolled" or
	// "executor unavailable".
	KeyStatus string
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

func (h *Handler) handleInventory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	data := pageData{Title: "Inventory", Active: "inventory", Content: "inventory"}
	if h.hosts == nil {
		h.render(w, data)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), inventoryCallTimeout)
	defer cancel()
	hosts, err := h.hosts(ctx)
	if err != nil {
		// The page shows a fixed "Inventory unavailable" message; the
		// error detail (which can contain internal state) goes to the
		// log only.
		h.log.Error("list inventory hosts", "error", err)
		data.InventoryUnavailable = true
		h.render(w, data)
		return
	}
	keys, keysUnavailable := h.hostKeyStatuses(ctx)
	for _, host := range hosts {
		v := viewHost(host, keys)
		if keysUnavailable {
			v.KeyStatus = "executor unavailable"
		}
		data.Inventory = append(data.Inventory, v)
	}
	h.render(w, data)
}

// hostKeyStatuses maps a host ID to its SSH key status text. The second
// return value is true when the executor's pins could not be read (the
// column then shows "executor unavailable").
func (h *Handler) hostKeyStatuses(ctx context.Context) (map[string]string, bool) {
	if h.hostKeys == nil {
		return nil, true
	}
	pins, err := h.hostKeys(ctx)
	if err != nil {
		// The column shows a fixed "executor unavailable" message; the
		// error detail goes to the log only.
		h.log.Error("list host key pins", "error", err)
		return nil, true
	}
	// The executor pins one key per host; if a host ever has several
	// pins, the blocked one wins, since it is the state that refuses
	// connections.
	byHost := make(map[string]*pb.HostKeyPin, len(pins))
	for _, pin := range pins {
		if pin == nil {
			continue
		}
		id := pin.GetHostId()
		if cur, ok := byHost[id]; !ok || (pin.GetBlocked() && !cur.GetBlocked()) {
			byHost[id] = pin
		}
	}
	statuses := make(map[string]string, len(byHost))
	for id, pin := range byHost {
		if pin.GetBlocked() {
			statuses[id] = "BLOCKED (host key mismatch)"
			continue
		}
		statuses[id] = "pinned " + pin.GetKeyType() + " " + pin.GetFingerprint()
	}
	return statuses, false
}

// viewHost formats one inventory host for the table.
func viewHost(host inventory.Host, keys map[string]string) hostView {
	endpoints := make([]string, len(host.Endpoints))
	for i, e := range host.Endpoints {
		port := e.Port
		if port == 0 {
			port = defaultSSHPort
		}
		endpoints[i] = e.Address + ":" + strconv.Itoa(port)
	}
	keyStatus := "not enrolled"
	if s, ok := keys[host.ID]; ok {
		keyStatus = s
	}
	return hostView{
		ID:          host.ID,
		DisplayName: host.DisplayName,
		Environment: string(host.Environment),
		Criticality: string(host.Criticality),
		Endpoints:   endpoints,
		KeyStatus:   keyStatus,
	}
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

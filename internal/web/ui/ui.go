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
	"net/netip"
	"time"

	"google.golang.org/grpc"

	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pveinventory"
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

// InventoryStore is the part of the inventory store the UI uses to
// create, edit and delete hosts. inventory.Store satisfies it.
type InventoryStore interface {
	Create(ctx context.Context, h inventory.Host, opts inventory.CreateOptions) (inventory.Host, error)
	Get(ctx context.Context, id string) (inventory.Host, error)
	Update(ctx context.Context, h inventory.Host) (inventory.Host, error)
	Delete(ctx context.Context, id string) error
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
	// Inventory provides create, update and delete for the inventory
	// page. Nil leaves the page read-only: no form, no edit or delete
	// buttons, and the change endpoints answer 404.
	Inventory InventoryStore
	// Operations plans and follows executions. Nil leaves the
	// operations page empty.
	Operations Operations
	// Pins stores the per-host pinned quick actions (job ui5). Nil
	// leaves pin management off: no pin endpoints and no pin UI.
	Pins PinStore
	// Schedules manages scheduled read-only checks. Nil hides them.
	Schedules Schedules
	// Runbooks stores runbooks. Nil leaves the runbooks page empty.
	Runbooks Runbooks
	// Trust asks the executor about artifact trust (runbook pages). Nil
	// shows "unknown" and no trust button.
	Trust ArtifactTrust
	// Modules imports and lists modules. Nil hides the modules pages.
	Modules Modules
	// LastResult feeds the module cards on host pages. Nil shows none.
	LastResult LastResultFunc
	// Network keeps networks and assets (M9-1). Nil leaves the network
	// page empty.
	Network NetworkStore
	// Discovery queues scans and imports their results (M9-2). Nil hides
	// discovery.
	Discovery DiscoveryStore
	// Events reads the executor's signed event chain and Audit the
	// server's audit lines, for the History page (M10-1).
	Events EventSource
	Audit  AuditStore
	// Repin re-pins hosts blocked by a host key mismatch. Nil leaves only
	// the CLI instructions on the dashboard.
	Repin Repinner
	// Enroll pins new hosts in bulk from the inventory. It needs
	// Inventory; nil leaves enrollment to the CLI.
	Enroll Enroller
	// ServerIP returns the server's own first private IPv4, for the
	// quick-scan prefill. Nil uses the machine's interfaces.
	ServerIP func() netip.Addr
	// SecurityKeys returns the WebAuthn credentials registered with the
	// executor, for the settings page ("Sign-in and security keys"). Nil
	// hides the key table; an error makes the section show a plain error
	// line (the detail goes to the log only).
	SecurityKeys func(ctx context.Context) ([]*pb.WebAuthnCredential, error)
	// TOTPStatus returns the executor's TOTP status, for the settings
	// page ("Recovery"). Nil hides the status; an error makes the section
	// show a plain error line (the detail goes to the log only).
	TOTPStatus func(ctx context.Context) (*pb.GetTOTPStatusResponse, error)
	// PVEChart returns the PVE side of the org chart for the inventory
	// chart page: PVE node boxes with their guest and storage (datastore)
	// children. Nil hides the PVE section. An error makes the PVE section
	// show "PVE unavailable"; the detail goes to the log only.
	PVEChart func(ctx context.Context) (pveinventory.Tree, error)
	// Log receives executor status errors (the page itself only shows
	// "Executor unavailable"). Nil means slog.Default().
	Log *slog.Logger
}

// Handler renders the UI pages and serves the embedded static assets.
type Handler struct {
	publicOrigin string
	// pages maps a content name to the parsed template set (layout +
	// that page), so every page can define its own "content" block.
	pages        map[string]*template.Template
	staticFS     fs.FS
	status       StatusProvider
	hostNames    func(ctx context.Context) []string
	hosts        func(ctx context.Context) ([]inventory.Host, error)
	hostKeys     func(ctx context.Context) ([]*pb.HostKeyPin, error)
	inventory    InventoryStore
	operations   Operations
	pins         PinStore
	schedules    Schedules
	runbooks     Runbooks
	trust        ArtifactTrust
	modules      Modules
	lastResult   LastResultFunc
	network      NetworkStore
	discovery    DiscoveryStore
	events       EventSource
	auditLog     AuditStore
	log          *slog.Logger
	repin        Repinner
	enroll       Enroller
	serverIP     func() netip.Addr
	securityKeys func(ctx context.Context) ([]*pb.WebAuthnCredential, error)
	totpStatus   func(ctx context.Context) (*pb.GetTOTPStatusResponse, error)
	pveChart     func(ctx context.Context) (pveinventory.Tree, error)
}

// New parses the embedded templates and builds a Handler.
func New(o Options) (*Handler, error) {
	if o.PublicOrigin == "" {
		return nil, errors.New("ui: PublicOrigin is required")
	}
	pages := make(map[string]*template.Template, len(pageFiles))
	for name, file := range pageFiles {
		set, err := template.New("").Funcs(template.FuncMap{"timeTag": timeTag}).ParseFS(templates.FS, append([]string{"layout.html", file}, pagePartials[name]...)...)
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
	serverIP := o.ServerIP
	if serverIP == nil {
		serverIP = serverPrivateIPv4
	}
	return &Handler{
		publicOrigin: o.PublicOrigin,
		pages:        pages,
		staticFS:     staticFS,
		status:       o.Status,
		hostNames:    o.HostNames,
		hosts:        o.Hosts,
		hostKeys:     o.HostKeys,
		inventory:    o.Inventory,
		operations:   o.Operations,
		pins:         o.Pins,
		schedules:    o.Schedules,
		runbooks:     o.Runbooks,
		trust:        o.Trust,
		modules:      o.Modules,
		lastResult:   o.LastResult,
		network:      o.Network,
		discovery:    o.Discovery,
		events:       o.Events,
		auditLog:     o.Audit,
		repin:        o.Repin,
		enroll:       o.Enroll,
		serverIP:     serverIP,
		securityKeys: o.SecurityKeys,
		totpStatus:   o.TOTPStatus,
		pveChart:     o.PVEChart,
		log:          log,
	}, nil
}

// pageFiles maps a content name to the template file that defines its
// "content" block.
var pageFiles = map[string]string{
	"dashboard": "dashboard.html",
	"empty":     "empty.html",
	"inventory": "inventory.html",
	"chart":     "chart.html",
	"login":     "login.html",
	"setup":     "setup.html",
	"settings":  "settings.html",

	"operations":       "operations.html",
	"inventory_import": "inventory_import.html",
	"inventory_enroll": "inventory_enroll.html",
	"operation_new":    "operation_new.html",
	"operation":        "operation.html",
	"schedules":        "schedules.html",
	"runbooks":         "runbooks.html",
	"runbook":          "runbook.html",
	"runbook_edit":     "runbook_edit.html",
	"modules":          "modules.html",
	"module":           "module.html",
	"host":             "host.html",
	"network":          "network.html",
	"network_quick":    "network_quick.html",
	"network_detail":   "network_detail.html",
	"asset":            "asset.html",
	"search":           "search.html",
	"history":          "history.html",
	"discovery":        "discovery.html",
	"discovery_job":    "discovery_job.html",
}

// pagePartials are extra template files a page uses.
var pagePartials = map[string][]string{
	"network":        {"network_forms.html"},
	"network_detail": {"network_forms.html"},
	"asset":          {"network_forms.html"},
}

// Handler returns the UI's http.Handler without the security middleware
// chain. Use Server for a ready-to-serve *http.Server.
func (h *Handler) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", h.handleRoot)
	mux.HandleFunc("/dashboard", h.handleDashboard)
	mux.HandleFunc("/inventory", h.handleInventory)
	mux.HandleFunc("GET /inventory/chart", h.handleInventoryChart)
	mux.HandleFunc("/inventory/new", h.handleInventoryNew)
	// Host changes are JSON POSTs only (decision 36: never plain form
	// posts). Without Options.Inventory they answer 404.
	mux.HandleFunc("/inventory/hosts", h.handleHostCreate)
	mux.HandleFunc("/inventory/hosts/update", h.handleHostUpdate)
	mux.HandleFunc("/inventory/hosts/delete", h.handleHostDelete)
	// CSV import (spec 12): page, preview, import of the selected rows.
	mux.HandleFunc("GET /inventory/import", h.handleImportPage)
	mux.HandleFunc("POST /inventory/import/preview", h.handleImportPreview)
	mux.HandleFunc("POST /inventory/import/commit", h.handleImportCommit)
	// Operations (M4): pages and the JSON endpoints their script calls.
	mux.HandleFunc("GET /operations", h.handleOperations)
	mux.HandleFunc("GET /operations/new", h.handleOperationNew)
	mux.HandleFunc("GET /operations/{id}", h.handleOperation)
	mux.HandleFunc("POST /operations/create", h.handleOperationCreate)
	mux.HandleFunc("POST /operations/approve", h.handleOperationApprove)
	mux.HandleFunc("POST /operations/{id}/check", h.handleOperationCheck)
	// The status poll is GET only (the handler answers 405 otherwise).
	mux.HandleFunc("/operations/{id}/status", h.handleOperationStatus)
	mux.HandleFunc("POST /operations/gate", h.handleOperationGate)
	mux.HandleFunc("POST /operations/gate/commit", h.handleOperationGateCommit)
	mux.HandleFunc("POST /operations/abort", h.handleOperationAbort)
	mux.HandleFunc("POST /operations/retry", h.handleOperationRetry)
	// Scheduled read-only checks (schedule grants).
	mux.HandleFunc("GET /schedules", h.handleSchedules)
	mux.HandleFunc("POST /schedules/create", h.handleScheduleCreate)
	mux.HandleFunc("POST /schedules/approve", h.handleScheduleApprove)
	mux.HandleFunc("POST /schedules/revoke", h.handleScheduleRevoke)
	// Runbooks (M7-2).
	mux.HandleFunc("GET /runbooks", h.handleRunbooks)
	mux.HandleFunc("GET /runbooks/new", h.handleRunbookEdit)
	mux.HandleFunc("GET /runbooks/{slug}", h.handleRunbook)
	mux.HandleFunc("GET /runbooks/{slug}/{version}/artifact", h.handleRunbookArtifact)
	mux.HandleFunc("POST /runbooks/save", h.handleRunbookSave)
	mux.HandleFunc("POST /runbooks/trust/begin", h.handleRunbookTrustBegin)
	mux.HandleFunc("POST /runbooks/trust/commit", h.handleRunbookTrustCommit)
	// Modules (M7-5).
	mux.HandleFunc("GET /modules", h.handleModules)
	mux.HandleFunc("GET /modules/{name}", h.handleModule)
	mux.HandleFunc("POST /modules/import", h.handleModuleImport)
	mux.HandleFunc("POST /modules/verify", h.handleModuleVerify)
	mux.HandleFunc("GET /hosts/{id}", h.handleHost)
	// The host settings form (edit and delete) posts as a plain form
	// (no JavaScript) or as JSON from the dialog; both go through the
	// Origin-checked POST routes.
	mux.HandleFunc("POST /hosts/{id}/refresh", h.handleHostRefresh)
	mux.HandleFunc("POST /inventory/refresh", h.handleInventoryRefresh)
	// Pin management: the handlers answer 405 for the wrong method.
	mux.HandleFunc("/hosts/{id}/pins", h.handleHostPins)
	mux.HandleFunc("/actions/pin", h.handleActionPin)
	mux.HandleFunc("/privileged/session", h.handlePrivilegedSession)
	mux.HandleFunc("POST /hosts/{id}/settings", h.handleHostFormUpdate)
	mux.HandleFunc("POST /hosts/{id}/delete", h.handleHostFormDelete)
	// Global search (M9-3): read-only, quick actions are links.
	mux.HandleFunc("GET /search", h.handleSearch)
	mux.HandleFunc("GET /history", h.handleHistory)
	mux.HandleFunc("GET /settings", h.handleSettingsPage)
	mux.HandleFunc("POST /settings/appearance", h.handleSettingsAppearance)
	mux.HandleFunc("POST /ui/nav", h.handleNav)
	// Network: assets and IPAM-light (M9-1).
	mux.HandleFunc("GET /network", h.handleNetworkPage)
	mux.HandleFunc("GET /network/n/{id}", h.handleNetworkDetail)
	mux.HandleFunc("GET /network/a/{id}", h.handleAssetDetail)
	mux.HandleFunc("POST /network/save", h.handleNetworkSave)
	mux.HandleFunc("POST /network/scan", h.handleNetworkScan)
	mux.HandleFunc("POST /network/delete", h.handleNetworkDelete)
	mux.HandleFunc("POST /network/entry", h.handleIPEntry)
	mux.HandleFunc("POST /network/a/save", h.handleAssetSave)
	mux.HandleFunc("POST /network/a/delete", h.handleAssetDelete)
	mux.HandleFunc("POST /network/a/link", h.handleAssetLink)
	// Discovery (M9-2).
	mux.HandleFunc("GET /network/discovery", h.handleDiscoveryPage)
	mux.HandleFunc("GET /network/discovery/{id}", h.handleDiscoveryJob)
	mux.HandleFunc("POST /network/discovery/submit", h.handleDiscoverySubmit)
	mux.HandleFunc("POST /network/discovery/cancel", h.handleDiscoveryCancel)
	mux.HandleFunc("POST /network/discovery/import", h.handleDiscoveryImport)
	mux.HandleFunc("POST /network/discovery/schedule/delete", h.handleDiscoveryScheduleDelete)
	mux.HandleFunc("POST /hostkeys/repin/propose", h.handleRepinPropose)
	mux.HandleFunc("POST /hostkeys/repin/commit", h.handleRepinCommit)
	mux.HandleFunc("GET /inventory/enroll", h.handleEnrollPage)
	mux.HandleFunc("POST /inventory/enroll/propose", h.handleEnrollPropose)
	mux.HandleFunc("POST /inventory/enroll/commit", h.handleEnrollCommit)
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

// emptyPages are the shell pages that have no content yet. /settings is a
// real page now (see settings.go); the list is empty until the next shell
// page needs a placeholder.
var emptyPages = []struct {
	path  string
	title string
}{}

// pageData is the data passed to the layout template.
type pageData struct {
	// Title is the page title, shown in <title> and <h1>.
	Title string
	// Active marks the current navigation item.
	Active string
	// Theme is "system" (default), "light" or "dark"; it is set on the
	// <html> data-theme attribute. render fills it from the nebula_theme
	// cookie when a handler leaves it empty.
	Theme string
	// NavCollapsed is true when the nebula_nav cookie says the sidebar is
	// collapsed (icons only); the layout renders the collapsed state so
	// the first paint is correct (no client-side flicker).
	NavCollapsed bool
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
	// Chart is the data of the inventory org chart page.
	Chart *chartData
	// InventoryDialogOpen shows the add-host dialog with the open
	// attribute (the no-JavaScript form at /inventory/new, or a form
	// error).
	InventoryDialogOpen bool
	// InventoryError is a form error shown inside the add dialog.
	InventoryError string
	// InventoryConfirmDuplicate adds the hidden confirmation field to
	// the add form (after a duplicate-endpoint warning).
	InventoryConfirmDuplicate bool
	// InventoryState, InventoryEnv and InventoryEnvs are the active
	// server-side filters and the known environments.
	InventoryState string
	InventoryEnv   string
	InventoryEnvs  []string
	// InventoryStale is the active ?stale=1 filter (enrolled hosts
	// without a read in 24 h).
	InventoryStale bool
	// Blocked lists hosts blocked after a host key mismatch.
	Blocked []blockedView
	// BlockedUnknown is true when the executor could not be asked.
	BlockedUnknown bool
	// RepinEnabled shows the re-pin controls for blocked hosts.
	RepinEnabled bool
	// Enroll lists inventory hosts without a pinned key.
	Enroll []enrollRow
	// EnrollNote explains a preselected enrollment (?host=).
	EnrollNote string
	// EnrollEnabled links the enrollment page from the inventory.
	EnrollEnabled bool
	// Schedules is the data of the scheduled-checks page.
	Schedules *schedulesData
	// Runbooks is the data of the runbook pages.
	Runbooks *runbooksData
	// Modules is the data of the module pages.
	Modules *modulesData
	// Network is the data of the network pages.
	Network *networkData
	// Quick is the data of the quick network view.
	Quick *networkQuickData
	// NetworkMode is the active network view ("quick" or "expert"), for the
	// segmented switch.
	NetworkMode string
	// Discovery is the data of the discovery pages.
	Discovery *discoveryData
	// Search is the data of the search page.
	Search *searchData
	// History is the data of the history page.
	History *historyData
	// Settings is the data of the settings page.
	Settings *settingsData
	// InventoryPrefill is the JSON that prefills the add-host form from
	// an asset ("add to managed hosts").
	InventoryPrefill string
	// Host is the data of a host's page.
	Host *hostPageData
	// Ops is the data of the operations pages.
	Ops *operationsData
	// InventoryEditable is true when Options.Inventory is set; the
	// page then shows the add-host form and the per-row edit and
	// delete controls.
	InventoryEditable bool
	// DashboardTiles are the host-state tiles on the dashboard, each
	// linking to the filtered inventory.
	DashboardTiles []dashboardTile
}

// statusView is the dashboard's executor status, pre-formatted for
// display.
type statusView struct {
	// LockText is "Locked" or "Unlocked".
	LockText string
	// Session is "none" or "active, expires <UTC time>".
	Session string
	// Recovery is true while a TOTP recovery waits for a new security key.
	Recovery bool
	// Vault is "not set up", "locked", "unlocked" or "unknown".
	Vault string
}

// blockedView is a host blocked after a host key mismatch (spec 08). The
// endpoint and fingerprint come from the host side: text only.
type blockedView struct {
	HostID      string
	Endpoint    string
	Fingerprint string
	Since       string
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
	data := pageData{Title: "Dashboard", Active: "dashboard", Content: "dashboard", Scripts: []string{"webauthn.js", "dashboard.js"},
		RepinEnabled: h.repin != nil}
	if h.repin != nil {
		data.Scripts = append(data.Scripts, "repin.js")
	}
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
	data.Blocked, data.BlockedUnknown = h.blockedHosts(r.Context())
	if h.hosts != nil && h.inventory != nil {
		data.DashboardTiles = h.dashboardTiles(r.Context())
	}
	h.render(w, r, data)
}

// blockedHosts lists hosts blocked after a host key mismatch, so the
// dashboard shows them until notifications exist (Milestone 4). The
// second result is true when the executor could not be asked.
func (h *Handler) blockedHosts(ctx context.Context) ([]blockedView, bool) {
	if h.hostKeys == nil {
		return nil, false
	}
	ctx, cancel := context.WithTimeout(ctx, statusCallTimeout)
	defer cancel()
	pins, err := h.hostKeys(ctx)
	if err != nil {
		h.log.Error("list host keys", "error", err)
		return nil, true
	}
	var out []blockedView
	for _, p := range pins {
		if !p.GetBlocked() {
			continue
		}
		fp := p.GetBlockedFingerprint()
		if fp == "" {
			fp = "no key of the pinned type"
		}
		since := ""
		if p.GetBlockedAtUnix() > 0 {
			since = time.Unix(p.GetBlockedAtUnix(), 0).UTC().Format("2006-01-02 15:04:05 MST")
		}
		out = append(out, blockedView{HostID: p.GetHostId(), Endpoint: p.GetBlockedEndpoint(), Fingerprint: fp, Since: since})
	}
	return out, false
}

func (h *Handler) handleBare(title, content, script string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		h.render(w, r, pageData{Title: title, Content: content, Bare: true, Scripts: []string{"webauthn.js", script}})
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
		h.render(w, r, pageData{Title: title, Active: path[1:], Content: "empty"})
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
	vault := "unknown"
	switch st.GetVaultState() {
	case pb.VaultState_VAULT_STATE_NOT_INITIALIZED:
		vault = "not set up"
	case pb.VaultState_VAULT_STATE_LOCKED:
		vault = "locked"
	case pb.VaultState_VAULT_STATE_UNLOCKED:
		vault = "unlocked"
	}
	return &statusView{LockText: lock, Session: session, Recovery: st.GetRecoveryPending(), Vault: vault}
}

func (h *Handler) render(w http.ResponseWriter, r *http.Request, data pageData) {
	if data.Theme == "" {
		data.Theme = themeFromRequest(r)
	}
	data.NavCollapsed = navStateFromRequest(r) == navCollapsed
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

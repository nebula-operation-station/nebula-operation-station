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
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/sshtransport"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/auth"
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
	// Schedules manages scheduled read-only checks. Nil hides them.
	Schedules Schedules
	// Runbooks stores runbooks. Nil leaves the runbooks page empty.
	Runbooks Runbooks
	// Trust asks the executor about artifact trust (runbook pages). Nil
	// shows "unknown" and no trust button.
	Trust ArtifactTrust
	// Repin re-pins hosts blocked by a host key mismatch. Nil leaves only
	// the CLI instructions on the dashboard.
	Repin Repinner
	// Enroll pins new hosts in bulk from the inventory. It needs
	// Inventory; nil leaves enrollment to the CLI.
	Enroll Enroller
	// Log receives executor status errors (the page itself only shows
	// "Executor unavailable"). Nil means slog.Default().
	Log *slog.Logger
}

// Handler renders the UI pages and serves the embedded static assets.
type Handler struct {
	publicOrigin string
	// pages maps a content name to the parsed template set (layout +
	// that page), so every page can define its own "content" block.
	pages      map[string]*template.Template
	staticFS   fs.FS
	status     StatusProvider
	hostNames  func(ctx context.Context) []string
	hosts      func(ctx context.Context) ([]inventory.Host, error)
	hostKeys   func(ctx context.Context) ([]*pb.HostKeyPin, error)
	inventory  InventoryStore
	operations Operations
	schedules  Schedules
	runbooks   Runbooks
	trust      ArtifactTrust
	log        *slog.Logger
	repin      Repinner
	enroll     Enroller
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
		inventory:    o.Inventory,
		operations:   o.Operations,
		schedules:    o.Schedules,
		runbooks:     o.Runbooks,
		trust:        o.Trust,
		repin:        o.Repin,
		enroll:       o.Enroll,
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

	"operations":       "operations.html",
	"inventory_import": "inventory_import.html",
	"inventory_enroll": "inventory_enroll.html",
	"operation_new":    "operation_new.html",
	"operation":        "operation.html",
	"schedules":        "schedules.html",
	"runbooks":         "runbooks.html",
	"runbook":          "runbook.html",
	"runbook_edit":     "runbook_edit.html",
}

// Handler returns the UI's http.Handler without the security middleware
// chain. Use Server for a ready-to-serve *http.Server.
func (h *Handler) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", h.handleRoot)
	mux.HandleFunc("/dashboard", h.handleDashboard)
	mux.HandleFunc("/inventory", h.handleInventory)
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

// emptyPages are the shell pages that have no content yet.
var emptyPages = []struct {
	path  string
	title string
}{
	{"/network", "Network"},
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
	// Blocked lists hosts blocked after a host key mismatch.
	Blocked []blockedView
	// BlockedUnknown is true when the executor could not be asked.
	BlockedUnknown bool
	// RepinEnabled shows the re-pin controls for blocked hosts.
	RepinEnabled bool
	// Enroll lists inventory hosts without a pinned key.
	Enroll []enrollRow
	// EnrollEnabled links the enrollment page from the inventory.
	EnrollEnabled bool
	// Schedules is the data of the scheduled-checks page.
	Schedules *schedulesData
	// Runbooks is the data of the runbook pages.
	Runbooks *runbooksData
	// Ops is the data of the operations pages.
	Ops *operationsData
	// InventoryEditable is true when Options.Inventory is set; the
	// page then shows the add-host form and the per-row edit and
	// delete controls.
	InventoryEditable bool
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
	// EndpointsJSON is the JSON array of the endpoint strings, used to
	// prefill the edit form (host:port and [v6]:port are exactly what
	// the form and sshtransport.ParseEndpoint accept).
	EndpointsJSON string
	// TagsJSON is the JSON object of the host tags, used to prefill
	// the edit form.
	TagsJSON string
	// KeyStatus is the host's SSH key status: "pinned <key type>
	// <fingerprint>", "BLOCKED (host key mismatch)", "not enrolled" or
	// "executor unavailable".
	KeyStatus string
	// OpsState is READY, WARNING, UNREACHABLE or UNKNOWN (spec 12) and
	// OpsReason its "time · reason" text.
	OpsState  string
	OpsReason string
	// Updates summarizes the latest update check, "" if none.
	Updates string
	// UpdatesAlert marks pending security updates or a required reboot.
	UpdatesAlert bool
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
	h.render(w, data)
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

func (h *Handler) handleInventory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	data := pageData{Title: "Inventory", Active: "inventory", Content: "inventory"}
	if h.inventory != nil {
		data.InventoryEditable = true
		data.EnrollEnabled = h.enroll != nil && h.hosts != nil
		data.Scripts = []string{"webauthn.js", "inventory.js"}
	}
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
	var updates map[string]executions.HostUpdates
	var states map[string]executions.OpsState
	if h.operations != nil {
		if updates, err = h.operations.AllUpdates(ctx); err != nil {
			h.log.Error("list host updates", "error", err)
		}
		if states, err = h.operations.AllOpsStates(ctx); err != nil {
			h.log.Error("list ops states", "error", err)
		}
	}
	for _, host := range hosts {
		v := viewHost(host, keys)
		if keysUnavailable {
			v.KeyStatus = "executor unavailable"
		}
		if u, ok := updates[host.ID]; ok {
			v.Updates, v.UpdatesAlert = updatesSummary(u)
		}
		v.OpsState, v.OpsReason = opsStateView(states[host.ID], v.KeyStatus)
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
		// JoinHostPort brackets IPv6 addresses ("[fd00::1]:22").
		endpoints[i] = net.JoinHostPort(e.Address, strconv.Itoa(port))
	}
	endpointsJSON, _ := json.Marshal(endpoints)
	tags := host.Tags
	if tags == nil {
		tags = map[string]string{}
	}
	tagsJSON, _ := json.Marshal(tags)
	keyStatus := "not enrolled"
	if s, ok := keys[host.ID]; ok {
		keyStatus = s
	}
	return hostView{
		ID:            host.ID,
		DisplayName:   host.DisplayName,
		Environment:   string(host.Environment),
		Criticality:   string(host.Criticality),
		Endpoints:     endpoints,
		EndpointsJSON: string(endpointsJSON),
		TagsJSON:      string(tagsJSON),
		KeyStatus:     keyStatus,
	}
}

// maxHostBodyBytes limits the JSON body of the host change endpoints.
const maxHostBodyBytes = 64 << 10

// hostRequest is the JSON body of the create and update endpoints.
// Endpoints are strings parsed by sshtransport.ParseEndpoint ("host",
// "host:port" or "[v6]:port").
type hostRequest struct {
	ID          string            `json:"id"`
	DisplayName string            `json:"display_name"`
	Environment string            `json:"environment"`
	Criticality string            `json:"criticality"`
	Endpoints   []string          `json:"endpoints"`
	Tags        map[string]string `json:"tags"`
}

// toHost converts the request into an inventory host, parsing every
// endpoint. The returned error describes the input only.
func (in hostRequest) toHost() (inventory.Host, error) {
	h := inventory.Host{
		ID:          in.ID,
		DisplayName: in.DisplayName,
		Environment: inventory.Environment(in.Environment),
		Criticality: inventory.Criticality(in.Criticality),
		Tags:        in.Tags,
	}
	for _, s := range in.Endpoints {
		e, err := sshtransport.ParseEndpoint(s)
		if err != nil {
			return inventory.Host{}, err
		}
		port := int(e.Port)
		if port == 0 {
			port = 22 // the inventory default; the store stores it explicitly
		}
		h.Endpoints = append(h.Endpoints, inventory.Endpoint{Address: e.Host, Port: port})
	}
	return h, nil
}

// decodeHostRequest reads and validates the JSON body of a create or
// update request. It returns the parsed host, or an error describing
// the input (bad JSON, unknown fields, oversized body, bad endpoint).
func decodeHostRequest(w http.ResponseWriter, r *http.Request) (inventory.Host, error) {
	r.Body = http.MaxBytesReader(w, r.Body, maxHostBodyBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return inventory.Host{}, fmt.Errorf("read request body: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	var in hostRequest
	if err := dec.Decode(&in); err != nil {
		return inventory.Host{}, fmt.Errorf("request body is not valid JSON: %v", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return inventory.Host{}, errors.New("request body contains data after the JSON object")
	}
	return in.toHost()
}

// answerStoreError maps an inventory store error to a response:
// validation problems (which describe the input) are 400 with the
// problem text, unknown hosts are 404, and everything else is 500 with
// a fixed message — the detail goes to the log only.
func (h *Handler) answerStoreError(w http.ResponseWriter, action, id string, err error) {
	var verr *inventory.ValidationError
	switch {
	case errors.As(err, &verr):
		writeJSONError(w, http.StatusBadRequest, verr.Error())
	case errors.Is(err, inventory.ErrHostNotFound):
		writeJSONError(w, http.StatusNotFound, "host not found")
	case errors.Is(err, inventory.ErrHostExists):
		writeJSONError(w, http.StatusConflict, "a host with this ID already exists")
	default:
		h.log.Error(action, "host", id, "error", err)
		writeJSONError(w, http.StatusInternalServerError, "inventory unavailable")
	}
}

// audit logs one line per inventory change: the kind, the host ID and
// the web user.
func (h *Handler) audit(r *http.Request, kind, hostID string) {
	user := "unknown"
	if s, ok := auth.SessionFrom(r.Context()); ok {
		user = s.UserName
	}
	h.log.Info("audit", "kind", kind, "host", hostID, "user", user)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// answerDecodeError turns a decodeHostRequest error into a response:
// an oversized body is 413, anything else (bad JSON, unknown fields,
// bad endpoint) is 400 with the input-describing text.
func answerDecodeError(w http.ResponseWriter, err error) {
	var mbe *http.MaxBytesError
	if errors.As(err, &mbe) {
		writeJSONError(w, http.StatusRequestEntityTooLarge, "request body too large")
		return
	}
	writeJSONError(w, http.StatusBadRequest, err.Error())
}

// hostChangeAllowed answers the request itself unless it is a JSON POST
// to a configured inventory. Requiring application/json is defence in
// depth next to the Origin check: no plain HTML form can send it.
func (h *Handler) hostChangeAllowed(w http.ResponseWriter, r *http.Request) bool {
	if h.inventory == nil {
		http.NotFound(w, r)
		return false
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return false
	}
	if ct, _, _ := strings.Cut(r.Header.Get("Content-Type"), ";"); !strings.EqualFold(strings.TrimSpace(ct), "application/json") {
		writeJSONError(w, http.StatusUnsupportedMediaType, "Content-Type must be application/json")
		return false
	}
	return true
}

func (h *Handler) handleHostCreate(w http.ResponseWriter, r *http.Request) {
	if !h.hostChangeAllowed(w, r) {
		return
	}
	host, err := decodeHostRequest(w, r)
	if err != nil {
		answerDecodeError(w, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), inventoryCallTimeout)
	defer cancel()
	if _, err := h.inventory.Create(ctx, host, inventory.CreateOptions{}); err != nil {
		h.answerStoreError(w, "create host", host.ID, err)
		return
	}
	h.audit(r, "host_created", host.ID)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (h *Handler) handleHostUpdate(w http.ResponseWriter, r *http.Request) {
	if !h.hostChangeAllowed(w, r) {
		return
	}
	host, err := decodeHostRequest(w, r)
	if err != nil {
		answerDecodeError(w, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), inventoryCallTimeout)
	defer cancel()
	if _, err := h.inventory.Update(ctx, host); err != nil {
		h.answerStoreError(w, "update host", host.ID, err)
		return
	}
	h.audit(r, "host_updated", host.ID)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// deleteRequest is the JSON body of the delete endpoint.
type deleteRequest struct {
	ID string `json:"id"`
}

func (h *Handler) handleHostDelete(w http.ResponseWriter, r *http.Request) {
	if !h.hostChangeAllowed(w, r) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxHostBodyBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		answerDecodeError(w, err)
		return
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	var in deleteRequest
	if err := dec.Decode(&in); err != nil {
		writeJSONError(w, http.StatusBadRequest, "request body is not valid JSON: "+err.Error())
		return
	}
	if _, err := dec.Token(); err != io.EOF {
		writeJSONError(w, http.StatusBadRequest, "request body contains data after the JSON object")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), inventoryCallTimeout)
	defer cancel()
	if err := h.inventory.Delete(ctx, in.ID); err != nil {
		h.answerStoreError(w, "delete host", in.ID, err)
		return
	}
	h.audit(r, "host_deleted", in.ID)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
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

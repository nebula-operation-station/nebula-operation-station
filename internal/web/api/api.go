// SPDX-License-Identifier: AGPL-3.0-or-later

// Package api serves the read-only API under /api/v1 (spec 13): token
// authentication, scopes inventory.read, operations.read and
// execution_logs.read, no anonymous access, no state changes. This is how
// Home Assistant, a status page or a script reads the Ops State.
package api

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverconfig"
)

// Prefix is the path prefix of the API.
const Prefix = "/api/v1/"

// Limits.
const (
	// maxListLimit bounds the operations list.
	maxListLimit = 200
	// maxOutput bounds result and log text per host in a response.
	maxOutput   = 64 << 10
	callTimeout = 10 * time.Second
)

// Operations is the read side of the executions service.
type Operations interface {
	Get(ctx context.Context, id string) (executions.Execution, error)
	List(ctx context.Context, limit int) ([]executions.Summary, error)
	AllUpdates(ctx context.Context) (map[string]executions.HostUpdates, error)
	AllOpsStates(ctx context.Context) (map[string]executions.OpsState, error)
}

// Options configure the API handler.
type Options struct {
	Tokens     []serverconfig.APIToken
	Hosts      func(ctx context.Context) ([]inventory.Host, error)
	Operations Operations
	Log        *slog.Logger
}

// Handler serves the API.
type Handler struct {
	tokens []token
	hosts  func(ctx context.Context) ([]inventory.Host, error)
	ops    Operations
	log    *slog.Logger
}

type token struct {
	name   string
	hash   [sha256.Size]byte
	scopes []string
}

// New returns the API handler. Tokens are the validated configuration.
func New(o Options) (*Handler, error) {
	if len(o.Tokens) == 0 {
		return nil, errors.New("api: no tokens")
	}
	if o.Hosts == nil || o.Operations == nil {
		return nil, errors.New("api: hosts and operations are required")
	}
	h := &Handler{hosts: o.Hosts, ops: o.Operations, log: o.Log}
	if h.log == nil {
		h.log = slog.Default()
	}
	for _, t := range o.Tokens {
		raw, err := hex.DecodeString(t.SHA256)
		if err != nil || len(raw) != sha256.Size {
			return nil, errors.New("api: token " + t.Name + ": bad hash")
		}
		var x token
		x.name, x.scopes = t.Name, slices.Clone(t.Scopes)
		copy(x.hash[:], raw)
		h.tokens = append(h.tokens, x)
	}
	return h, nil
}

// HashToken returns the configuration hash of a token string.
func HashToken(tok string) string {
	sum := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(sum[:])
}

// authenticate returns the token of the request, or nil. Every configured
// hash is compared in constant time.
func (h *Handler) authenticate(r *http.Request) *token {
	auth := r.Header.Get("Authorization")
	tok, ok := strings.CutPrefix(auth, "Bearer ")
	if !ok || tok == "" || len(tok) > 256 {
		return nil
	}
	sum := sha256.Sum256([]byte(tok))
	var found *token
	for i := range h.tokens {
		if subtle.ConstantTimeCompare(sum[:], h.tokens[i].hash[:]) == 1 {
			found = &h.tokens[i]
		}
	}
	return found
}

func (t *token) has(scope string) bool { return slices.Contains(t.scopes, scope) }

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// ServeHTTP authenticates, checks the scope and serves one endpoint.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		writeError(w, http.StatusMethodNotAllowed, "the API is read-only")
		return
	}
	t := h.authenticate(r)
	if t == nil {
		w.Header().Set("WWW-Authenticate", `Bearer realm="nebula"`)
		h.log.Warn("audit", "kind", "api_unauthorized", "path", r.URL.Path, "remote", r.RemoteAddr)
		writeError(w, http.StatusUnauthorized, "a valid API token is required")
		return
	}
	path := strings.TrimPrefix(r.URL.Path, Prefix)
	parts := strings.Split(path, "/")
	ctx, cancel := context.WithTimeout(r.Context(), callTimeout)
	defer cancel()
	var scope string
	var serve func()
	switch {
	case path == "hosts":
		scope, serve = serverconfig.ScopeInventoryRead, func() { h.listHosts(ctx, w, "") }
	case len(parts) == 2 && parts[0] == "hosts" && parts[1] != "":
		scope, serve = serverconfig.ScopeInventoryRead, func() { h.listHosts(ctx, w, parts[1]) }
	case path == "operations":
		scope, serve = serverconfig.ScopeOperationsRead, func() { h.listOperations(ctx, w, r) }
	case len(parts) == 2 && parts[0] == "operations" && parts[1] != "":
		scope, serve = serverconfig.ScopeOperationsRead, func() { h.getOperation(ctx, w, parts[1], t.has(serverconfig.ScopeExecutionLogsRead)) }
	default:
		writeError(w, http.StatusNotFound, "no such endpoint")
		return
	}
	if !t.has(scope) {
		h.log.Warn("audit", "kind", "api_forbidden", "token", t.name, "path", r.URL.Path, "scope", scope)
		writeError(w, http.StatusForbidden, "the token lacks the scope "+scope)
		return
	}
	h.log.Info("audit", "kind", "api_read", "token", t.name, "path", r.URL.Path)
	serve()
}

type updatesJSON struct {
	Total          int    `json:"total"`
	Security       int    `json:"security"`
	Kernel         int    `json:"kernel"`
	RebootRequired bool   `json:"reboot_required"`
	CheckedAt      string `json:"checked_at"`
}

type hostJSON struct {
	ID          string       `json:"id"`
	DisplayName string       `json:"display_name"`
	Environment string       `json:"environment"`
	Criticality string       `json:"criticality"`
	OpsState    string       `json:"ops_state"`
	OpsReason   string       `json:"ops_reason,omitempty"`
	OpsObserved string       `json:"ops_observed_at,omitempty"`
	Updates     *updatesJSON `json:"updates,omitempty"`
}

func rfc3339(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func (h *Handler) listHosts(ctx context.Context, w http.ResponseWriter, only string) {
	hosts, err := h.hosts(ctx)
	if err != nil {
		h.log.Error("api hosts", "error", err)
		writeError(w, http.StatusServiceUnavailable, "inventory unavailable")
		return
	}
	states, err := h.ops.AllOpsStates(ctx)
	if err != nil {
		h.log.Error("api ops states", "error", err)
		writeError(w, http.StatusServiceUnavailable, "operations unavailable")
		return
	}
	updates, err := h.ops.AllUpdates(ctx)
	if err != nil {
		h.log.Error("api updates", "error", err)
		writeError(w, http.StatusServiceUnavailable, "operations unavailable")
		return
	}
	out := []hostJSON{}
	for _, x := range hosts {
		if only != "" && x.ID != only {
			continue
		}
		v := hostJSON{ID: x.ID, DisplayName: x.DisplayName, Environment: string(x.Environment), Criticality: string(x.Criticality),
			OpsState: executions.StateUnknown}
		if st, ok := states[x.ID]; ok {
			v.OpsState, v.OpsReason, v.OpsObserved = st.State, st.Reason, rfc3339(st.ObservedAt)
		}
		if u, ok := updates[x.ID]; ok {
			v.Updates = &updatesJSON{Total: u.Total, Security: u.Security, Kernel: u.Kernel, RebootRequired: u.RebootRequired,
				CheckedAt: rfc3339(u.ObservedAt)}
		}
		out = append(out, v)
	}
	if only != "" {
		if len(out) == 0 {
			writeError(w, http.StatusNotFound, "no such host")
			return
		}
		writeJSON(w, http.StatusOK, out[0])
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"hosts": out})
}

type opSummaryJSON struct {
	ID        string `json:"id"`
	Action    string `json:"action"`
	Risk      string `json:"risk"`
	State     string `json:"state"`
	CreatedBy string `json:"created_by"`
	CreatedAt string `json:"created_at"`
	Hosts     int    `json:"hosts"`
	Failed    int    `json:"failed"`
}

func (h *Handler) listOperations(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	limit := 50
	if s := r.URL.Query().Get("limit"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 || n > maxListLimit {
			writeError(w, http.StatusBadRequest, "limit must be 1 to 200")
			return
		}
		limit = n
	}
	list, err := h.ops.List(ctx, limit)
	if err != nil {
		h.log.Error("api operations", "error", err)
		writeError(w, http.StatusServiceUnavailable, "operations unavailable")
		return
	}
	out := make([]opSummaryJSON, 0, len(list))
	for _, e := range list {
		out = append(out, opSummaryJSON{ID: e.ID, Action: e.ActionID, Risk: e.Risk, State: e.State, CreatedBy: e.CreatedBy,
			CreatedAt: rfc3339(e.CreatedAt), Hosts: e.Hosts, Failed: e.Failed})
	}
	writeJSON(w, http.StatusOK, map[string]any{"operations": out})
}

type opHostJSON struct {
	Host       string `json:"host"`
	State      string `json:"state"`
	Class      string `json:"class,omitempty"`
	ExitCode   *int   `json:"exit_code,omitempty"`
	StartedAt  string `json:"started_at,omitempty"`
	FinishedAt string `json:"finished_at,omitempty"`
	// Only with execution_logs.read: untrusted host output, as text.
	Detail       string `json:"detail,omitempty"`
	Result       string `json:"result,omitempty"`
	Log          string `json:"log,omitempty"`
	OutputCut    bool   `json:"output_cut,omitempty"`
	LogTruncated bool   `json:"log_truncated,omitempty"`
}

type opJSON struct {
	opSummaryJSON
	Version    string       `json:"version"`
	Params     string       `json:"params,omitempty"`
	Detail     string       `json:"detail,omitempty"`
	FinishedAt string       `json:"finished_at,omitempty"`
	HostsList  []opHostJSON `json:"host_runs"`
}

// text returns at most maxOutput bytes of b as valid UTF-8.
func text(b []byte) (string, bool) {
	cut := false
	if len(b) > maxOutput {
		b, cut = b[:maxOutput], true
		for len(b) > 0 && !utf8.Valid(b) {
			b = b[:len(b)-1]
		}
	}
	return strings.ToValidUTF8(string(b), "�"), cut
}

func (h *Handler) getOperation(ctx context.Context, w http.ResponseWriter, id string, logs bool) {
	e, err := h.ops.Get(ctx, id)
	if errors.Is(err, executions.ErrNotFound) {
		writeError(w, http.StatusNotFound, "no such operation")
		return
	}
	if err != nil {
		h.log.Error("api operation", "error", err)
		writeError(w, http.StatusServiceUnavailable, "operations unavailable")
		return
	}
	v := opJSON{opSummaryJSON: opSummaryJSON{ID: e.ID, Action: e.ActionID, Risk: e.Risk, State: e.State, CreatedBy: e.CreatedBy,
		CreatedAt: rfc3339(e.CreatedAt), Hosts: len(e.Hosts)},
		Version: e.ModuleVersion, Detail: e.Detail, FinishedAt: rfc3339(e.FinishedAt), HostsList: []opHostJSON{}}
	if e.Params != "{}" {
		v.Params = e.Params
	}
	for _, x := range e.Hosts {
		hv := opHostJSON{Host: x.HostID, State: x.State, Class: x.Class, StartedAt: rfc3339(x.StartedAt), FinishedAt: rfc3339(x.FinishedAt)}
		if x.State == "finished" {
			code := x.ExitCode
			hv.ExitCode = &code
			if x.Class != "success" {
				v.Failed++
			}
		}
		if logs {
			var c1, c2 bool
			hv.Detail = x.Detail
			hv.Result, c1 = text(x.Result)
			hv.Log, c2 = text(x.Log)
			hv.OutputCut, hv.LogTruncated = c1 || c2, x.LogTruncated
		}
		v.HostsList = append(v.HostsList, hv)
	}
	writeJSON(w, http.StatusOK, v)
}

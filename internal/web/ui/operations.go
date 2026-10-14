// SPDX-License-Identifier: AGPL-3.0-or-later

package ui

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/actions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/dockerhost"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/osdebian"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/auth"
)

// Operations plans and follows executions (executions.Service).
type Operations interface {
	Create(ctx context.Context, user, actionID string, hosts []string, params map[string]string) (executions.Created, error)
	Approve(ctx context.Context, user, id string, assertion []byte, typedTargets uint32) error
	Get(ctx context.Context, id string) (executions.Execution, error)
	List(ctx context.Context, limit int) ([]executions.Summary, error)
	AllUpdates(ctx context.Context) (map[string]executions.HostUpdates, error)
	AllOpsStates(ctx context.Context) (map[string]executions.OpsState, error)
}

// updatesSummary is the inventory text of an update list and whether it
// needs attention (security updates or a reboot).
func updatesSummary(u executions.HostUpdates) (string, bool) {
	var parts []string
	if u.Total == 0 {
		parts = append(parts, "up to date")
	} else {
		parts = append(parts, strconv.Itoa(u.Security)+" security / "+strconv.Itoa(u.Total)+" total")
		if u.Kernel > 0 {
			parts = append(parts, "kernel")
		}
	}
	if u.RebootRequired {
		parts = append(parts, "reboot required")
	}
	parts = append(parts, "checked "+u.ObservedAt.UTC().Format("2006-01-02 15:04 MST"))
	return strings.Join(parts, ", "), u.Security > 0 || u.RebootRequired
}

const (
	operationsCallTimeout = 30 * time.Second
	// displayLimit bounds result and log text on the page; the rest is
	// cut with a note (host output is untrusted and can be large).
	displayLimit = 64 << 10
	listLimit    = 100
)

// operationsData is the page data of the operations pages.
type operationsData struct {
	List    []opsRow
	Actions []actionView
	Hosts   []opsHostOption
	Exec    *execView
}

type opsRow struct {
	ID, Short, Action, Risk, State, CreatedBy, Created string
	Hosts, Failed                                      int
}

type actionView struct {
	ID, Title, Description, Risk string
	ReadOnly                     bool
	Params                       []paramView
}

type paramView struct {
	Name, Label, Pattern string
}

type opsHostOption struct {
	ID, Name, Status string
	Usable           bool
}

type execView struct {
	ID, Action, Version, Risk, Requirement, State, Detail, Digest, CreatedBy, Created, Params string
	// Options is the WebAuthn request options JSON while approval is
	// pending (rendered into a data attribute, escaped by html/template).
	Options                        string
	Pending, Live, NeedsTypedCount bool
	Hosts                          []execHostView
}

type execHostView struct {
	ID, State, Class, Detail, Exit string
	Facts                          []executions.Fact
	// Updates is the parsed package.list_updates result.
	Updates *updatesView
	// Install is the parsed package.install_* result.
	Install *osdebian.Install
	// Units and Service are the parsed service.* results.
	Units   []osdebian.Unit
	Service *osdebian.ServiceStatus
	// Docker is the parsed docker.list result.
	Docker *dockerView
	// DockerLogs is the parsed docker.logs result.
	DockerLogs *dockerhost.Logs
	// DockerInspect is the parsed docker.inspect result.
	DockerInspect               *dockerhost.Inspect
	Result, Log                 string
	ResultCut, LogCut, LogTrunc bool
	OK                          bool
}

// dockerView is a docker.list result with its counts.
type dockerView struct {
	dockerhost.List
	Summary dockerhost.Summary
}

func (h *Handler) operationsEnabled(w http.ResponseWriter, r *http.Request) bool {
	if h.operations == nil {
		http.NotFound(w, r)
		return false
	}
	return true
}

func (h *Handler) handleOperations(w http.ResponseWriter, r *http.Request) {
	data := pageData{Title: "Operations", Active: "operations", Content: "operations"}
	if h.operations == nil {
		data.Content = "empty"
		h.render(w, data)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), operationsCallTimeout)
	defer cancel()
	list, err := h.operations.List(ctx, listLimit)
	if err != nil {
		h.log.Error("list executions", "error", err)
		http.Error(w, "operations unavailable", http.StatusInternalServerError)
		return
	}
	ops := &operationsData{}
	for _, e := range list {
		ops.List = append(ops.List, opsRow{ID: e.ID, Short: e.ID[:8], Action: e.ActionID, Risk: e.Risk, State: e.State,
			CreatedBy: e.CreatedBy, Created: e.CreatedAt.UTC().Format("2006-01-02 15:04 MST"), Hosts: e.Hosts, Failed: e.Failed})
	}
	data.Ops = ops
	h.render(w, data)
}

func (h *Handler) handleOperationNew(w http.ResponseWriter, r *http.Request) {
	if !h.operationsEnabled(w, r) {
		return
	}
	data := pageData{Title: "New operation", Active: "operations", Content: "operation_new", Scripts: []string{"webauthn.js", "operations.js"}}
	ops := &operationsData{}
	for _, a := range actions.Builtin {
		v := actionView{ID: a.ID, Title: a.Title, Description: a.Description,
			Risk: strings.TrimPrefix(a.Risk.String(), "RISK_CLASS_"), ReadOnly: a.ReadOnly}
		for _, p := range a.Params {
			v.Params = append(v.Params, paramView{Name: p.Name, Label: p.Label, Pattern: strings.TrimSuffix(strings.TrimPrefix(p.Pattern.String(), "^"), "$")})
		}
		ops.Actions = append(ops.Actions, v)
	}
	ctx, cancel := context.WithTimeout(r.Context(), inventoryCallTimeout)
	defer cancel()
	if h.hosts != nil {
		hosts, err := h.hosts(ctx)
		if err != nil {
			h.log.Error("list hosts", "error", err)
		}
		keys := map[string]string{}
		usable := map[string]bool{}
		if h.hostKeys != nil {
			if pins, err := h.hostKeys(ctx); err == nil {
				for _, p := range pins {
					if p.GetBlocked() {
						keys[p.GetHostId()] = "blocked (host key mismatch)"
					} else {
						keys[p.GetHostId()], usable[p.GetHostId()] = "enrolled", true
					}
				}
			} else {
				h.log.Error("list host keys", "error", err)
			}
		}
		for _, x := range hosts {
			st := keys[x.ID]
			if st == "" {
				st = "not enrolled"
			}
			name := x.DisplayName
			if name == "" {
				name = x.ID
			}
			ops.Hosts = append(ops.Hosts, opsHostOption{ID: x.ID, Name: name, Status: st, Usable: usable[x.ID]})
		}
	}
	data.Ops = ops
	h.render(w, data)
}

// cut returns at most limit bytes of b as valid UTF-8 text and whether it
// was cut.
func cut(b []byte, limit int) (string, bool) {
	if len(b) <= limit {
		return strings.ToValidUTF8(string(b), "�"), false
	}
	b = b[:limit]
	// Do not end inside a multi-byte sequence.
	for i := 0; i < utf8.UTFMax && len(b) > 0 && !utf8.Valid(b); i++ {
		b = b[:len(b)-1]
	}
	return strings.ToValidUTF8(string(b), "�"), true
}

func (h *Handler) handleOperation(w http.ResponseWriter, r *http.Request) {
	if !h.operationsEnabled(w, r) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), operationsCallTimeout)
	defer cancel()
	e, err := h.operations.Get(ctx, r.PathValue("id"))
	if errors.Is(err, executions.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		h.log.Error("get execution", "error", err)
		http.Error(w, "operations unavailable", http.StatusInternalServerError)
		return
	}
	v := &execView{ID: e.ID, Action: e.ActionID, Version: e.ModuleVersion, Risk: e.Risk, Requirement: e.Requirement, State: e.State,
		Detail: e.Detail, Digest: e.Digest, CreatedBy: e.CreatedBy, Created: e.CreatedAt.UTC().Format("2006-01-02 15:04:05 MST"),
		Pending: e.State == "pending", Live: e.State == "approved" || e.State == "running",
		NeedsTypedCount: e.Requirement == "assertion_verified_typed_count"}
	if e.Params != "" && e.Params != "{}" {
		v.Params = e.Params
	}
	if v.Pending && len(e.Options) > 0 && json.Valid(e.Options) {
		v.Options = string(e.Options)
	}
	for _, x := range e.Hosts {
		hv := execHostView{ID: x.HostID, State: x.State, Class: x.Class, Detail: x.Detail, OK: x.Class == "success", LogTrunc: x.LogTruncated}
		if x.State == "finished" && x.ExitCode >= 0 {
			hv.Exit = strconv.Itoa(x.ExitCode)
		}
		if e.ActionID == "core.facts" && x.Class == "success" {
			hv.Facts = executions.DecodeFacts(x.Result)
		}
		if strings.HasPrefix(e.ActionID, "package.install_") && len(x.Result) > 0 {
			if in, err := osdebian.ParseInstall(x.Result); err == nil {
				hv.Install = &in
			}
		}
		if e.ActionID == "service.list" && x.Class == "success" {
			hv.Units, _ = osdebian.ParseUnits(x.Result)
		}
		if strings.HasPrefix(e.ActionID, "service.") && e.ActionID != "service.list" && len(x.Result) > 0 {
			if st, err := osdebian.ParseServiceStatus(x.Result); err == nil {
				hv.Service = &st
			}
		}
		if e.ActionID == "docker.list" && len(x.Result) > 0 {
			if l, err := dockerhost.ParseList(x.Result); err == nil {
				hv.Docker = &dockerView{List: l, Summary: l.Summary()}
			}
		}
		if e.ActionID == "docker.logs" && len(x.Result) > 0 {
			if l, err := dockerhost.ParseLogs(x.Result); err == nil {
				hv.DockerLogs = &l
			}
		}
		if e.ActionID == "docker.inspect" && len(x.Result) > 0 {
			if in, err := dockerhost.ParseInspect(x.Result); err == nil {
				hv.DockerInspect = &in
			}
		}
		if e.ActionID == "package.list_updates" && x.Class == "success" {
			if u, err := osdebian.ParseUpdates(x.Result); err == nil {
				hv.Updates = viewUpdates(u)
			}
		}
		res := x.Result
		var pretty bytes.Buffer
		if len(res) > 0 && json.Indent(&pretty, res, "", "  ") == nil {
			res = pretty.Bytes()
		}
		hv.Result, hv.ResultCut = cut(res, displayLimit)
		hv.Log, hv.LogCut = cut(x.Log, displayLimit)
		v.Hosts = append(v.Hosts, hv)
	}
	data := pageData{Title: "Operation " + e.ID[:8], Active: "operations", Content: "operation",
		Scripts: []string{"webauthn.js", "operations.js"}, Ops: &operationsData{Exec: v}}
	h.render(w, data)
}

func webUser(r *http.Request) string {
	if s, ok := auth.SessionFrom(r.Context()); ok {
		return s.UserName
	}
	return "unknown"
}

// readOpsJSON decodes a small JSON body; unknown fields are rejected.
func readOpsJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if ct, _, _ := strings.Cut(r.Header.Get("Content-Type"), ";"); !strings.EqualFold(strings.TrimSpace(ct), "application/json") {
		writeJSONError(w, http.StatusUnsupportedMediaType, "Content-Type must be application/json")
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeJSONError(w, http.StatusBadRequest, "request body is not valid JSON")
		return false
	}
	return true
}

// executorRefusal maps an executor error to a message for the browser.
// The executor's messages for refusals describe the request (risk,
// session, lock state); anything else is a fixed text and goes to the log.
func (h *Handler) executorRefusal(w http.ResponseWriter, op string, err error) {
	st, _ := status.FromError(err)
	switch st.Code() {
	case codes.InvalidArgument, codes.FailedPrecondition, codes.PermissionDenied, codes.ResourceExhausted, codes.AlreadyExists, codes.NotFound:
		msg := st.Message()
		if len(msg) > 300 {
			msg = msg[:300]
		}
		writeJSONError(w, http.StatusConflict, "the executor refused: "+msg)
	default:
		h.log.Error(op, "error", err)
		writeJSONError(w, http.StatusBadGateway, "executor unavailable")
	}
}

func (h *Handler) handleOperationCreate(w http.ResponseWriter, r *http.Request) {
	if !h.operationsEnabled(w, r) {
		return
	}
	var in struct {
		Action string            `json:"action"`
		Hosts  []string          `json:"hosts"`
		Params map[string]string `json:"params"`
	}
	if !readOpsJSON(w, r, &in) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), operationsCallTimeout)
	defer cancel()
	c, err := h.operations.Create(ctx, webUser(r), in.Action, in.Hosts, in.Params)
	var he *executions.HostError
	var pe *executions.ParamError
	switch {
	case err == nil:
		writeJSON(w, http.StatusOK, map[string]any{"id": c.ID, "state": c.State, "risk": c.Risk})
	case errors.Is(err, executions.ErrUnknownAction), errors.Is(err, executions.ErrNoHosts), errors.Is(err, executions.ErrTooManyHosts), errors.As(err, &he), errors.As(err, &pe):
		writeJSONError(w, http.StatusBadRequest, err.Error())
	default:
		if st, ok := status.FromError(err); ok && st.Code() != codes.Unknown {
			h.executorRefusal(w, "propose execution", err)
			return
		}
		h.log.Error("create execution", "error", err)
		writeJSONError(w, http.StatusInternalServerError, "operations unavailable")
	}
}

func (h *Handler) handleOperationApprove(w http.ResponseWriter, r *http.Request) {
	if !h.operationsEnabled(w, r) {
		return
	}
	var in struct {
		ID         string          `json:"id"`
		Assertion  json.RawMessage `json:"assertion"`
		TypedCount uint32          `json:"typed_count"`
	}
	if !readOpsJSON(w, r, &in) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), operationsCallTimeout)
	defer cancel()
	err := h.operations.Approve(ctx, webUser(r), in.ID, in.Assertion, in.TypedCount)
	switch {
	case err == nil:
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	case errors.Is(err, executions.ErrNotFound):
		writeJSONError(w, http.StatusNotFound, "operation not found")
	case errors.Is(err, executions.ErrNotPending):
		writeJSONError(w, http.StatusConflict, "the operation is not waiting for approval")
	default:
		switch status.Code(err) {
		case codes.PermissionDenied, codes.Unauthenticated:
			writeJSONError(w, http.StatusForbidden, "security key not accepted (or the typed number of hosts is wrong)")
		case codes.FailedPrecondition, codes.NotFound, codes.InvalidArgument:
			h.executorRefusal(w, "approve execution", err)
		default:
			h.log.Error("approve execution", "error", err)
			writeJSONError(w, http.StatusBadGateway, "executor unavailable")
		}
	}
}

// maxShownPackages bounds the update table on the page.
const maxShownPackages = 500

type updatesView struct {
	Total, Security, Kernel int
	Reboot                  bool
	RebootPackages          string
	ListsUpdated            string
	Packages                []osdebian.Package
	More                    int
}

func viewUpdates(u osdebian.Updates) *updatesView {
	v := &updatesView{Total: len(u.Packages), Security: u.Security, Kernel: u.Kernel, Reboot: u.RebootRequired,
		RebootPackages: strings.Join(u.RebootPackages, ", ")}
	if !u.ListsUpdated.IsZero() {
		v.ListsUpdated = u.ListsUpdated.UTC().Format("2006-01-02 15:04 MST")
	}
	v.Packages = u.Packages
	if len(v.Packages) > maxShownPackages {
		v.More = len(v.Packages) - maxShownPackages
		v.Packages = v.Packages[:maxShownPackages]
	}
	return v
}

// opsStateView is the inventory text of a host's Ops State. A blocked pin
// is UNREACHABLE whatever the last run said.
func opsStateView(o executions.OpsState, keyStatus string) (string, string) {
	if strings.HasPrefix(keyStatus, "BLOCKED") {
		return executions.StateUnreachable, "host key mismatch: blocked until re-pinned"
	}
	if keyStatus == "not enrolled" {
		return executions.StateUnknown, "not enrolled"
	}
	if o.State == "" {
		return executions.StateUnknown, "not checked yet"
	}
	reason := o.Reason
	if !o.ObservedAt.IsZero() {
		reason = o.ObservedAt.UTC().Format("2006-01-02 15:04 MST") + " · " + reason
	}
	return o.State, reason
}

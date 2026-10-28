// SPDX-License-Identifier: AGPL-3.0-or-later

package ui

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
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
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/scanner"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/auth"
)

// Operations plans and follows executions (executions.Service).
type Operations interface {
	CreateStaged(ctx context.Context, user, actionID string, hosts []string, params map[string]string, plan executions.Plan) (executions.Created, error)
	Approve(ctx context.Context, user, id string, assertion []byte, typedTargets uint32) error
	Get(ctx context.Context, id string) (executions.Execution, error)
	List(ctx context.Context, limit int) ([]executions.Summary, error)
	AllUpdates(ctx context.Context) (map[string]executions.HostUpdates, error)
	// Updates is one host's latest update list with its packages.
	Updates(ctx context.Context, host string) (executions.HostUpdates, error)
	AllOpsStates(ctx context.Context) (map[string]executions.OpsState, error)
	// LastResults is the latest successful result per host for one
	// action (one query, not one per host).
	LastResults(ctx context.Context, actionID string) (map[string]executions.LastResultRow, error)
	// LastSeenAll is the newest finished execution per host.
	LastSeenAll(ctx context.Context) (map[string]time.Time, error)
	// ListHosts is the host IDs of the given executions (one query).
	ListHosts(ctx context.Context, ids []string) (map[string][]string, error)
	// ListHost is the newest executions that targeted a host (the host
	// page's operations tab).
	ListHost(ctx context.Context, host string, limit int) ([]executions.Summary, error)
	Rollout(ctx context.Context, id string) (*pb.Rollout, error)
	BeginGate(ctx context.Context, user, id string, g executions.Gate) (executions.GateResult, error)
	CommitGate(ctx context.Context, user, id string, g executions.Gate, assertion []byte) error
	Abort(ctx context.Context, user, id string) error
	RetryHost(ctx context.Context, user, id, host string) error
	// CheckCLIApproval asks the executor for the permit state of one
	// execution (the "Check approval" button) and returns its state after
	// the check.
	CheckCLIApproval(ctx context.Context, id string) (string, error)
	// Catalog lists the plannable actions (built-ins, then runbooks).
	Catalog(ctx context.Context) ([]actions.Action, error)
	// Action finds an action at a version ("" for the current one).
	Action(ctx context.Context, id, version string) (actions.Action, bool, error)
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
	// Items is the list: single operations and groups, newest first.
	Items []opsItem
	// Pending are the operations waiting for approval (the section at
	// the top of the page).
	Pending []opsRow
	// StateFilter is the active ?state= chip.
	StateFilter string
	Actions     []actionView
	Hosts       []opsHostOption
	Exec        *execView
}

type opsRow struct {
	ID, Short, Action, Title, Risk, State, StateClass, CreatedBy string
	Created, Finished                                            time.Time
	FinishedSet                                                  bool
	Hosts, Failed                                                int
	// HostNames is the compact host display (first 3 names + "+N").
	HostNames string
	// Search is the lowercased text the client-side filter matches
	// (ID, action, host names).
	Search string
	// hostKey is the sorted host set (grouping key, not rendered).
	hostKey string
}

// opsItem is one row of the operations list: a single operation or a
// group of operations created together (the inventory bulk refresh).
type opsItem struct {
	Row   *opsRow
	Group *opsGroup
}

// opsGroup is a batch of operations collapsed into one expandable row.
type opsGroup struct {
	Label     string
	Hosts     int
	CreatedBy string
	Created   time.Time
	Search    string
	Rows      []opsRow
}

type actionView struct {
	ID, Title, Description, Risk string
	ReadOnly, Selected           bool
	Params                       []paramView
	// Scanner lists the Safety Scanner's categories for the script.
	Scanner []string
	// Secrets are the action's secret slots.
	Secrets []string
}

type paramView struct {
	Name, Label, Pattern string
	// Value prefills the input (?param=name=value; the value comes from
	// the user's own URL and is validated by the action's pattern and
	// by the executor).
	Value string
}

type opsHostOption struct {
	ID, Name, Status string
	Usable           bool
	// Checked preselects the host (a quick action from search: ?host=ID).
	Checked bool
}

type execView struct {
	ID, Action, Version, Risk, Requirement, State, Detail, Digest, CreatedBy, Params string
	Created                                                                          time.Time
	// Options is the WebAuthn request options JSON while approval is
	// pending (rendered into a data attribute, escaped by html/template).
	Options                        string
	Pending, Live, NeedsTypedCount bool
	// Expired is true when the approval window ended before anyone
	// approved (issue #71): nothing was run. PlanAgain opens the
	// operation form prefilled with the same action, hosts and parameters.
	Expired   bool
	PlanAgain string
	// Scanner holds the Safety Scanner's findings for the action's script
	// (advisory; the executor applies the same list to the risk).
	Scanner []scanner.Finding
	// ScriptPreview is the first lines of the action's script (at most 40
	// lines / 4 KiB), shown collapsed next to the scanner findings.
	ScriptPreview string
	Hosts         []execHostView
	// Rollout is the stage view of a staged operation.
	Rollout *rolloutView
}

type execHostView struct {
	ID, State, Class, Detail, Exit string
	Stage                          int
	CanSkip, CanRetry              bool
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
	DockerInspect *dockerhost.Inspect
	// Compose is the parsed docker.compose_update result.
	Compose *dockerhost.ComposeUpdate
	// DockerUpdates is the parsed docker.check_updates result.
	DockerUpdates *dockerhost.ImageUpdates
	// DockerControl is the parsed docker.start/stop/restart result.
	DockerControl               *dockerhost.Control
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
	data := pageData{Title: "Operations", Active: "operations", Content: "operations", Scripts: []string{"operations.js"}}
	if h.operations == nil {
		data.Content = "empty"
		h.render(w, r, data)
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
	ids := make([]string, len(list))
	for i, e := range list {
		ids[i] = e.ID
	}
	hostIDs, err := h.operations.ListHosts(ctx, ids)
	if err != nil {
		h.log.Error("list execution hosts", "error", err)
		hostIDs = map[string][]string{}
	}
	catalog, err := h.operations.Catalog(ctx)
	if err != nil {
		h.log.Error("action catalog", "error", err)
	}
	readOnly := map[string]bool{}
	actionTitle := map[string]string{}
	for _, a := range catalog {
		readOnly[a.ID] = a.ReadOnly
		actionTitle[a.ID] = a.Title
	}
	names := map[string]string{}
	if h.hosts != nil {
		if hosts, err := h.hosts(ctx); err == nil {
			for _, x := range hosts {
				name := x.DisplayName
				if name == "" {
					name = x.ID
				}
				names[x.ID] = name
			}
		}
	}
	stateF := r.URL.Query().Get("state")
	switch stateF {
	case "", "pending", "running", "finished", "failed", "expired":
	default:
		stateF = "" // invalid values are ignored
	}
	var rows, pending []opsRow
	for _, e := range list {
		row := opsRow{ID: e.ID, Short: e.ID[:8], Action: e.ActionID, Title: actionTitle[e.ActionID],
			Risk: e.Risk, State: e.State, StateClass: opsStateClass(e.State), CreatedBy: e.CreatedBy,
			Created: e.CreatedAt.UTC(), Finished: e.FinishedAt.UTC(), FinishedSet: !e.FinishedAt.IsZero(),
			Hosts: e.Hosts, Failed: e.Failed, hostKey: strings.Join(hostIDs[e.ID], "\n")}
		var parts []string
		for _, id := range hostIDs[e.ID] {
			n := names[id]
			if n == "" {
				n = id
			}
			parts = append(parts, n)
		}
		row.HostNames = compactHosts(parts)
		row.Search = strings.ToLower(e.ID + " " + e.ActionID + " " + strings.Join(parts, " "))
		if e.State == "pending" {
			pending = append(pending, row)
		}
		if stateF != "" && e.State != stateF {
			continue
		}
		rows = append(rows, row)
	}
	data.Ops = &operationsData{Items: groupOpsRows(rows, readOnly, stateF == ""), Pending: pending, StateFilter: stateF}
	h.render(w, r, data)
}

// opsStateClass is the badge class of an execution state.
func opsStateClass(state string) string {
	switch state {
	case "pending":
		return "badge--pending"
	case "approved", "running":
		return "badge--warning"
	case "finished":
		return "badge--ok"
	case "failed":
		return "badge--critical"
	case "expired":
		return "badge--expired"
	default:
		return "badge--unknown"
	}
}

// compactHosts renders at most three names plus "+N" for the rest.
func compactHosts(names []string) string {
	if len(names) <= 3 {
		return strings.Join(names, ", ")
	}
	return strings.Join(names[:3], ", ") + " +" + strconv.Itoa(len(names)-3)
}

// groupOpsRows collapses consecutive operations created in the same
// second by the same user for the same host set into one expandable row
// — that is what the inventory bulk refresh creates. Only read-only
// operations are grouped, and only without an active state filter.
func groupOpsRows(rows []opsRow, readOnly map[string]bool, group bool) []opsItem {
	items := make([]opsItem, 0, len(rows))
	for i := 0; i < len(rows); {
		j := i + 1
		for group && j < len(rows) && sameBatch(&rows[i], &rows[j], readOnly) {
			j++
		}
		if j-i >= 2 {
			first := rows[i]
			search := make([]string, 0, j-i)
			for _, x := range rows[i:j] {
				search = append(search, x.Search)
			}
			items = append(items, opsItem{Group: &opsGroup{
				Label: "Refresh (" + strconv.Itoa(j-i) + " reads)", Hosts: first.Hosts, CreatedBy: first.CreatedBy,
				Created: first.Created, Search: strings.Join(search, " "), Rows: rows[i:j],
			}})
		} else {
			items = append(items, opsItem{Row: &rows[i]})
		}
		i = j
	}
	return items
}

// sameBatch reports whether b belongs to the batch started by a: both
// read-only, same creation second, same user, same host set.
func sameBatch(a, b *opsRow, readOnly map[string]bool) bool {
	if !readOnly[a.Action] || !readOnly[b.Action] {
		return false
	}
	return a.CreatedBy == b.CreatedBy && a.hostKey == b.hostKey &&
		a.Created.Truncate(time.Second) == b.Created.Truncate(time.Second)
}

func (h *Handler) handleOperationNew(w http.ResponseWriter, r *http.Request) {
	if !h.operationsEnabled(w, r) {
		return
	}
	data := pageData{Title: "New operation", Active: "operations", Content: "operation_new", Scripts: []string{"webauthn.js", "operations.js"}}
	ops := &operationsData{}
	cctx, ccancel := context.WithTimeout(r.Context(), operationsCallTimeout)
	catalog, err := h.operations.Catalog(cctx)
	ccancel()
	if err != nil {
		h.log.Error("action catalog", "error", err)
	}
	want := r.URL.Query().Get("action")
	if !slices.ContainsFunc(catalog, func(a actions.Action) bool { return a.ID == want }) && len(catalog) > 0 {
		want = catalog[0].ID
	}
	// Param prefill: ?param=name=value, repeatable (a container action
	// link from the host page).
	paramValues := map[string]string{}
	for _, p := range r.URL.Query()["param"] {
		if name, value, ok := strings.Cut(p, "="); ok {
			paramValues[name] = value
		}
	}
	for _, a := range catalog {
		v := actionView{ID: a.ID, Title: a.Title, Description: a.Description, Selected: a.ID == want,
			Risk: strings.TrimPrefix(a.Risk.String(), "RISK_CLASS_"), ReadOnly: a.ReadOnly}
		f, _ := scanner.Scan(a.Script)
		v.Scanner = scanner.Categories(f)
		v.Secrets = a.Secrets
		for _, p := range a.Params {
			v.Params = append(v.Params, paramView{Name: p.Name, Label: p.Label, Value: paramValues[p.Name],
				Pattern: strings.TrimSuffix(strings.TrimPrefix(p.Pattern.String(), "^"), "$")})
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
			ops.Hosts = append(ops.Hosts, opsHostOption{ID: x.ID, Name: name, Status: st, Usable: usable[x.ID],
				Checked: usable[x.ID] && slices.Contains(r.URL.Query()["host"], x.ID)})
		}
	}
	data.Ops = ops
	h.render(w, r, data)
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

// scriptPreview returns the first 40 lines of b, at most 4 KiB, as valid
// UTF-8 text, for the operation page's collapsed script preview.
func scriptPreview(b []byte) string {
	const maxLines = 40
	const maxBytes = 4 << 10
	if len(b) > maxBytes {
		b = b[:maxBytes]
	}
	off := 0
	for i := 0; i < maxLines; i++ {
		j := bytes.IndexByte(b[off:], '\n')
		if j < 0 {
			// Fewer than maxLines lines: keep the rest.
			return strings.ToValidUTF8(string(b), "�")
		}
		off += j + 1 // keep the newline
	}
	return strings.ToValidUTF8(string(b[:off]), "�")
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
		Detail: e.Detail, Digest: e.Digest, CreatedBy: e.CreatedBy, Created: e.CreatedAt.UTC(),
		Pending: e.State == "pending", Live: e.State == "approved" || e.State == "running",
		NeedsTypedCount: e.Requirement == "assertion_verified_typed_count"}
	if e.State == "expired" {
		v.Expired = true
		v.PlanAgain = planAgainURL(e)
	}
	if e.Params != "" && e.Params != "{}" {
		v.Params = e.Params
	}
	if a, ok, err := h.operations.Action(ctx, e.ActionID, e.ModuleVersion); err == nil && ok && a.SHA256() == e.ArtifactSHA256 {
		v.Scanner, _ = scanner.Scan(a.Script)
		v.ScriptPreview = scriptPreview(a.Script)
	}
	if v.Pending && len(e.Options) > 0 && json.Valid(e.Options) {
		v.Options = string(e.Options)
	}
	for _, x := range e.Hosts {
		hv := execHostView{ID: x.HostID, State: x.State, Class: x.Class, Detail: x.Detail, OK: x.Class == "success", LogTrunc: x.LogTruncated, Stage: x.Stage}
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
		switch e.ActionID {
		case "docker.compose_update":
			if c, err := dockerhost.ParseComposeUpdate(x.Result); err == nil && len(x.Result) > 0 {
				hv.Compose = &c
			}
		case "docker.check_updates":
			if u, err := dockerhost.ParseImageUpdates(x.Result); err == nil && len(x.Result) > 0 {
				hv.DockerUpdates = &u
			}
		case "docker.start", "docker.stop", "docker.restart":
			if c, err := dockerhost.ParseControl(x.Result); err == nil && len(x.Result) > 0 {
				hv.DockerControl = &c
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
	h.rolloutFor(ctx, e, v)
	data := pageData{Title: "Operation " + e.ID[:8], Active: "operations", Content: "operation",
		Scripts: []string{"webauthn.js", "operations.js"}, Ops: &operationsData{Exec: v}}
	h.render(w, r, data)
}

// planAgainURL is the operation form prefilled with the execution's action,
// hosts and parameters (issue #71), reusing the same prefill a container
// action link from the host page uses: ?action=, ?host= (repeatable) and
// ?param=name=value (repeatable).
func planAgainURL(e executions.Execution) string {
	q := url.Values{}
	q.Set("action", e.ActionID)
	for _, x := range e.Hosts {
		q.Add("host", x.HostID)
	}
	if e.Params != "" && e.Params != "{}" {
		var pm map[string]string
		if json.Unmarshal([]byte(e.Params), &pm) == nil {
			for k, val := range pm {
				q.Add("param", k+"="+val)
			}
		}
	}
	return "/operations/new?" + q.Encode()
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
		Action  string            `json:"action"`
		Hosts   []string          `json:"hosts"`
		Params  map[string]string `json:"params"`
		Secrets map[string]string `json:"secrets"`
		Plan    *struct {
			Preset    string `json:"preset"`
			Size      int    `json:"size"`
			Continue  string `json:"continue"`
			MaxFailed int    `json:"max_failed"`
		} `json:"plan"`
	}
	if !readOpsJSON(w, r, &in) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), operationsCallTimeout)
	defer cancel()
	var plan executions.Plan
	if in.Plan != nil {
		plan = executions.Plan{Preset: in.Plan.Preset, Size: in.Plan.Size, Continue: in.Plan.Continue, MaxFailed: in.Plan.MaxFailed}
	}
	plan.Secrets = in.Secrets
	c, err := h.operations.CreateStaged(ctx, webUser(r), in.Action, in.Hosts, in.Params, plan)
	var he *executions.HostError
	var pe *executions.ParamError
	var ple *executions.PlanError
	switch {
	case err == nil:
		out := map[string]any{"id": c.ID, "state": c.State, "risk": c.Risk, "requirement": c.Requirement}
		// Options are the WebAuthn request options JSON the browser
		// approves with; the in-place run UI (runop.js) needs them in
		// the response instead of a detour through the operation page.
		if len(c.Options) > 0 {
			out["options"] = json.RawMessage(c.Options)
		}
		writeJSON(w, http.StatusOK, out)
	case errors.Is(err, executions.ErrUnknownAction), errors.Is(err, executions.ErrNoHosts), errors.Is(err, executions.ErrTooManyHosts), errors.As(err, &he), errors.As(err, &pe), errors.As(err, &ple):
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

// handleOperationCheck is the "Check approval" button of the operation page
// for operations that are approved on the executor host (hardened path): it
// asks the executor for the permit state of that one execution, records it
// when approved, and returns the new state.
func (h *Handler) handleOperationCheck(w http.ResponseWriter, r *http.Request) {
	if !h.operationsEnabled(w, r) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), operationsCallTimeout)
	defer cancel()
	state, err := h.operations.CheckCLIApproval(ctx, r.PathValue("id"))
	switch {
	case err == nil:
		writeJSON(w, http.StatusOK, map[string]string{"state": state})
	case errors.Is(err, executions.ErrNotFound):
		writeJSONError(w, http.StatusNotFound, "operation not found")
	default:
		h.log.Error("check CLI approval", "error", err)
		writeJSONError(w, http.StatusBadGateway, "executor unavailable")
	}
}

// maxShownPackages bounds the update table on the page.
const maxShownPackages = 500

type updatesView struct {
	Total, Security, Kernel int
	Reboot                  bool
	RebootPackages          string
	ListsUpdated            time.Time
	Packages                []osdebian.Package
	More                    int
}

func viewUpdates(u osdebian.Updates) *updatesView {
	v := &updatesView{Total: len(u.Packages), Security: u.Security, Kernel: u.Kernel, Reboot: u.RebootRequired,
		RebootPackages: strings.Join(u.RebootPackages, ", ")}
	if !u.ListsUpdated.IsZero() {
		v.ListsUpdated = u.ListsUpdated.UTC()
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

// SPDX-License-Identifier: AGPL-3.0-or-later

package ui

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions"
	"github.com/nebula-operation-station/nebula-operation-station/web/templates"
)

// Batch pages (ADR 0007 E13). GET /batches lists batches with their
// outcome counts; GET /batches/new shows the plan form; POST
// /batches/create plans and proposes a batch and redirects to GET
// /batches/{id}, which shows the complete frozen plan before approval
// (every member with its action, version, artifact hash, exact
// parameters, target, host key, credential, container and risk; the
// stages with their gates and thresholds; total counts) and every
// member's outcome afterwards. Nothing is truncated or summarized away.
// POST /batches/approve relays the security key assertion (schedules.js);
// in hardened mode the page shows the CLI command instead. POST
// /batches/refresh asks the executor whether it still holds the approval;
// POST /batches/skip skips one planned member.
//
// There is no retry, redispatch or rollback control: a batch is not a
// transaction, and a retry or rollback is a new batch with a fresh
// approval.
//
// Every string from the plan, the inventory, a host or the executor is
// untrusted and rendered by html/template as text only.

// Limits of the batch plan form.
const (
	maxBatchPlanBytes = 64 << 10
	maxBatchPlanLines = 300
	maxBatchLineBytes = 1024
	maxBatchParams    = 8
	batchCLICommand   = "nebula approve "
)

// BatchPlanner plans, proposes and follows batches.
// executions.Batches satisfies it.
type BatchPlanner interface {
	ListBatches(ctx context.Context) ([]executions.BatchSummary, error)
	Batch(ctx context.Context, id string) (executions.BatchView, error)
	ProposeBatch(ctx context.Context, user string, req executions.BatchRequest) (executions.BatchCreated, error)
	ApproveBatch(ctx context.Context, user, id string, assertion []byte) error
	RefreshBatch(ctx context.Context, id string) error
	SkipMember(ctx context.Context, user, batchID, memberID string) error
}

// BatchPages serves the batch pages. Register mounts them on a mux; the
// mux must sit behind the same session, privileged-session and origin
// middleware as the other state-changing UI routes.
type BatchPages struct {
	batches BatchPlanner
	log     *slog.Logger
	pages   map[string]*template.Template
}

// batchPageFiles maps a batch page to its template file.
var batchPageFiles = map[string]string{
	"batches":   "batches.html",
	"batch":     "batch.html",
	"batch_new": "batch_new.html",
}

// NewBatchPages parses the batch templates.
func NewBatchPages(b BatchPlanner, log *slog.Logger) (*BatchPages, error) {
	if b == nil {
		return nil, errors.New("batch pages: planner required")
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	p := &BatchPages{batches: b, log: log, pages: map[string]*template.Template{}}
	for name, file := range batchPageFiles {
		t, err := template.New("").Funcs(template.FuncMap{"timeTag": timeTag}).ParseFS(templates.FS, "batch_layout.html", file)
		if err != nil {
			return nil, fmt.Errorf("parse batch template %s: %w", file, err)
		}
		p.pages[name] = t
	}
	return p, nil
}

// Register mounts the batch routes on mux.
func (p *BatchPages) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /batches", p.handleList)
	mux.HandleFunc("GET /batches/new", p.handleNew)
	mux.HandleFunc("POST /batches/create", p.handleCreate)
	mux.HandleFunc("GET /batches/{id}", p.handleBatch)
	mux.HandleFunc("POST /batches/approve", p.handleApprove)
	mux.HandleFunc("POST /batches/refresh", p.handleRefresh)
	mux.HandleFunc("POST /batches/skip", p.handleSkip)
}

// batchPage is the data of every batch page.
type batchPage struct {
	Title   string
	Theme   string
	Scripts []string
	Error   string
	List    []batchRow
	Batch   *batchDetail
}

type batchRow struct {
	executions.BatchSummary
	StateClass string
}

type batchDetail struct {
	executions.BatchView
	StateClass   string
	OptionsJSON  string
	CLICommand   string
	CanApprove   bool
	CanRefresh   bool
	MemberRows   []batchMemberRow
	StageSummary string
}

type batchMemberRow struct {
	executions.BatchMemberView
	OutcomeClass string
	OutcomeText  string
	CanSkip      bool
}

// batchIDRe is a batch ID (a UUID).
var batchIDRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// batchMemberIDRe is a planner-made member ID.
var batchMemberIDRe = regexp.MustCompile(`^m-[0-9]{3}$`)

func (p *BatchPages) render(w http.ResponseWriter, r *http.Request, name string, status int, data batchPage) {
	data.Theme = themeFromRequest(r)
	var buf bytes.Buffer
	if err := p.pages[name].ExecuteTemplate(&buf, "batch_layout", data); err != nil {
		p.log.Error("render batch page", "page", name, "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

func batchStateClass(state string) string {
	switch state {
	case "approved":
		return "badge--ok"
	case "pending":
		return "badge--pending"
	default:
		return "badge--expired"
	}
}

// batchOutcomeLabel is the shown name and badge class of a member outcome.
func batchOutcomeLabel(o string) (text, class string) {
	switch o {
	case executions.OutcomePlanned:
		return "planned", "badge--pending"
	case executions.OutcomeDispatched:
		return "running", "badge--blue"
	case executions.OutcomeSuccess:
		return "success", "badge--ok"
	case executions.OutcomeFailed:
		return "failed", "badge--critical"
	case executions.OutcomeSkipped:
		return "skipped", "badge--grey"
	case executions.OutcomeNotExecuted:
		return "not executed", "badge--grey"
	default:
		return "unknown", "badge--warning"
	}
}

func (p *BatchPages) handleList(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), operationsCallTimeout)
	defer cancel()
	list, err := p.batches.ListBatches(ctx)
	data := batchPage{Title: "Batches"}
	if err != nil {
		p.log.Error("list batches", "error", err)
		data.Error = "The batches could not be loaded."
	}
	for _, s := range list {
		data.List = append(data.List, batchRow{BatchSummary: s, StateClass: batchStateClass(s.State)})
	}
	p.render(w, r, "batches", http.StatusOK, data)
}

func (p *BatchPages) handleNew(w http.ResponseWriter, r *http.Request) {
	p.render(w, r, "batch_new", http.StatusOK, batchPage{Title: "New batch", Scripts: []string{"formpost.js"}})
}

func (p *BatchPages) handleBatch(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !batchIDRe.MatchString(id) {
		http.NotFound(w, r)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), operationsCallTimeout)
	defer cancel()
	v, err := p.batches.Batch(ctx, id)
	if errors.Is(err, executions.ErrBatchNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		p.log.Error("load batch", "batch", id, "error", err)
		http.Error(w, "the batch could not be loaded", http.StatusBadGateway)
		return
	}
	d := &batchDetail{BatchView: v, StateClass: batchStateClass(v.State), CanRefresh: v.State == "pending" || v.State == "approved"}
	if v.State == "pending" {
		if v.Requirement == "cli_only" {
			d.CLICommand = batchCLICommand + v.Digest
		} else if len(v.Options) > 0 && json.Valid(v.Options) {
			d.OptionsJSON, d.CanApprove = string(v.Options), true
		}
	}
	d.StageSummary = fmt.Sprintf("%d members in %d stages", v.Counts.Total, len(v.Stages))
	for _, m := range v.Members {
		text, class := batchOutcomeLabel(m.Outcome)
		d.MemberRows = append(d.MemberRows, batchMemberRow{BatchMemberView: m, OutcomeText: text, OutcomeClass: class,
			CanSkip: m.Outcome == executions.OutcomePlanned && (v.State == "pending" || v.State == "approved")})
	}
	p.render(w, r, "batch", http.StatusOK, batchPage{Title: "Batch", Batch: d, Scripts: []string{"webauthn.js", "schedules.js", "formpost.js"}})
}

// textError writes a plain-text error (formpost.js shows it as text).
func textError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(msg))
}

func (p *BatchPages) handleCreate(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBatchPlanBytes+4096)
	if err := r.ParseForm(); err != nil {
		textError(w, http.StatusRequestEntityTooLarge, "the plan is too large")
		return
	}
	req, err := parseBatchPlan(r.PostForm.Get("plan"))
	if err != nil {
		textError(w, http.StatusBadRequest, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*operationsCallTimeout)
	defer cancel()
	c, err := p.batches.ProposeBatch(ctx, webUser(r), req)
	if err != nil {
		var ie *executions.BatchInputError
		var he *executions.HostError
		var ce *executions.BatchCriticalError
		switch {
		case errors.As(err, &ce):
			var b strings.Builder
			b.WriteString("Refused: CRITICAL members cannot be approved in a batch. Remove them and approve each separately:")
			for _, m := range ce.Members {
				fmt.Fprintf(&b, "\n%s: %s on %s %s", m.MemberID, m.ActionID, m.HostID, m.Params)
			}
			textError(w, http.StatusUnprocessableEntity, b.String())
		case errors.As(err, &ie):
			textError(w, http.StatusBadRequest, ie.Reason)
		case errors.As(err, &he):
			textError(w, http.StatusBadRequest, he.Error())
		case errors.Is(err, executions.ErrBatchCredentials), errors.Is(err, executions.ErrBatchContainer), errors.Is(err, executions.ErrBatchAnswer):
			textError(w, http.StatusBadGateway, err.Error())
		default:
			p.log.Error("propose batch", "error", err)
			textError(w, http.StatusBadGateway, "the batch could not be proposed")
		}
		return
	}
	http.Redirect(w, r, "/batches/"+c.ID, http.StatusSeeOther)
}

func (p *BatchPages) handleApprove(w http.ResponseWriter, r *http.Request) {
	var in struct {
		ID        string          `json:"id"`
		Assertion json.RawMessage `json:"assertion"`
	}
	if !readOpsJSON(w, r, &in) {
		return
	}
	if !batchIDRe.MatchString(in.ID) {
		writeJSONError(w, http.StatusNotFound, "batch not found")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), operationsCallTimeout)
	defer cancel()
	if err := p.batches.ApproveBatch(ctx, webUser(r), in.ID, in.Assertion); err != nil {
		switch {
		case errors.Is(err, executions.ErrBatchNotFound):
			writeJSONError(w, http.StatusNotFound, err.Error())
		case errors.Is(err, executions.ErrBatchNotPending):
			writeJSONError(w, http.StatusConflict, err.Error())
		default:
			p.log.Error("approve batch", "batch", in.ID, "error", err)
			writeJSONError(w, http.StatusBadGateway, "the batch could not be approved")
		}
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"done": true})
}

func (p *BatchPages) handleRefresh(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := r.ParseForm(); err != nil {
		textError(w, http.StatusBadRequest, "invalid form")
		return
	}
	id := r.PostForm.Get("id")
	if !batchIDRe.MatchString(id) {
		textError(w, http.StatusNotFound, "batch not found")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), operationsCallTimeout)
	defer cancel()
	if err := p.batches.RefreshBatch(ctx, id); err != nil {
		if errors.Is(err, executions.ErrBatchNotFound) {
			textError(w, http.StatusNotFound, "batch not found")
			return
		}
		p.log.Error("refresh batch", "batch", id, "error", err)
		textError(w, http.StatusBadGateway, "the executor could not be asked about this batch")
		return
	}
	http.Redirect(w, r, "/batches/"+id, http.StatusSeeOther)
}

func (p *BatchPages) handleSkip(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := r.ParseForm(); err != nil {
		textError(w, http.StatusBadRequest, "invalid form")
		return
	}
	id, member := r.PostForm.Get("id"), r.PostForm.Get("member")
	if !batchIDRe.MatchString(id) || !batchMemberIDRe.MatchString(member) {
		textError(w, http.StatusNotFound, "batch member not found")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), operationsCallTimeout)
	defer cancel()
	if err := p.batches.SkipMember(ctx, webUser(r), id, member); err != nil {
		switch {
		case errors.Is(err, executions.ErrBatchMemberNotFound):
			textError(w, http.StatusNotFound, "batch member not found")
		case errors.Is(err, executions.ErrBatchMemberFinal), errors.Is(err, executions.ErrBatchNotDispatchable):
			textError(w, http.StatusConflict, err.Error())
		default:
			p.log.Error("skip batch member", "batch", id, "error", err)
			textError(w, http.StatusBadGateway, "the member could not be skipped")
		}
		return
	}
	http.Redirect(w, r, "/batches/"+id, http.StatusSeeOther)
}

// batchParamKeyRe is a parameter name in a plan line.
var batchParamKeyRe = regexp.MustCompile(`^[a-z][a-z_]{0,31}$`)

// parseBatchPlan reads the plan form: one member per line,
// "<action> <host> [name=value ...]"; a line "stage [manual|automatic]
// [failures=N] [unreachable=N]" starts a new stage (the first stage is
// implicit, manual, with zero thresholds). Empty lines and lines starting
// with "#" are ignored. Members are never merged or reordered.
func parseBatchPlan(text string) (executions.BatchRequest, error) {
	if len(text) > maxBatchPlanBytes {
		return executions.BatchRequest{}, errors.New("the plan is too large")
	}
	if !utf8.ValidString(text) {
		return executions.BatchRequest{}, errors.New("the plan is not valid UTF-8")
	}
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	if len(lines) > maxBatchPlanLines {
		return executions.BatchRequest{}, fmt.Errorf("at most %d plan lines", maxBatchPlanLines)
	}
	var req executions.BatchRequest
	newStage := func() { req.Stages = append(req.Stages, executions.BatchStageSpec{Gate: "manual"}) }
	for n, line := range lines {
		if len(line) > maxBatchLineBytes {
			return executions.BatchRequest{}, fmt.Errorf("line %d is too long", n+1)
		}
		f := strings.Fields(line)
		if len(f) == 0 || strings.HasPrefix(f[0], "#") {
			continue
		}
		if f[0] == "stage" {
			if len(req.Stages) > 0 && len(req.Stages[len(req.Stages)-1].Members) == 0 {
				return executions.BatchRequest{}, fmt.Errorf("line %d: the previous stage has no members", n+1)
			}
			newStage()
			st := &req.Stages[len(req.Stages)-1]
			for _, opt := range f[1:] {
				switch {
				case opt == "manual" || opt == "automatic":
					st.Gate = opt
				case strings.HasPrefix(opt, "failures="):
					v, err := strconv.Atoi(strings.TrimPrefix(opt, "failures="))
					if err != nil || v < 0 || v > executions.MaxBatchMembers {
						return executions.BatchRequest{}, fmt.Errorf("line %d: failures must be 0 to %d", n+1, executions.MaxBatchMembers)
					}
					st.FailureThreshold = v
				case strings.HasPrefix(opt, "unreachable="):
					v, err := strconv.Atoi(strings.TrimPrefix(opt, "unreachable="))
					if err != nil || v < 0 || v > executions.MaxBatchMembers {
						return executions.BatchRequest{}, fmt.Errorf("line %d: unreachable must be 0 to %d", n+1, executions.MaxBatchMembers)
					}
					st.UnreachableThreshold = v
				default:
					return executions.BatchRequest{}, fmt.Errorf("line %d: unknown stage option", n+1)
				}
			}
			continue
		}
		if len(f) < 2 {
			return executions.BatchRequest{}, fmt.Errorf("line %d: write an action and a host", n+1)
		}
		if len(f)-2 > maxBatchParams {
			return executions.BatchRequest{}, fmt.Errorf("line %d: too many parameters", n+1)
		}
		m := executions.BatchMemberSpec{ActionID: f[0], HostID: f[1]}
		for _, kv := range f[2:] {
			k, v, ok := strings.Cut(kv, "=")
			if !ok || !batchParamKeyRe.MatchString(k) {
				return executions.BatchRequest{}, fmt.Errorf("line %d: parameters are name=value", n+1)
			}
			if m.Params == nil {
				m.Params = map[string]string{}
			}
			if _, dup := m.Params[k]; dup {
				return executions.BatchRequest{}, fmt.Errorf("line %d: parameter %s given twice", n+1, k)
			}
			m.Params[k] = v
		}
		if len(req.Stages) == 0 {
			newStage()
		}
		st := &req.Stages[len(req.Stages)-1]
		st.Members = append(st.Members, m)
	}
	if len(req.Stages) > 0 && len(req.Stages[len(req.Stages)-1].Members) == 0 {
		return executions.BatchRequest{}, errors.New("the last stage has no members")
	}
	if len(req.Stages) == 0 {
		return executions.BatchRequest{}, errors.New("add at least one member")
	}
	return req, nil
}

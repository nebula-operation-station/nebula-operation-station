// SPDX-License-Identifier: AGPL-3.0-or-later

package ui

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc"

	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/runbooks"
	"github.com/nebula-operation-station/nebula-operation-station/internal/scanner"
)

// Runbooks (spec 10, M7-2): local single-action modules. Saving creates a
// new immutable version; running one is an ordinary operation, and the
// executor rates its script itself (untrusted: at least HIGH).

// ArtifactTrust asks the executor about trust in an artifact and trusts
// one with the security key (M7-4). The executor hashes the bytes itself.
type ArtifactTrust interface {
	BeginTrustArtifact(ctx context.Context, in *pb.BeginTrustArtifactRequest, opts ...grpc.CallOption) (*pb.BeginTrustArtifactResponse, error)
	CommitTrustArtifact(ctx context.Context, in *pb.CommitTrustArtifactRequest, opts ...grpc.CallOption) (*pb.CommitTrustArtifactResponse, error)
	GetArtifactTrust(ctx context.Context, in *pb.GetArtifactTrustRequest, opts ...grpc.CallOption) (*pb.GetArtifactTrustResponse, error)
}

// Runbooks stores runbooks (internal/runbooks.Store).
type Runbooks interface {
	Save(ctx context.Context, user string, d runbooks.Draft) (runbooks.Version, error)
	Latest(ctx context.Context) ([]runbooks.Version, error)
	Versions(ctx context.Context, slug string) ([]runbooks.Version, error)
	Get(ctx context.Context, slug string, version int) (runbooks.Version, error)
}

type runbookRow struct {
	Slug, Title, Risk, Scanner string
	Created                    time.Time
	Version                    int
}

type runbookParamView struct {
	Name, Label, Type, Choices, Env string
}

type runbookVersionRow struct {
	Version          int
	Short, CreatedBy string
	Created          time.Time
}

type runbookDetail struct {
	// Trust is the executor's view: "trusted as LOW", "not trusted …" or
	// "unknown"; CanTrust offers the security-key button.
	Trust                                                                                     string
	CanTrust, Trusted                                                                         bool
	Slug, Title, Description, Risk, Kind, ActionID, ModuleVersion, SHA256, Body, TrustCommand string
	Version                                                                                   int
	Params                                                                                    []runbookParamView
	Secrets                                                                                   []runbookParamView
	Scanner                                                                                   []scanner.Finding
	Versions                                                                                  []runbookVersionRow
}

type runbookEdit struct {
	Existing bool
	// Draft is the JSON of the draft to start from (rendered into a data
	// attribute and parsed by runbooks.js).
	Draft string
}

type runbooksData struct {
	Rows   []runbookRow
	Detail *runbookDetail
	Edit   *runbookEdit
}

func (h *Handler) handleRunbooks(w http.ResponseWriter, r *http.Request) {
	if h.runbooks == nil {
		h.render(w, r, pageData{Title: "Runbooks / Modules", Active: "runbooks", Content: "empty"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), operationsCallTimeout)
	defer cancel()
	data := pageData{Title: "Runbooks", Active: "runbooks", Content: "runbooks", Runbooks: &runbooksData{}}
	list, err := h.runbooks.Latest(ctx)
	if err != nil {
		h.log.Error("list runbooks", "error", err)
	}
	for _, v := range list {
		f, _ := scanner.Scan(v.Artifact)
		data.Runbooks.Rows = append(data.Runbooks.Rows, runbookRow{Slug: v.Slug, Title: v.Title, Risk: v.Risk, Version: v.Version,
			Scanner: strings.Join(scanner.Categories(f), ", "), Created: v.CreatedAt.UTC()})
	}
	h.render(w, r, data)
}

func (h *Handler) handleRunbook(w http.ResponseWriter, r *http.Request) {
	if h.runbooks == nil {
		http.NotFound(w, r)
		return
	}
	slug := r.PathValue("slug")
	version := 0
	if s := r.URL.Query().Get("version"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 {
			http.NotFound(w, r)
			return
		}
		version = n
	}
	ctx, cancel := context.WithTimeout(r.Context(), operationsCallTimeout)
	defer cancel()
	v, err := h.runbooks.Get(ctx, slug, version)
	if errors.Is(err, runbooks.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		h.log.Error("get runbook", "error", err)
		http.Error(w, "runbooks unavailable", http.StatusInternalServerError)
		return
	}
	a := v.Action()
	d := &runbookDetail{Slug: v.Slug, Title: v.Title, Description: v.Description, Risk: v.Risk, ActionID: a.ID, ModuleVersion: a.Version,
		SHA256: v.ArtifactSHA256, Body: v.Body, Version: v.Version, Kind: "attached, timeout " + a.Timeout.String()}
	if v.Durable {
		d.Kind = "durable job, timeout " + a.Timeout.String()
	}
	for _, p := range v.Params {
		d.Params = append(d.Params, runbookParamView{Name: p.Name, Label: p.Label, Type: p.Type, Choices: strings.Join(p.Choices, ", "),
			Env: "NEBULA_P_" + strings.ToUpper(p.Name)})
	}
	for _, slot := range v.Secrets {
		d.Secrets = append(d.Secrets, runbookParamView{Name: slot, Env: "NEBULA_SECRET_" + strings.ToUpper(slot)})
	}
	d.Scanner, _ = scanner.Scan(v.Artifact)
	d.TrustCommand = "nebula artifact trust --action " + a.ID + " --version " + a.Version + " --risk " + v.Risk +
		" " + v.Slug + "-" + strconv.Itoa(v.Version) + ".sh"
	d.Trust = "unknown (executor unavailable)"
	if h.trust != nil {
		g, err := h.trust.GetArtifactTrust(ctx, &pb.GetArtifactTrustRequest{ArtifactSha256: v.ArtifactSHA256, ActionId: a.ID, ModuleVersion: a.Version})
		switch {
		case err != nil:
			h.log.Error("artifact trust", "error", err)
		case g.GetTrusted():
			d.Trust, d.Trusted = "trusted as "+strings.TrimPrefix(g.GetRiskClass().String(), "RISK_CLASS_"), true
		default:
			d.Trust, d.CanTrust = "not trusted: the executor treats this version as at least HIGH", true
		}
	}
	if all, err := h.runbooks.Versions(ctx, slug); err == nil {
		for _, x := range all {
			d.Versions = append(d.Versions, runbookVersionRow{Version: x.Version, Short: x.ArtifactSHA256[:16], CreatedBy: x.CreatedBy,
				Created: x.CreatedAt.UTC()})
		}
	}
	h.render(w, r, pageData{Title: "Runbook " + v.Slug, Active: "runbooks", Content: "runbook", Scripts: []string{"webauthn.js", "runbooks.js"},
		Runbooks: &runbooksData{Detail: d}})
}

// handleRunbookArtifact serves the exact bytes that run, for review and for
// `nebula artifact trust` on the executor host. Text only, never rendered.
func (h *Handler) handleRunbookArtifact(w http.ResponseWriter, r *http.Request) {
	if h.runbooks == nil {
		http.NotFound(w, r)
		return
	}
	n, err := strconv.Atoi(r.PathValue("version"))
	if err != nil || n < 1 {
		http.NotFound(w, r)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), operationsCallTimeout)
	defer cancel()
	v, err := h.runbooks.Get(ctx, r.PathValue("slug"), n)
	if errors.Is(err, runbooks.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		h.log.Error("get runbook", "error", err)
		http.Error(w, "runbooks unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+v.Slug+"-"+strconv.Itoa(v.Version)+`.sh"`)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(v.Artifact)
}

func (h *Handler) handleRunbookEdit(w http.ResponseWriter, r *http.Request) {
	if h.runbooks == nil {
		http.NotFound(w, r)
		return
	}
	d := runbooks.Draft{Risk: "HIGH", TimeoutS: 300, Params: []runbooks.Param{}, Secrets: []string{}}
	edit := &runbookEdit{}
	if slug := r.URL.Query().Get("from"); slug != "" {
		ctx, cancel := context.WithTimeout(r.Context(), operationsCallTimeout)
		defer cancel()
		v, err := h.runbooks.Get(ctx, slug, 0)
		if errors.Is(err, runbooks.ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		if err != nil {
			h.log.Error("get runbook", "error", err)
			http.Error(w, "runbooks unavailable", http.StatusInternalServerError)
			return
		}
		d, edit.Existing = v.Draft, true
	}
	js, err := json.Marshal(d)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	edit.Draft = string(js)
	title := "New runbook"
	if edit.Existing {
		title = "Edit runbook " + d.Slug
	}
	h.render(w, r, pageData{Title: title, Active: "runbooks", Content: "runbook_edit", Scripts: []string{"webauthn.js", "runbooks.js"},
		Runbooks: &runbooksData{Edit: edit}})
}

// maxRunbookRequest bounds a save request (the script is at most 256 KiB;
// JSON escaping can grow it).
const maxRunbookRequest = 1 << 20

func (h *Handler) handleRunbookSave(w http.ResponseWriter, r *http.Request) {
	if h.runbooks == nil {
		http.NotFound(w, r)
		return
	}
	if ct, _, _ := strings.Cut(r.Header.Get("Content-Type"), ";"); !strings.EqualFold(strings.TrimSpace(ct), "application/json") {
		writeJSONError(w, http.StatusUnsupportedMediaType, "Content-Type must be application/json")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxRunbookRequest)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	var d runbooks.Draft
	if err := dec.Decode(&d); err != nil {
		var mb *http.MaxBytesError
		if errors.As(err, &mb) {
			writeJSONError(w, http.StatusRequestEntityTooLarge, "the runbook is too large")
			return
		}
		writeJSONError(w, http.StatusBadRequest, "request body is not valid JSON")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	v, err := h.runbooks.Save(ctx, webUser(r), d)
	var ie *runbooks.InvalidError
	switch {
	case errors.As(err, &ie):
		writeJSONError(w, http.StatusBadRequest, ie.Error())
		return
	case err != nil:
		h.log.Error("save runbook", "error", err)
		writeJSONError(w, http.StatusInternalServerError, "the runbook could not be saved")
		return
	}
	h.log.Info("audit", "kind", "runbook_saved", "runbook", v.Slug, "version", v.Version, "artifact_sha256", v.ArtifactSHA256, "user", webUser(r))
	writeJSON(w, http.StatusOK, map[string]any{"slug": v.Slug, "version": v.Version})
}

// handleRunbookTrustBegin asks the executor for a challenge to trust a
// runbook version at its declared risk.
func (h *Handler) handleRunbookTrustBegin(w http.ResponseWriter, r *http.Request) {
	if h.runbooks == nil || h.trust == nil {
		http.NotFound(w, r)
		return
	}
	var in struct {
		Slug    string `json:"slug"`
		Version int    `json:"version"`
	}
	if !readOpsJSON(w, r, &in) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), operationsCallTimeout)
	defer cancel()
	if in.Version < 1 {
		writeJSONError(w, http.StatusNotFound, "runbook not found")
		return
	}
	v, err := h.runbooks.Get(ctx, in.Slug, in.Version)
	if errors.Is(err, runbooks.ErrNotFound) {
		writeJSONError(w, http.StatusNotFound, "runbook not found")
		return
	}
	if err != nil {
		h.log.Error("get runbook", "error", err)
		writeJSONError(w, http.StatusInternalServerError, "runbooks unavailable")
		return
	}
	a := v.Action()
	b, err := h.trust.BeginTrustArtifact(ctx, &pb.BeginTrustArtifactRequest{Artifact: v.Artifact, ActionId: a.ID, ModuleVersion: a.Version,
		RiskClass: a.Risk, Label: "runbook " + v.Slug + " version " + strconv.Itoa(v.Version)})
	if err != nil {
		h.executorRefusal(w, "begin artifact trust", err)
		return
	}
	if b.GetArtifactSha256() != v.ArtifactSHA256 || !json.Valid(b.GetRequestOptionsJson()) {
		h.log.Error("begin artifact trust", "error", "the executor hashed other bytes")
		writeJSONError(w, http.StatusBadGateway, "executor unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"trust_id": b.GetTrustId(), "options": json.RawMessage(b.GetRequestOptionsJson())})
}

// handleRunbookTrustCommit relays the assertion.
func (h *Handler) handleRunbookTrustCommit(w http.ResponseWriter, r *http.Request) {
	if h.trust == nil {
		http.NotFound(w, r)
		return
	}
	var in struct {
		TrustID   string          `json:"trust_id"`
		Assertion json.RawMessage `json:"assertion"`
	}
	if !readOpsJSON(w, r, &in) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), operationsCallTimeout)
	defer cancel()
	c, err := h.trust.CommitTrustArtifact(ctx, &pb.CommitTrustArtifactRequest{TrustId: in.TrustID, AssertionJson: in.Assertion})
	if err != nil {
		h.executorRefusal(w, "commit artifact trust", err)
		return
	}
	h.log.Info("audit", "kind", "artifact_trusted", "artifact_sha256", c.GetArtifactSha256(), "user", webUser(r))
	writeJSON(w, http.StatusOK, map[string]bool{"done": true})
}

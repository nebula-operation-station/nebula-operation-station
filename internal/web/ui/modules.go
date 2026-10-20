// SPDX-License-Identifier: AGPL-3.0-or-later

package ui

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/modules"
	"github.com/nebula-operation-station/nebula-operation-station/internal/scanner"
)

// Modules (spec 10, M7-5): import signed module archives; the executor
// verifies them and decides trust. Pages show what each action runs.

// Modules stores modules (internal/modules.Store).
type Modules interface {
	Import(ctx context.Context, user string, archive []byte) (modules.Version, error)
	Verify(ctx context.Context, name, version string) (modules.Version, error)
	Latest(ctx context.Context) ([]modules.Version, error)
	Versions(ctx context.Context, name string) ([]modules.Version, error)
	Get(ctx context.Context, name, version string) (modules.Version, error)
}

type moduleRow struct {
	Name, Version, Title, State, Signer, Detail, Imported string
	Actions                                               int
	Verified                                              bool
}

type moduleActionView struct {
	ID, Title, Description, Risk, Kind, Declares, Script, Body, Secrets string
	Params                                                              []runbookParamView
	Scanner                                                             []scanner.Finding
}

type moduleDetail struct {
	moduleRow
	Description string
	LockSHA256  string
	Actions     []moduleActionView
	Versions    []moduleRow
}

type modulesData struct {
	Rows   []moduleRow
	Detail *moduleDetail
}

func rowOf(v modules.Version) moduleRow {
	return moduleRow{Name: v.Lock.Name, Version: v.Lock.Version, Title: v.Lock.Title, State: v.State, Signer: v.Signer, Detail: v.Detail,
		Imported: v.ImportedAt.UTC().Format("2006-01-02 15:04 MST") + " by " + v.ImportedBy, Actions: len(v.Lock.Actions),
		Verified: v.State == modules.StateVerified}
}

func (h *Handler) handleModules(w http.ResponseWriter, r *http.Request) {
	if h.modules == nil {
		http.NotFound(w, r)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), operationsCallTimeout)
	defer cancel()
	data := pageData{Title: "Modules", Active: "runbooks", Content: "modules", Scripts: []string{"webauthn.js", "modules.js"}, Modules: &modulesData{}}
	list, err := h.modules.Latest(ctx)
	if err != nil {
		h.log.Error("list modules", "error", err)
	}
	for _, v := range list {
		data.Modules.Rows = append(data.Modules.Rows, rowOf(v))
	}
	h.render(w, data)
}

func (h *Handler) handleModule(w http.ResponseWriter, r *http.Request) {
	if h.modules == nil {
		http.NotFound(w, r)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), operationsCallTimeout)
	defer cancel()
	v, err := h.modules.Get(ctx, r.PathValue("name"), r.URL.Query().Get("version"))
	if errors.Is(err, modules.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		h.log.Error("get module", "error", err)
		http.Error(w, "modules unavailable", http.StatusInternalServerError)
		return
	}
	d := &moduleDetail{moduleRow: rowOf(v), Description: v.Lock.Description, LockSHA256: v.LockSHA256}
	for _, a := range v.Actions() {
		name := strings.TrimPrefix(a.ID, v.Lock.Name+".")
		la := v.Lock.Actions[name]
		av := moduleActionView{ID: a.ID, Title: a.Title, Description: a.Description, Risk: la.Risk, Kind: "attached, timeout " + a.Timeout.String(),
			Declares: strings.Join(la.Declares, ", "), Script: la.Script, Body: string(v.Scripts[la.Script]), Secrets: strings.Join(la.Secrets, ", ")}
		if la.Durable {
			av.Kind = "durable job, timeout " + a.Timeout.String()
		}
		for _, p := range la.Params {
			av.Params = append(av.Params, runbookParamView{Name: p.Name, Label: p.Label, Type: p.Type, Choices: strings.Join(p.Choices, ", "),
				Env: "NEBULA_P_" + strings.ToUpper(p.Name)})
		}
		av.Scanner, _ = scanner.Scan(a.Script)
		d.Actions = append(d.Actions, av)
	}
	if all, err := h.modules.Versions(ctx, v.Lock.Name); err == nil {
		for _, x := range all {
			d.Versions = append(d.Versions, rowOf(x))
		}
	}
	h.render(w, pageData{Title: "Module " + v.Lock.Name, Active: "runbooks", Content: "module", Scripts: []string{"webauthn.js", "modules.js"},
		Modules: &modulesData{Detail: d}})
}

// handleModuleImport takes the archive as the raw body
// (Content-Type: application/gzip, which a cross-site form cannot send).
func (h *Handler) handleModuleImport(w http.ResponseWriter, r *http.Request) {
	if h.modules == nil {
		http.NotFound(w, r)
		return
	}
	if ct, _, _ := strings.Cut(r.Header.Get("Content-Type"), ";"); !strings.EqualFold(strings.TrimSpace(ct), "application/gzip") {
		writeJSONError(w, http.StatusUnsupportedMediaType, "Content-Type must be application/gzip")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, modules.MaxArchive))
	if err != nil {
		writeJSONError(w, http.StatusRequestEntityTooLarge, "the archive is larger than 1 MiB")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	v, err := h.modules.Import(ctx, webUser(r), body)
	var ie *modules.ImportError
	switch {
	case errors.As(err, &ie):
		writeJSONError(w, http.StatusBadRequest, ie.Error())
		return
	case err != nil:
		h.log.Error("import module", "error", err)
		writeJSONError(w, http.StatusInternalServerError, "the module could not be imported")
		return
	}
	h.log.Info("audit", "kind", "module_imported", "module", v.Lock.Name, "version", v.Lock.Version, "lock_sha256", v.LockSHA256,
		"state", v.State, "user", webUser(r))
	writeJSON(w, http.StatusOK, map[string]any{"name": v.Lock.Name, "version": v.Lock.Version, "state": v.State})
}

func (h *Handler) handleModuleVerify(w http.ResponseWriter, r *http.Request) {
	if h.modules == nil {
		http.NotFound(w, r)
		return
	}
	var in struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	if !readOpsJSON(w, r, &in) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	v, err := h.modules.Verify(ctx, in.Name, in.Version)
	var ie *modules.ImportError
	switch {
	case errors.Is(err, modules.ErrNotFound):
		writeJSONError(w, http.StatusNotFound, "module not found")
		return
	case errors.As(err, &ie):
		writeJSONError(w, http.StatusBadRequest, ie.Error())
		return
	case err != nil:
		h.log.Error("verify module", "error", err)
		writeJSONError(w, http.StatusInternalServerError, "modules unavailable")
		return
	}
	h.log.Info("audit", "kind", "module_verified", "module", v.Lock.Name, "version", v.Lock.Version, "state", v.State, "signer", v.Signer,
		"user", webUser(r))
	writeJSON(w, http.StatusOK, map[string]any{"state": v.State})
}

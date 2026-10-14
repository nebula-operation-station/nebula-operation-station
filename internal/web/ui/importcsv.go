// SPDX-License-Identifier: AGPL-3.0-or-later

package ui

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory/csvimport"
)

// CSV import in the web UI (spec 12): the browser sends the file text and
// a column mapping; the server parses it (csvimport, untrusted input) into
// a staging preview and creates only the rows the user selects, after
// parsing the file again. Nothing the browser sends back about a row is
// trusted. The file is never stored.

// MaxImportBytes bounds the CSV text in the web UI: the request body
// limit of the security middleware is 1 MiB, and JSON escaping needs room.
const MaxImportBytes = 768 << 10

type importRequest struct {
	CSV     string            `json:"csv"`
	Mapping map[string]string `json:"mapping"`
	Rows    []int             `json:"rows,omitempty"`
	// Defaults for rows without an environment or criticality.
	Environment string `json:"default_environment,omitempty"`
	Criticality string `json:"default_criticality,omitempty"`
}

type importRow struct {
	Number      int               `json:"number"`
	ID          string            `json:"id"`
	DisplayName string            `json:"display_name"`
	Environment string            `json:"environment"`
	Criticality string            `json:"criticality"`
	Endpoints   []string          `json:"endpoints"`
	Tags        map[string]string `json:"tags"`
	Errors      []string          `json:"errors"`
	Exists      bool              `json:"exists"`
}

type importResult struct {
	Number int    `json:"number"`
	ID     string `json:"id"`
	Status string `json:"status"` // created, skipped, failed
	Reason string `json:"reason,omitempty"`
}

func (h *Handler) handleImportPage(w http.ResponseWriter, r *http.Request) {
	if h.inventory == nil {
		http.NotFound(w, r)
		return
	}
	h.render(w, pageData{Title: "Import hosts from CSV", Active: "inventory", Content: "inventory_import",
		Scripts: []string{"webauthn.js", "inventory-import.js"}})
}

// readImport reads and parses an import request. It answers the request
// itself on any problem.
func (h *Handler) readImport(w http.ResponseWriter, r *http.Request, in *importRequest) (*csvimport.Result, bool) {
	if !h.hostChangeAllowed(w, r) {
		return nil, false
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(in); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			writeJSONError(w, http.StatusRequestEntityTooLarge, "the file is too large for the web import (768 KiB)")
			return nil, false
		}
		writeJSONError(w, http.StatusBadRequest, "request body is not valid JSON")
		return nil, false
	}
	if len(in.CSV) > MaxImportBytes {
		writeJSONError(w, http.StatusRequestEntityTooLarge, "the file is too large for the web import (768 KiB)")
		return nil, false
	}
	if len(in.Rows) > csvimport.MaxRows {
		writeJSONError(w, http.StatusBadRequest, "too many selected rows")
		return nil, false
	}
	m := csvimport.Mapping{}
	for f, col := range in.Mapping {
		if col == "" {
			continue
		}
		m[csvimport.Field(f)] = col
	}
	res, err := csvimport.ParseWithDefaults([]byte(in.CSV), m, csvimport.Defaults{
		Environment: inventory.Environment(in.Environment), Criticality: inventory.Criticality(in.Criticality)})
	if err != nil {
		// csvimport errors describe the file and the mapping.
		writeJSONError(w, http.StatusBadRequest, strings.TrimPrefix(err.Error(), "csvimport: "))
		return nil, false
	}
	return res, true
}

func viewImportRow(row csvimport.Row) importRow {
	v := importRow{Number: row.Number, ID: row.Host.ID, DisplayName: row.Host.DisplayName, Environment: string(row.Host.Environment),
		Criticality: string(row.Host.Criticality), Tags: row.Host.Tags, Errors: row.Errors}
	if v.Errors == nil {
		v.Errors = []string{}
	}
	for _, e := range row.Host.Endpoints {
		port := e.Port
		if port == 0 {
			port = 22
		}
		v.Endpoints = append(v.Endpoints, net.JoinHostPort(e.Address, strconv.Itoa(port)))
	}
	return v
}

// exists reports whether a host ID is taken; an error is a storage error.
func (h *Handler) exists(ctx context.Context, id string) (bool, error) {
	if id == "" {
		return false, nil
	}
	_, err := h.inventory.Get(ctx, id)
	if errors.Is(err, inventory.ErrHostNotFound) {
		return false, nil
	}
	return err == nil, err
}

func (h *Handler) handleImportPreview(w http.ResponseWriter, r *http.Request) {
	var in importRequest
	res, ok := h.readImport(w, r, &in)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), inventoryCallTimeout)
	defer cancel()
	rows := make([]importRow, 0, len(res.Rows))
	for _, row := range res.Rows {
		v := viewImportRow(row)
		ex, err := h.exists(ctx, v.ID)
		if err != nil {
			h.log.Error("import preview", "error", err)
			writeJSONError(w, http.StatusInternalServerError, "inventory unavailable")
			return
		}
		v.Exists = ex
		rows = append(rows, v)
	}
	writeJSON(w, http.StatusOK, map[string]any{"columns": res.Columns, "rows": rows})
}

func (h *Handler) handleImportCommit(w http.ResponseWriter, r *http.Request) {
	var in importRequest
	res, ok := h.readImport(w, r, &in)
	if !ok {
		return
	}
	selected := map[int]bool{}
	for _, n := range in.Rows {
		selected[n] = true
	}
	byNumber := map[int]csvimport.Row{}
	for _, row := range res.Rows {
		byNumber[row.Number] = row
	}
	numbers := make([]int, 0, len(selected))
	for n := range selected {
		numbers = append(numbers, n)
	}
	sort.Ints(numbers)
	ctx, cancel := context.WithTimeout(r.Context(), 2*inventoryCallTimeout)
	defer cancel()
	var results []importResult
	created, skipped, failed := 0, 0, 0
	for _, n := range numbers {
		row, ok := byNumber[n]
		switch {
		case !ok:
			results = append(results, importResult{Number: n, Status: "skipped", Reason: "not in the file"})
			skipped++
			continue
		case len(row.Errors) > 0:
			results = append(results, importResult{Number: n, ID: row.Host.ID, Status: "skipped", Reason: strings.Join(row.Errors, "; ")})
			skipped++
			continue
		}
		_, err := h.inventory.Create(ctx, row.Host, inventory.CreateOptions{})
		var verr *inventory.ValidationError
		switch {
		case err == nil:
			results = append(results, importResult{Number: n, ID: row.Host.ID, Status: "created"})
			h.audit(r, "host_imported", row.Host.ID)
			created++
		case errors.Is(err, inventory.ErrHostExists):
			results = append(results, importResult{Number: n, ID: row.Host.ID, Status: "skipped", Reason: "already exists"})
			skipped++
		case errors.As(err, &verr):
			results = append(results, importResult{Number: n, ID: row.Host.ID, Status: "skipped", Reason: verr.Error()})
			skipped++
		default:
			h.log.Error("import host", "host", row.Host.ID, "error", err)
			results = append(results, importResult{Number: n, ID: row.Host.ID, Status: "failed", Reason: "inventory unavailable"})
			failed++
		}
	}
	h.log.Info("audit", "kind", "host_import", "user", webUser(r), "created", created, "skipped", skipped, "failed", failed)
	if results == nil {
		results = []importResult{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"results": results})
}

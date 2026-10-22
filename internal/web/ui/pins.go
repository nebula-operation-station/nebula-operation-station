// SPDX-License-Identifier: AGPL-3.0-or-later
// Per-host pinned quick actions (spec 12, job ui5): the catalog actions
// an admin pins to a host. Two ways in: the host page settings tab
// replaces the ordered list (POST /hosts/{id}/pins), and the runbook and
// module pages add one action to several hosts (POST /actions/pin). Only
// catalog actions may be pinned, and pinning changes no risk and no
// approval; the UI layer validates both.

package ui

import (
	"context"
	"errors"
	"net/http"
	"strconv"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
)

// maxPinnedActions bounds the pins of one host (the quick-action bar
// stays one row) and the host list of one pin request.
const maxPinnedActions = 12

// PinStore persists per-host pinned quick actions. inventory.Store
// satisfies it.
type PinStore interface {
	ListPinnedActions(ctx context.Context, hostID string) ([]inventory.PinnedAction, error)
	SetPinnedActions(ctx context.Context, hostID string, actionIDs []string, by string) error
	AddPinnedAction(ctx context.Context, hostID, actionID, by string) error
}

// catalogActionIDs returns the set of plannable action IDs.
func (h *Handler) catalogActionIDs(ctx context.Context) (map[string]bool, error) {
	catalog, err := h.operations.Catalog(ctx)
	if err != nil {
		return nil, err
	}
	known := make(map[string]bool, len(catalog))
	for _, a := range catalog {
		known[a.ID] = true
	}
	return known, nil
}

// handleHostPins replaces the pins of one host (POST /hosts/{id}/pins,
// JSON {"actions": ["…", …]} in the wanted order). An empty list clears
// the pins.
func (h *Handler) handleHostPins(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "POST only")
		return
	}
	if h.pins == nil || h.operations == nil {
		writeJSONError(w, http.StatusNotFound, "pins unavailable")
		return
	}
	id := r.PathValue("id")
	if !canonical.ValidHostID(id) {
		writeJSONError(w, http.StatusNotFound, "unknown host")
		return
	}
	var in struct {
		Actions []string `json:"actions"`
	}
	if !readOpsJSON(w, r, &in) {
		return
	}
	if len(in.Actions) > maxPinnedActions {
		writeJSONError(w, http.StatusBadRequest, "at most "+strconv.Itoa(maxPinnedActions)+" pinned actions per host")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), operationsCallTimeout)
	defer cancel()
	known, err := h.catalogActionIDs(ctx)
	if err != nil {
		h.log.Error("list catalog", "error", err)
		writeJSONError(w, http.StatusInternalServerError, "operations unavailable")
		return
	}
	seen := make(map[string]bool, len(in.Actions))
	for _, a := range in.Actions {
		if seen[a] {
			writeJSONError(w, http.StatusBadRequest, "duplicate pinned action: "+a)
			return
		}
		seen[a] = true
		if !known[a] {
			writeJSONError(w, http.StatusBadRequest, "not a catalog action: "+a)
			return
		}
	}
	if err := h.pins.SetPinnedActions(ctx, id, in.Actions, webUser(r)); err != nil {
		if errors.Is(err, inventory.ErrHostNotFound) {
			writeJSONError(w, http.StatusNotFound, "unknown host")
			return
		}
		h.log.Error("set host pins", "error", err)
		writeJSONError(w, http.StatusInternalServerError, "pins unavailable")
		return
	}
	h.audit(r, "host_pins_set", id)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// handleActionPin pins one catalog action to the selected hosts
// (POST /actions/pin, JSON {"action": "…", "hosts": ["…", …]}). A pin
// that already exists is left in place.
func (h *Handler) handleActionPin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "POST only")
		return
	}
	if h.pins == nil || h.operations == nil {
		writeJSONError(w, http.StatusNotFound, "pins unavailable")
		return
	}
	var in struct {
		Action string   `json:"action"`
		Hosts  []string `json:"hosts"`
	}
	if !readOpsJSON(w, r, &in) {
		return
	}
	if len(in.Hosts) == 0 || len(in.Hosts) > maxPinnedActions {
		writeJSONError(w, http.StatusBadRequest, "choose between 1 and "+strconv.Itoa(maxPinnedActions)+" hosts")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), operationsCallTimeout)
	defer cancel()
	known, err := h.catalogActionIDs(ctx)
	if err != nil {
		h.log.Error("list catalog", "error", err)
		writeJSONError(w, http.StatusInternalServerError, "operations unavailable")
		return
	}
	if !known[in.Action] {
		writeJSONError(w, http.StatusBadRequest, "not a catalog action: "+in.Action)
		return
	}
	seen := make(map[string]bool, len(in.Hosts))
	for _, host := range in.Hosts {
		if seen[host] {
			continue
		}
		seen[host] = true
		if !canonical.ValidHostID(host) {
			writeJSONError(w, http.StatusBadRequest, "invalid host ID: "+host)
			return
		}
		if err := h.pins.AddPinnedAction(ctx, host, in.Action, webUser(r)); err != nil {
			if errors.Is(err, inventory.ErrHostNotFound) {
				writeJSONError(w, http.StatusBadRequest, "unknown host: "+host)
				return
			}
			h.log.Error("pin action", "error", err)
			writeJSONError(w, http.StatusInternalServerError, "pins unavailable")
			return
		}
		h.audit(r, "host_pinned", host)
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

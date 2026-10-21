// SPDX-License-Identifier: AGPL-3.0-or-later

package ui

import (
	"context"
	"errors"
	"net/http"
	"slices"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
)

// Bulk actions on the inventory selection. "Refresh" creates the read-only
// reads behind the inventory columns (facts, updates, containers, services)
// as one operation per action for all selected hosts, through the normal
// create path: inside an open privileged session the executor approves
// LOW reads itself, otherwise each operation waits for its approval. A
// reboot is not created here: the selection goes to the operation form,
// where the rollout (canary, waves) is chosen and approved.

// maxBulkHosts limits one bulk request.
const maxBulkHosts = 200

// bulkRefreshActions are the reads one inventory refresh runs.
var bulkRefreshActions = []string{"core.facts", "package.list_updates", "docker.list", "service.list"}

// errBulkSelection is a selection the server refuses.
var errBulkSelection = errors.New("select between 1 and 200 hosts from the inventory")

// bulkHosts reads and checks the selected host IDs: valid, unique, known
// to the inventory.
func (h *Handler) bulkHosts(ctx context.Context, r *http.Request) ([]string, error) {
	if err := r.ParseForm(); err != nil {
		return nil, errBulkSelection
	}
	ids := r.PostForm["host"]
	if len(ids) == 0 || len(ids) > maxBulkHosts {
		return nil, errBulkSelection
	}
	var out []string
	for _, id := range ids {
		if !canonical.ValidHostID(id) {
			return nil, errBulkSelection
		}
		if slices.Contains(out, id) {
			continue
		}
		if _, err := h.inventory.Get(ctx, id); err != nil {
			if errors.Is(err, inventory.ErrHostNotFound) {
				return nil, errors.New("host " + id + " is not in the inventory")
			}
			return nil, err
		}
		out = append(out, id)
	}
	return out, nil
}

// handleInventoryRefresh creates the refresh operations for the selected
// hosts that have a pinned key (POST /inventory/refresh, host=ID...).
func (h *Handler) handleInventoryRefresh(w http.ResponseWriter, r *http.Request) {
	if h.inventory == nil || h.operations == nil {
		http.NotFound(w, r)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), operationsCallTimeout)
	defer cancel()
	ids, err := h.bulkHosts(ctx, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	pins, unavailable := h.hostKeyPins(ctx)
	if unavailable {
		http.Error(w, "the executor is unavailable", http.StatusServiceUnavailable)
		return
	}
	var enrolled []string
	for _, id := range ids {
		if pins[id] != nil {
			enrolled = append(enrolled, id)
		}
	}
	if len(enrolled) == 0 {
		http.Error(w, "none of the selected hosts has a pinned key yet: enroll them first", http.StatusBadRequest)
		return
	}
	pending := 0
	for _, a := range bulkRefreshActions {
		c, err := h.operations.CreateStaged(ctx, webUser(r), a, enrolled, map[string]string{}, executions.Plan{})
		if err != nil {
			h.log.Error("inventory refresh", "action", a, "hosts", len(enrolled), "error", err)
			http.Error(w, "the refresh could not be created: "+err.Error(), http.StatusBadGateway)
			return
		}
		if c.State == "pending" {
			pending++
		}
	}
	h.log.Info("audit", "kind", "inventory_refresh", "user", webUser(r), "hosts", len(enrolled), "skipped", len(ids)-len(enrolled), "pending", pending)
	http.Redirect(w, r, "/operations", http.StatusSeeOther)
}

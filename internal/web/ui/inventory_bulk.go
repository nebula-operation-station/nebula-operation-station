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
// to the inventory. It returns the hosts with their inventory records.
func (h *Handler) bulkHosts(ctx context.Context, r *http.Request) ([]inventory.Host, error) {
	if err := r.ParseForm(); err != nil {
		return nil, errBulkSelection
	}
	ids := r.PostForm["host"]
	if len(ids) == 0 || len(ids) > maxBulkHosts {
		return nil, errBulkSelection
	}
	var out []inventory.Host
	for _, id := range ids {
		if !canonical.ValidHostID(id) {
			return nil, errBulkSelection
		}
		if slices.ContainsFunc(out, func(x inventory.Host) bool { return x.ID == id }) {
			continue
		}
		host, err := h.inventory.Get(ctx, id)
		if err != nil {
			if errors.Is(err, inventory.ErrHostNotFound) {
				return nil, errors.New("host " + id + " is not in the inventory")
			}
			return nil, err
		}
		out = append(out, host)
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
	hosts, err := h.bulkHosts(ctx, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	pins, unavailable := h.hostKeyPins(ctx)
	if unavailable {
		http.Error(w, "the executor is unavailable", http.StatusServiceUnavailable)
		return
	}
	// Only hosts an operation can run on, as CreateStaged checks them: a
	// pinned key that is not blocked, and an endpoint. The others are
	// skipped rather than failing the whole refresh.
	var usable []string
	for _, host := range hosts {
		if p := pins[host.ID]; p != nil && !p.GetBlocked() && len(host.Endpoints) > 0 {
			usable = append(usable, host.ID)
		}
	}
	if len(usable) == 0 {
		http.Error(w, "none of the selected hosts can run an operation (no pinned key, key blocked, or no endpoint)", http.StatusBadRequest)
		return
	}
	pending, created := 0, 0
	// The executor takes at most executions.MaxHosts hosts per operation.
	for chunk := range slices.Chunk(usable, executions.MaxHosts) {
		for _, a := range bulkRefreshActions {
			c, err := h.operations.CreateStaged(ctx, webUser(r), a, chunk, map[string]string{}, executions.Plan{})
			if err != nil {
				h.log.Error("inventory refresh", "action", a, "hosts", len(chunk), "created", created, "error", err)
				http.Error(w, "the refresh could not be created; see the server log", http.StatusBadGateway)
				return
			}
			created++
			if c.State == "pending" {
				pending++
			}
		}
	}
	h.log.Info("audit", "kind", "inventory_refresh", "user", webUser(r), "hosts", len(usable), "skipped", len(hosts)-len(usable), "operations", created, "pending", pending)
	http.Redirect(w, r, "/operations", http.StatusSeeOther)
}

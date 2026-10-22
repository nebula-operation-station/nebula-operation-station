// SPDX-License-Identifier: AGPL-3.0-or-later
// The per-host quick-action bar (job ui5): the built-ins (refresh,
// install security updates, reboot) plus the actions pinned to the host,
// and the settings-tab view that manages the pins. The bar runs actions
// in place through web/static/runop.js; actions with parameters open the
// operation form prefilled for the host instead.

package ui

import (
	"context"
	"errors"
	"sort"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/actions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
)

// quickActionView is one button of the host page quick-action bar.
type quickActionView struct {
	ActionID string
	Title    string
	// Params says the action needs parameters: the button opens the
	// operation form prefilled for this host instead of running.
	Params bool
}

// pinActionRow is one catalog action in the pin management list.
type pinActionRow struct {
	ID        string
	Title     string
	Position  int
	Pinned    bool
	HasParams bool
}

// pinSettingsView is the settings-tab pin list: the catalog actions,
// pinned first in pin order, then the rest in catalog order.
type pinSettingsView struct {
	Actions []pinActionRow
}

// pinHostRow is one host of the "Pin to hosts…" chooser.
type pinHostRow struct {
	ID          string
	DisplayName string
}

// pinToHostsView is the "Pin to hosts…" section of the runbook and
// module pages: the inventory hosts to choose from.
type pinToHostsView struct {
	Hosts []pinHostRow
}

// pinToHosts fills the "Pin to hosts…" section: the inventory hosts in
// ID order. Nil while pins are not wired.
func (h *Handler) pinToHosts(ctx context.Context) *pinToHostsView {
	if h.pins == nil || h.hosts == nil {
		return nil
	}
	hosts, err := h.hosts(ctx)
	if err != nil {
		h.log.Error("list inventory hosts", "error", err)
		return nil
	}
	sort.Slice(hosts, func(i, j int) bool { return hosts[i].ID < hosts[j].ID })
	v := &pinToHostsView{}
	for _, host := range hosts {
		name := host.DisplayName
		if name == "" {
			name = host.ID
		}
		v.Hosts = append(v.Hosts, pinHostRow{ID: host.ID, DisplayName: name})
	}
	return v
}

// hostQuickActions fills the quick-action bar of the host page. The
// built-ins are always there while operations are enabled; the pinned
// actions follow in their stored order. A pin whose action is no longer
// in the catalog is skipped (it can no longer run).
func (h *Handler) hostQuickActions(ctx context.Context, id string, hp *hostPageData) {
	if !hp.Found || h.operations == nil {
		return
	}
	catalog, err := h.operations.Catalog(ctx)
	if err != nil {
		h.log.Error("list catalog", "error", err)
		return
	}
	byID := make(map[string]actions.Action, len(catalog))
	for _, a := range catalog {
		byID[a.ID] = a
	}
	hp.QuickActions = []quickActionView{
		{ActionID: "refresh", Title: "Refresh"},
		{ActionID: "package.install_security", Title: "Install security updates"},
		{ActionID: "system.reboot", Title: "Reboot"},
	}
	if h.pins != nil {
		pinned, err := h.pins.ListPinnedActions(ctx, id)
		if err != nil && !errors.Is(err, inventory.ErrHostNotFound) {
			h.log.Error("list host pins", "error", err)
		}
		for _, p := range pinned {
			a, ok := byID[p.ActionID]
			if !ok {
				continue
			}
			hp.QuickActions = append(hp.QuickActions, quickActionView{ActionID: a.ID, Title: a.Title, Params: len(a.Params) > 0})
		}
	}
}

// hostPinSettings fills the settings-tab pin list.
func (h *Handler) hostPinSettings(ctx context.Context, id string, hp *hostPageData) {
	if !hp.Found || h.pins == nil || h.operations == nil {
		return
	}
	catalog, err := h.operations.Catalog(ctx)
	if err != nil {
		h.log.Error("list catalog", "error", err)
		return
	}
	pinnedSet := map[string]bool{}
	pos := map[string]int{}
	if pinned, err := h.pins.ListPinnedActions(ctx, id); err == nil {
		for _, p := range pinned {
			pinnedSet[p.ActionID] = true
			pos[p.ActionID] = p.Position
		}
	}
	rows := make([]pinActionRow, 0, len(catalog))
	for _, a := range catalog {
		rows = append(rows, pinActionRow{
			ID: a.ID, Title: a.Title,
			Position: pos[a.ID], Pinned: pinnedSet[a.ID], HasParams: len(a.Params) > 0,
		})
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].Pinned != rows[j].Pinned {
			return rows[i].Pinned
		}
		return rows[i].Pinned && rows[i].Position < rows[j].Position
	})
	hp.PinSettings = &pinSettingsView{Actions: rows}
}

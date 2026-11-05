// SPDX-License-Identifier: AGPL-3.0-or-later

package ui

import (
	"context"
	"net/url"
	"strconv"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
)

// pveLeaseRequestURL is the lease form pre-filled with remote id.
func pveLeaseRequestURL(id string) string {
	q := url.Values{}
	q.Set("scope", executions.ScopeProvider)
	q.Set("remote", id)
	return "/leases/new?" + q.Encode()
}

// pveLeaseState fills the lease parts of a PVE detail page from the
// executor's approved leases. Nothing is shown when leases are not
// configured, the remote is not active in the registry or the leases
// cannot be listed (unknown is not "none").
//
// Read lease: the "Request read lease" link appears when no active provider
// read lease lists the remote, so the collector has no read authority for
// it. When every active read lease listing it is stale (the remote was
// re-pinned or its read token rotated: trust generation or credential
// version no longer match the registry), the page says so and offers the
// same link for the renewal. A lease whose binding is unknown (registry not
// readable) counts as present.
//
// Live values: the "Enable live values" form is offered with the node and
// guest checkboxes (pveLiveOptions); each row shows whether a current
// telemetry lease covers it exactly ("on") or only an outdated one does
// ("stale": stale binding, or a guest recreated with a new generation).
// Neither the link nor the form proposes anything by itself.
func (h *Handler) pveLeaseState(ctx context.Context, id string, meta PVERemoteMeta, d *pveDetailData) {
	if h.leases == nil || h.pveRemotes == nil || meta.State != "active" || !pvecontract.ValidRemoteID(id) {
		return
	}
	grants, err := h.leases.ReadGrants(ctx)
	if err != nil {
		h.log.Error("list read grants", "error", err)
		return
	}
	var readListed, readUsable bool
	// live maps a target key to the generations a current lease covers;
	// stale holds the keys an outdated lease lists.
	live := map[string][]uint64{}
	stale := map[string]bool{}
	for _, g := range grants {
		if g.State != "active" || g.ScopeKind != executions.ScopeProvider {
			continue
		}
		for _, p := range g.Providers {
			if p.RemoteID != id {
				continue
			}
			switch g.RateProfile {
			case permit.ProviderReadProfile:
				readListed = true
				if p.Binding != executions.ProviderBindingStale {
					readUsable = true
				}
			case permit.ProviderTelemetryProfile:
				for _, m := range p.MetricsTargets {
					switch p.Binding {
					case executions.ProviderBindingCurrent:
						live[m.Key()] = append(live[m.Key()], m.Generation)
					case executions.ProviderBindingStale:
						stale[m.Key()] = true
					}
				}
			}
		}
	}
	switch {
	case !readListed:
		d.LeaseRequestURL = pveLeaseRequestURL(id)
	case !readUsable:
		d.LeaseRequestURL, d.ReadLeaseStale = pveLeaseRequestURL(id), true
	}
	h.pveLiveOptions(id, d, live, stale)
}

// pveLiveStatus is the live-values state of one target: "on" when a current
// lease lists it with generation gen, "stale" when only an outdated lease
// (stale binding or another generation) lists it, otherwise "".
func pveLiveStatus(key string, gen uint64, live map[string][]uint64, stale map[string]bool) string {
	for _, g := range live[key] {
		if g == gen {
			return "on"
		}
	}
	if len(live[key]) > 0 || stale[key] {
		return "stale"
	}
	return ""
}

// pveGuestTarget is the metrics target of a guest row, or false when the
// row cannot be one (unknown kind, malformed node, VMID or generation).
func pveGuestTarget(g pveGuestRow) (permit.ProviderMetricsTarget, bool) {
	vmid, err := strconv.ParseUint(g.VMIDText, 10, 64)
	if err != nil {
		return permit.ProviderMetricsTarget{}, false
	}
	t := permit.ProviderMetricsTarget{Node: g.Node, Kind: g.Kind, VMID: vmid, Generation: g.generation}
	if t.Kind == permit.MetricsKindNode || !t.Valid() {
		return permit.ProviderMetricsTarget{}, false
	}
	return t, true
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package ui

import (
	"context"
	"net/url"
	"slices"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
)

// pveLeaseRequestURL is the lease form pre-filled with this remote when
// the remote is active in the registry and no active provider lease covers
// it, so the collector has no read authority for it. It returns "" when
// leases are not configured, the remote is not active, the leases cannot
// be listed (unknown is not "none") or an active provider lease exists.
// The link only opens the form; a lease needs the proposal and approval.
func (h *Handler) pveLeaseRequestURL(ctx context.Context, id string, meta PVERemoteMeta) string {
	if h.leases == nil || h.pveRemotes == nil || meta.State != "active" || !pvecontract.ValidRemoteID(id) {
		return ""
	}
	grants, err := h.leases.ReadGrants(ctx)
	if err != nil {
		h.log.Error("list read grants", "error", err)
		return ""
	}
	for _, g := range grants {
		if g.State == "active" && g.ScopeKind == executions.ScopeProvider && slices.Contains(g.Remotes, id) {
			return ""
		}
	}
	q := url.Values{}
	q.Set("scope", executions.ScopeProvider)
	q.Set("remote", id)
	return "/leases/new?" + q.Encode()
}

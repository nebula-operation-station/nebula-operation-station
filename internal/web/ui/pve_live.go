// SPDX-License-Identifier: AGPL-3.0-or-later

package ui

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pveinventory"
)

// Live values for a PVE remote (spec 17 "SSH/provider telemetry leases",
// docs/admin/guide.md "Live values for Proxmox nodes and guests"). The
// detail page /pve/{id} offers "Enable live values": a checkbox per stored
// node and guest (by default every node and every running guest, at most
// permit.MaxProviderMetricsTargets). The form posts scope=provider_telemetry
// to POST /leases/preview, which proposes a provider telemetry lease via
// Leases.ProposeProviderTelemetryGrant and redirects to the same proposal
// page as every other lease. A guest checkbox posts the incarnation
// generation the page showed; the service checks each chosen target against
// the stored inventory (node, kind and that generation: a guest recreated
// since the page was loaded is refused, not re-bound) and the
// executor's remote binding; nothing is read before the lease is approved
// with the security key (or the hardened-mode CLI).

// pveLiveScope is the scope value of the live-values form.
const pveLiveScope = permit.ProviderTelemetryProfile

// pveLiveOption is the live-values checkbox of one node or guest row.
type pveLiveOption struct {
	// Value is the posted target: "<node>/node/0" for a node,
	// "<node>/<kind>/<vmid>/<generation>" for a guest, with the guest
	// incarnation generation the page showed (pveLiveValue).
	Value string
	// Checked pre-selects the row (default selection).
	Checked bool
	// Status is "on" (a current telemetry lease covers it exactly),
	// "stale" (only an outdated lease lists it) or "".
	Status string
}

// pveLiveData is the "Enable live values" form of a PVE detail page.
type pveLiveData struct {
	// Offered shows the form: leases are configured, the remote is active
	// and the approved leases could be listed.
	Offered bool
	// RemoteID is posted with the form.
	RemoteID string
	// Max is permit.MaxProviderMetricsTargets.
	Max int
	// Truncated is set when the default selection had to stop at Max.
	Truncated bool
	// On and Stale count the rows with that status.
	On, Stale int
	// DayOptions are the lease lifetimes.
	DayOptions []int
}

// pveLiveOptions sets the checkbox of every node and guest row: by default
// every node, then every running guest, up to the target limit.
func (h *Handler) pveLiveOptions(id string, d *pveDetailData, live map[string][]uint64, stale map[string]bool) {
	d.Live = pveLiveData{Offered: true, RemoteID: id, Max: permit.MaxProviderMetricsTargets,
		DayOptions: []int{executions.ReadGrantShortDays, executions.ReadGrantLongDays}}
	checked := 0
	pick := func() bool {
		if checked < permit.MaxProviderMetricsTargets {
			checked++
			return true
		}
		d.Live.Truncated = true
		return false
	}
	count := func(s string) {
		switch s {
		case "on":
			d.Live.On++
		case "stale":
			d.Live.Stale++
		}
	}
	for i := range d.Nodes {
		n := &d.Nodes[i]
		t := permit.ProviderMetricsTarget{Node: n.Node, Kind: permit.MetricsKindNode}
		if !t.Valid() {
			continue
		}
		n.Live = pveLiveOption{Value: t.Key(), Status: pveLiveStatus(t.Key(), 0, live, stale)}
		n.Live.Checked = pick()
		count(n.Live.Status)
	}
	for i := range d.Guests {
		g := &d.Guests[i]
		t, ok := pveGuestTarget(*g)
		if !ok {
			continue
		}
		g.Live = pveLiveOption{Value: pveLiveValue(t), Status: pveLiveStatus(t.Key(), t.Generation, live, stale)}
		if g.Status == string(pvecontract.GuestRunning) {
			g.Live.Checked = pick()
		}
		count(g.Live.Status)
	}
}

// pveLiveValue is the posted checkbox value of a valid metrics target: the
// target key, plus "/<generation>" for a guest so the proposal can refuse a
// guest recreated since the page was rendered.
func pveLiveValue(t permit.ProviderMetricsTarget) string {
	if t.Kind == permit.MetricsKindNode {
		return t.Key()
	}
	return t.Key() + "/" + strconv.FormatUint(t.Generation, 10)
}

// parsePVELiveUint parses a canonical decimal (no sign, no leading zeros).
func parsePVELiveUint(s string) (uint64, bool) {
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil || strconv.FormatUint(v, 10) != s {
		return 0, false
	}
	return v, true
}

// parsePVELiveTarget parses one posted target, "<node>/node/0" for a node
// or "<node>/<kind>/<vmid>/<generation>" for a guest (pveLiveValue). A
// guest without the generation the page showed is refused.
func parsePVELiveTarget(s string) (executions.ProviderMetricsSelection, bool) {
	parts := strings.Split(s, "/")
	if len(parts) < 3 || !pvecontract.ValidNodeName(parts[0]) {
		return executions.ProviderMetricsSelection{}, false
	}
	vmid, ok := parsePVELiveUint(parts[2])
	if !ok {
		return executions.ProviderMetricsSelection{}, false
	}
	m := executions.ProviderMetricsSelection{Node: parts[0], Kind: parts[1], VMID: vmid}
	switch parts[1] {
	case permit.MetricsKindNode:
		if len(parts) != 3 || vmid != 0 {
			return executions.ProviderMetricsSelection{}, false
		}
	case permit.MetricsKindQEMU, permit.MetricsKindLXC:
		if len(parts) != 4 || vmid < pvecontract.MinVMID || vmid > pvecontract.MaxVMID {
			return executions.ProviderMetricsSelection{}, false
		}
		gen, ok := parsePVELiveUint(parts[3])
		if !ok || gen < 1 || gen > pvecontract.MaxGuestGeneration {
			return executions.ProviderMetricsSelection{}, false
		}
		m.Generation = gen
	default:
		return executions.ProviderMetricsSelection{}, false
	}
	return m, true
}

// checkPVELiveForm turns the posted live-values form into a request, or
// returns the reason it is refused. active are the remotes the form may
// name.
func checkPVELiveForm(form map[string][]string, active map[string]bool) (executions.ProviderTelemetryGrantRequest, string) {
	get := func(k string) string {
		if v := form[k]; len(v) == 1 {
			return v[0]
		}
		return ""
	}
	days, err := strconv.Atoi(get("days"))
	if err != nil || (days != executions.ReadGrantShortDays && days != executions.ReadGrantLongDays) {
		return executions.ProviderTelemetryGrantRequest{}, fmt.Sprintf("a read lease lasts %d or %d days", executions.ReadGrantShortDays, executions.ReadGrantLongDays)
	}
	id := get("remote")
	if !pvecontract.ValidRemoteID(id) || !active[id] {
		return executions.ProviderTelemetryGrantRequest{}, "the Proxmox remote is unknown or not active"
	}
	raw := form["target"]
	if len(raw) == 0 || len(raw) > permit.MaxProviderMetricsTargets {
		return executions.ProviderTelemetryGrantRequest{}, fmt.Sprintf("choose 1 to %d nodes and guests", permit.MaxProviderMetricsTargets)
	}
	seen := map[string]bool{}
	in := executions.ProviderTelemetryGrantRequest{RemoteID: id, Days: days}
	for _, s := range raw {
		m, ok := parsePVELiveTarget(s)
		// Twice is by identity: the same guest with two generations too.
		key := permit.ProviderMetricsTarget{Node: m.Node, Kind: m.Kind, VMID: m.VMID}.Key()
		if !ok || seen[key] {
			return executions.ProviderTelemetryGrantRequest{}, "a node or guest is malformed or chosen twice"
		}
		seen[key] = true
		in.Targets = append(in.Targets, m)
	}
	return in, ""
}

// handlePVELivePreview proposes a provider telemetry lease
// (scope=provider_telemetry of POST /leases/preview; the form is already
// parsed) and redirects to its proposal page. Errors are plain text for
// formpost.js.
func (h *Handler) handlePVELivePreview(w http.ResponseWriter, r *http.Request) {
	if h.pve == nil {
		http.Error(w, "the PVE inventory is not available", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), operationsCallTimeout)
	defer cancel()
	remotes, ok := h.providerLeaseRemotes(ctx)
	if !ok {
		http.Error(w, "the Proxmox remotes are not available", http.StatusBadRequest)
		return
	}
	active := make(map[string]bool, len(remotes))
	for _, m := range remotes {
		active[m.RemoteID] = true
	}
	in, reason := checkPVELiveForm(r.PostForm, active)
	if reason != "" {
		http.Error(w, reason, http.StatusBadRequest)
		return
	}
	user := webUser(r)
	now := h.clockNow()
	if !h.leaseProposals.allow(user, now) {
		w.Header().Set("Retry-After", strconv.Itoa(int(leasePreviewInterval/time.Second)))
		http.Error(w, "at most one read lease preview every 10 seconds: wait and try again", http.StatusTooManyRequests)
		return
	}
	v, err := h.leases.ProposeProviderTelemetryGrant(ctx, user, in, pveTelemetryInventory{h.pve})
	if err != nil {
		var ie *executions.ReadGrantInputError
		switch {
		case errors.As(err, &ie):
			http.Error(w, ie.Reason, http.StatusBadRequest)
		case errors.Is(err, executions.ErrProviderRemotesUnavailable), errors.Is(err, executions.ErrReadGrantProposeFailed),
			errors.Is(err, executions.ErrReadGrantProposalMismatch), errors.Is(err, executions.ErrReadGrantProposeUnsupported):
			h.log.Error("propose provider telemetry grant", "error", err)
			http.Error(w, err.Error(), http.StatusBadGateway)
		default:
			h.log.Error("propose provider telemetry grant", "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
		}
		return
	}
	if !leaseDigestRe.MatchString(v.Digest) {
		http.Error(w, "the executor returned no usable digest", http.StatusBadGateway)
		return
	}
	h.leaseProposals.put(user, v, now)
	http.Redirect(w, r, "/leases/proposals/"+v.Digest, http.StatusSeeOther)
}

// pveTelemetryInventory adapts the stored PVE inventory to
// executions.TelemetryInventory.
type pveTelemetryInventory struct{ store PVEStore }

// HasRemote reports whether the remote has stored inventory.
func (p pveTelemetryInventory) HasRemote(ctx context.Context, remoteID string) (bool, error) {
	if _, err := p.store.GetRemote(ctx, remoteID); err != nil {
		if errors.Is(err, pveinventory.ErrRemoteNotFound) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// HasNode reports whether the node is stored for the remote. A node beyond
// the page's node limit is not found (fail closed).
func (p pveTelemetryInventory) HasNode(ctx context.Context, remoteID, node string) (bool, error) {
	nodes, err := p.store.ListNodes(ctx, remoteID, pveNodeLimit)
	if err != nil {
		return false, err
	}
	for _, n := range nodes {
		if n.Node == node {
			return true, nil
		}
	}
	return false, nil
}

// ActiveGuests returns up to limit active incarnations of vmid.
func (p pveTelemetryInventory) ActiveGuests(ctx context.Context, remoteID string, vmid uint64, limit int) ([]executions.TelemetryGuest, error) {
	if vmid == 0 || limit < 1 {
		return nil, nil
	}
	gs, err := p.store.ListGuests(ctx, remoteID, pveinventory.GuestFilter{VMID: vmid}, limit)
	if err != nil {
		return nil, err
	}
	var out []executions.TelemetryGuest
	for _, g := range gs {
		if g.Tombstoned || g.VMID != vmid {
			continue
		}
		out = append(out, executions.TelemetryGuest{VMID: g.VMID, Generation: g.Generation, Kind: g.Kind, Node: g.Node})
	}
	return out, nil
}

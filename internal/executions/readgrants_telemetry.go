// SPDX-License-Identifier: AGPL-3.0-or-later

package executions

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
)

// Provider telemetry leases (spec 17 "SSH/provider telemetry leases",
// docs/admin/guide.md "Live values for Proxmox nodes and guests"). The
// 10-second live values of a Proxmox node or guest box need a read-grant-v2
// document with the provider_telemetry rate profile that names the remote
// (trust pin, trust generation and read credential version as the executor
// reports them), the single method "metrics" and the exact metrics targets.
// The server builds the targets from its current imported inventory: a
// node must be stored for the remote, and a guest must have exactly one
// active incarnation whose node, kind and local incarnation generation are
// the ones the page showed and posted. A guest recreated (same VMID, new
// generation) since the page was loaded is refused, never re-bound to the
// new incarnation; a lease bound to the old generation does not cover the
// new one either.
// The document goes through the same proposal, preview and approval flow as
// every other read lease; nothing is read before it is approved.

// Fixed values of provider telemetry proposals.
const (
	// providerTelemetryReadsPerHour is how often one metrics target can be
	// read live per rolling hour at the live interval (the executor keeps
	// each target's live reads at least this far apart).
	providerTelemetryReadsPerHour = int64(time.Hour / permit.ProviderTelemetryLiveInterval)
	// providerTelemetryLiveTargets is how many metrics targets of one
	// remote the executor serves live at once. It is the executor's own cap
	// (executor pve_metrics.go uses the same permit constant; spec 12
	// "Visible-target requests"), so raising that cap raises the budget.
	providerTelemetryLiveTargets = permit.ProviderTelemetryMaxLiveTargets
)

// ProviderMetricsSelection is one metrics target the operator chose: a node
// (Kind permit.MetricsKindNode, VMID 0) or a guest (Kind
// permit.MetricsKindQEMU or permit.MetricsKindLXC with its VMID and the node
// the page showed it on). A guest also carries the local incarnation
// generation the page showed (1 to pvecontract.MaxGuestGeneration; 0 for a
// node): the proposal binds a guest only while the imported inventory still
// has exactly that incarnation.
type ProviderMetricsSelection struct {
	Node       string
	Kind       string
	VMID       uint64
	Generation uint64
}

// key is the selection's identity, the same as permit's metrics target key.
func (m ProviderMetricsSelection) key() string {
	return permit.ProviderMetricsTarget{Node: m.Node, Kind: m.Kind, VMID: m.VMID}.Key()
}

// ProviderTelemetryGrantRequest is what the "Enable live values" form on a
// PVE remote page submits.
type ProviderTelemetryGrantRequest struct {
	// RemoteID is the PVE remote.
	RemoteID string
	// Targets are the chosen node and guests, 1 to
	// permit.MaxProviderMetricsTargets.
	Targets []ProviderMetricsSelection
	Days    int // ReadGrantShortDays or ReadGrantLongDays
}

// TelemetryGuest is one active guest incarnation of the imported PVE
// inventory, as a telemetry proposal binds it.
type TelemetryGuest struct {
	VMID       uint64
	Generation uint64
	Kind       string
	Node       string
}

// TelemetryInventory is the server's imported PVE inventory as a telemetry
// proposal reads it. The web UI adapts its pveinventory store (which cannot
// be imported here: pveinventory imports this package). Every answer comes
// from the stored inventory, never from the request.
type TelemetryInventory interface {
	// HasRemote reports whether the remote has stored inventory.
	HasRemote(ctx context.Context, remoteID string) (bool, error)
	// HasNode reports whether the node is stored for the remote.
	HasNode(ctx context.Context, remoteID, node string) (bool, error)
	// ActiveGuests returns the active (not tombstoned) incarnations of
	// vmid, at most limit of them.
	ActiveGuests(ctx context.Context, remoteID string, vmid uint64, limit int) ([]TelemetryGuest, error)
}

// providerTelemetryBudget sizes the per-remote rolling-hour metrics budget
// for n targets. The executor spends one unit for every metrics request of
// the remote (permit.AuthorizeProviderMetrics, budget key per remote), keeps
// each target's live reads at least the live interval apart and serves at
// most providerTelemetryLiveTargets targets live at once; the grant's
// on_demand trigger allows no scheduled history reads. So at most
// min(n, providerTelemetryLiveTargets) targets each read
// providerTelemetryReadsPerHour times per hour, which is the budget; it
// never exceeds permit.MaxProviderTelemetryBudget.
func providerTelemetryBudget(n int) int64 {
	return min(int64(min(n, providerTelemetryLiveTargets))*providerTelemetryReadsPerHour, permit.MaxProviderTelemetryBudget)
}

// checkProviderTelemetryRequest validates the form input and returns the
// selections in document order: by node, the node itself first, then the
// guests by kind and VMID.
func checkProviderTelemetryRequest(in ProviderTelemetryGrantRequest) ([]ProviderMetricsSelection, error) {
	if in.Days != ReadGrantShortDays && in.Days != ReadGrantLongDays {
		return nil, &ReadGrantInputError{fmt.Sprintf("a read lease lasts %d or %d days", ReadGrantShortDays, ReadGrantLongDays)}
	}
	if !pvecontract.ValidRemoteID(in.RemoteID) {
		return nil, &ReadGrantInputError{"the PVE remote is malformed"}
	}
	if len(in.Targets) == 0 || len(in.Targets) > permit.MaxProviderMetricsTargets {
		return nil, &ReadGrantInputError{fmt.Sprintf("choose 1 to %d nodes and guests", permit.MaxProviderMetricsTargets)}
	}
	seen := map[string]bool{}
	for _, m := range in.Targets {
		if !pvecontract.ValidNodeName(m.Node) {
			return nil, &ReadGrantInputError{"a node name is malformed"}
		}
		switch m.Kind {
		case permit.MetricsKindNode:
			if m.VMID != 0 || m.Generation != 0 {
				return nil, &ReadGrantInputError{"a node target has no VMID or generation"}
			}
		case permit.MetricsKindQEMU, permit.MetricsKindLXC:
			if m.VMID < pvecontract.MinVMID || m.VMID > pvecontract.MaxVMID {
				return nil, &ReadGrantInputError{"a guest VMID is out of range"}
			}
			if m.Generation < 1 || m.Generation > pvecontract.MaxGuestGeneration {
				return nil, &ReadGrantInputError{"a guest has no valid generation: reload the page"}
			}
		default:
			return nil, &ReadGrantInputError{"a target is neither a node nor a QEMU or LXC guest"}
		}
		if seen[m.key()] {
			return nil, &ReadGrantInputError{"a node or guest is listed twice"}
		}
		seen[m.key()] = true
	}
	out := append([]ProviderMetricsSelection(nil), in.Targets...)
	sort.Slice(out, func(i, j int) bool { return metricsLess(out[i], out[j]) })
	return out, nil
}

// metricsLess orders targets by node, the node target first, then by kind
// and VMID.
func metricsLess(a, b ProviderMetricsSelection) bool {
	if a.Node != b.Node {
		return a.Node < b.Node
	}
	if (a.Kind == permit.MetricsKindNode) != (b.Kind == permit.MetricsKindNode) {
		return a.Kind == permit.MetricsKindNode
	}
	if a.Kind != b.Kind {
		return a.Kind < b.Kind
	}
	return a.VMID < b.VMID
}

// telemetryTargets resolves the selections against the imported inventory
// of remoteID into exact metrics targets. Every selection must match the
// inventory exactly: a node must be stored; a guest must have exactly one
// active incarnation, of the chosen kind, on the chosen node, with the
// generation the page posted. A guest recreated since the page was loaded
// is refused, not bound to its new incarnation.
func telemetryTargets(ctx context.Context, inv TelemetryInventory, remoteID string, sel []ProviderMetricsSelection) ([]permit.ProviderMetricsTarget, error) {
	ok, err := inv.HasRemote(ctx, remoteID)
	if err != nil {
		return nil, fmt.Errorf("telemetry lease: read inventory of %s: %w", remoteID, err)
	}
	if !ok {
		return nil, &ReadGrantInputError{fmt.Sprintf("PVE remote %s has no imported inventory", remoteID)}
	}
	out := make([]permit.ProviderMetricsTarget, 0, len(sel))
	for _, m := range sel {
		if m.Kind == permit.MetricsKindNode {
			ok, err := inv.HasNode(ctx, remoteID, m.Node)
			if err != nil {
				return nil, fmt.Errorf("telemetry lease: read node %s/%s: %w", remoteID, m.Node, err)
			}
			if !ok {
				return nil, &ReadGrantInputError{fmt.Sprintf("node %s is not in the inventory of %s", m.Node, remoteID)}
			}
			out = append(out, permit.ProviderMetricsTarget{Node: m.Node, Kind: permit.MetricsKindNode})
			continue
		}
		// Two rows let an ambiguous VMID (two active incarnations) show.
		gs, err := inv.ActiveGuests(ctx, remoteID, m.VMID, 2)
		if err != nil {
			return nil, fmt.Errorf("telemetry lease: read guest %s/%d: %w", remoteID, m.VMID, err)
		}
		switch {
		case len(gs) == 0:
			return nil, &ReadGrantInputError{fmt.Sprintf("guest %d is not in the inventory of %s", m.VMID, remoteID)}
		case len(gs) > 1:
			return nil, &ReadGrantInputError{fmt.Sprintf("guest %d has more than one active incarnation; wait for the next inventory pass", m.VMID)}
		}
		g := gs[0]
		if g.VMID != m.VMID || g.Kind != m.Kind || g.Node != m.Node {
			return nil, &ReadGrantInputError{fmt.Sprintf("guest %d changed (kind or node): reload the page", m.VMID)}
		}
		if g.Generation != m.Generation {
			return nil, &ReadGrantInputError{fmt.Sprintf("guest %d was recreated since the page was loaded: reload the page", m.VMID)}
		}
		t := permit.ProviderMetricsTarget{Node: g.Node, Kind: g.Kind, VMID: g.VMID, Generation: g.Generation}
		if !t.Valid() {
			return nil, &ReadGrantInputError{fmt.Sprintf("guest %d has no valid generation in the inventory", m.VMID)}
		}
		out = append(out, t)
	}
	return out, nil
}

// ProposeProviderTelemetryGrant freezes the chosen node and guests of one
// PVE remote into a provider telemetry read-grant-v2 document, proposes it
// to the executor and returns the executor's complete canonical scope for
// approval (security key, or `nebula read-grant approve` in hardened mode).
//
// The document is: Grant permit.ReadGrantFormat, the server issuer, a fresh
// ID, Created now and Expiry after Days, Trigger permit.TriggerOnDemand
// (live reads only; no scheduled history reads), RateProfile
// permit.ProviderTelemetryProfile, MinIntervalS the live interval,
// RunBudget providerTelemetryBudget, and one provider target with the trust
// pin, trust generation and read credential version exactly as the
// executor's registry reports them, the method "metrics" and the metrics
// targets checked against inv, the current imported inventory
// (telemetryTargets; a guest's generation must match the posted one).
func (s *Service) ProposeProviderTelemetryGrant(ctx context.Context, user string, in ProviderTelemetryGrantRequest, inv TelemetryInventory) (ReadGrantPreview, error) {
	sel, err := checkProviderTelemetryRequest(in)
	if err != nil {
		return ReadGrantPreview{}, err
	}
	if inv == nil {
		return ReadGrantPreview{}, &ReadGrantInputError{"the PVE inventory is not available"}
	}
	exec, ok := s.exec.(readGrantProposer)
	if !ok {
		return ReadGrantPreview{}, ErrReadGrantProposeUnsupported
	}
	lister, ok := s.exec.(providerRemoteLister)
	if !ok {
		return ReadGrantPreview{}, ErrReadGrantProposeUnsupported
	}
	metrics, err := telemetryTargets(ctx, inv, in.RemoteID, sel)
	if err != nil {
		return ReadGrantPreview{}, err
	}
	known, err := s.providerRemotes(ctx, lister)
	if err != nil {
		return ReadGrantPreview{}, err
	}
	rm, ok := known[in.RemoteID]
	target, err := providerTarget(in.RemoteID, rm, ok, []string{permit.ProviderMethodMetrics})
	if err != nil {
		return ReadGrantPreview{}, err
	}
	target.MetricsTargets = metrics
	now := s.now()
	doc := permit.ReadGrantDoc{
		Grant: permit.ReadGrantFormat, Issuer: readGrantIssuer,
		CreatedUnix: now.Unix(), ExpiryUnix: now.Add(time.Duration(in.Days) * 24 * time.Hour).Unix(),
		Trigger: permit.TriggerOnDemand, RateProfile: permit.ProviderTelemetryProfile,
		MinIntervalS:    int64(permit.ProviderTelemetryLiveInterval / time.Second),
		RunBudget:       providerTelemetryBudget(len(metrics)),
		ProviderTargets: []permit.ProviderTarget{target},
	}
	if doc.ID, err = newUUID(); err != nil {
		return ReadGrantPreview{}, err
	}
	v, err := s.proposeProviderDoc(ctx, exec, doc, "provider telemetry")
	if err != nil {
		return ReadGrantPreview{}, err
	}
	s.log.Info("audit", "kind", "provider_telemetry_grant_proposed", "grant", v.ID, "digest", v.Digest, "user", user,
		"remote", in.RemoteID, "targets", len(metrics))
	return v, nil
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package ui

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
)

// Provider read leases (ADR 0007 E08): the "Proxmox remote" scope of the
// lease form. The form offers the active remotes of the executor registry
// (Options.PVERemotes) and the typed provider methods; POST /leases/preview
// with scope=provider proposes exactly the chosen remotes and methods via
// Leases.ProposeProviderReadGrant and redirects to the same proposal page
// as a host lease. Nothing is approved before the security key (or the
// hardened-mode CLI) approves the digest on that page.
//
// The handler checks the form itself before anything reaches the service:
// every remote must be active in the registry, at least one method must be
// chosen (an empty list would make the service fall back to its defaults,
// a scope the operator did not choose), no method may be unknown or
// repeated, and the lease lasts 7 or 30 days.

// leaseRemoteOption is one remote of the provider scope select.
type leaseRemoteOption struct {
	ID, Name string
	Selected bool
}

// leaseMethodOption is one provider method checkbox of the form.
type leaseMethodOption struct {
	ID, Description string
	Checked         bool
}

// providerMethodOptions are the methods the form offers, in display order,
// with one line on what each reads. Default methods are checked when the
// form is not pre-filled with methods.
var providerMethodOptions = []struct {
	ID, Description string
	Default         bool
}{
	{permit.ProviderMethodNodes, "node list with status, CPU, memory and versions", true},
	{permit.ProviderMethodGuests, "VM and container list with status, node and name", true},
	{permit.ProviderMethodStorage, "storage pools with type, usage and availability", true},
	{permit.ProviderMethodCluster, "cluster membership, quorum and HA states", true},
	{permit.ProviderMethodTasks, "bounded task metadata (actor, type, time, target, exit status), never raw task logs", true},
	{permit.ProviderMethodGuestConfig, "each guest's configuration: CPU, RAM, disks, NICs, boot order, passthrough, tags", false},
	{permit.ProviderMethodGuestAgent, "each guest's agent data: IP/MAC addresses, hostname, OS, filesystem summary", false},
	{permit.ProviderMethodSnapshots, "each guest's snapshot names, times, parents and RAM flag", false},
	{permit.ProviderMethodBackups, "nonsecret vzdump/PBS backup metadata and recent backup task summaries", false},
}

// providerMethodKnown reports whether the form offers method m.
func providerMethodKnown(m string) bool {
	for _, o := range providerMethodOptions {
		if o.ID == m {
			return true
		}
	}
	return false
}

// providerLeaseRemotes returns the active remotes of the registry sorted by
// ID, or ok=false when the registry is not configured or cannot be read.
func (h *Handler) providerLeaseRemotes(ctx context.Context) ([]PVERemoteMeta, bool) {
	if h.pveRemotes == nil {
		return nil, false
	}
	metas, err := h.pveRemotes(ctx)
	if err != nil {
		h.log.Error("list PVE remote metadata", "error", err)
		return nil, false
	}
	seen := map[string]bool{}
	var out []PVERemoteMeta
	for _, m := range metas {
		if m.State != "active" || !pvecontract.ValidRemoteID(m.RemoteID) || seen[m.RemoteID] {
			continue
		}
		seen[m.RemoteID] = true
		out = append(out, m)
		if len(out) == pveRemoteLimit {
			break
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RemoteID < out[j].RemoteID })
	return out, true
}

// providerLeaseForm adds the provider scope to the form: the active
// remotes and the methods, pre-filled from the query (the PVE page link
// and Refresh). Only active remotes and offered methods are kept.
func (h *Handler) providerLeaseForm(ctx context.Context, d *leaseNewData, q url.Values) {
	remotes, ok := h.providerLeaseRemotes(ctx)
	if !ok {
		return
	}
	d.ProviderOffered = true
	provider := q.Get("scope") == executions.ScopeProvider
	if provider {
		d.Kind, d.Value = executions.ScopeProvider, ""
	}
	selected := map[string]bool{}
	if provider {
		for _, id := range q["remote"] {
			selected[id] = true
		}
	}
	for _, m := range remotes {
		d.Remotes = append(d.Remotes, leaseRemoteOption{ID: m.RemoteID, Name: m.Name, Selected: selected[m.RemoteID]})
	}
	checked := map[string]bool{}
	if provider {
		for _, m := range q["method"] {
			if providerMethodKnown(m) {
				checked[m] = true
			}
		}
	}
	useDefaults := len(checked) == 0
	for _, o := range providerMethodOptions {
		c := checked[o.ID]
		if useDefaults {
			c = o.Default
		}
		d.Methods = append(d.Methods, leaseMethodOption{ID: o.ID, Description: o.Description, Checked: c})
	}
}

// checkProviderLeaseForm turns the posted provider form into a request, or
// returns the reason it is refused. active are the remotes the form may
// name.
func checkProviderLeaseForm(form url.Values, active map[string]bool) (executions.ProviderReadGrantRequest, string) {
	days, err := strconv.Atoi(form.Get("days"))
	if err != nil || (days != executions.ReadGrantShortDays && days != executions.ReadGrantLongDays) {
		return executions.ProviderReadGrantRequest{}, fmt.Sprintf("a read lease lasts %d or %d days", executions.ReadGrantShortDays, executions.ReadGrantLongDays)
	}
	remotes := form["remote"]
	if len(remotes) == 0 || len(remotes) > permit.MaxProviderTargets {
		return executions.ProviderReadGrantRequest{}, fmt.Sprintf("choose 1 to %d Proxmox remotes", permit.MaxProviderTargets)
	}
	seen := map[string]bool{}
	for _, id := range remotes {
		if !pvecontract.ValidRemoteID(id) || seen[id] {
			return executions.ProviderReadGrantRequest{}, "a Proxmox remote is malformed or chosen twice"
		}
		if !active[id] {
			return executions.ProviderReadGrantRequest{}, "a chosen Proxmox remote is not active"
		}
		seen[id] = true
	}
	methods := form["method"]
	if len(methods) == 0 {
		return executions.ProviderReadGrantRequest{}, "choose at least one method"
	}
	seen = map[string]bool{}
	for _, m := range methods {
		if !providerMethodKnown(m) || !permit.ValidProviderMethod(m) || seen[m] {
			return executions.ProviderReadGrantRequest{}, "a method is unknown or chosen twice"
		}
		seen[m] = true
	}
	return executions.ProviderReadGrantRequest{
		RemoteIDs: append([]string(nil), remotes...),
		Methods:   append([]string(nil), methods...),
		Days:      days,
	}, ""
}

// handleProviderLeasePreview proposes a provider lease (scope=provider of
// POST /leases/preview; the form is already parsed) and redirects to its
// proposal page. Errors are plain text for formpost.js.
func (h *Handler) handleProviderLeasePreview(w http.ResponseWriter, r *http.Request) {
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
	in, reason := checkProviderLeaseForm(r.PostForm, active)
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
	v, err := h.leases.ProposeProviderReadGrant(ctx, user, in)
	if err != nil {
		var ie *executions.ReadGrantInputError
		switch {
		case errors.As(err, &ie):
			http.Error(w, ie.Reason, http.StatusBadRequest)
		case errors.Is(err, executions.ErrProviderRemotesUnavailable), errors.Is(err, executions.ErrReadGrantProposeFailed),
			errors.Is(err, executions.ErrReadGrantProposalMismatch), errors.Is(err, executions.ErrReadGrantProposeUnsupported):
			h.log.Error("propose provider read grant", "error", err)
			http.Error(w, err.Error(), http.StatusBadGateway)
		default:
			h.log.Error("propose provider read grant", "error", err)
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

// providerLeaseRefreshURL is the form URL pre-filled with a provider
// lease's remotes, methods and lifetime, or "" when it cannot be refreshed.
func providerLeaseRefreshURL(v executions.ReadGrantView) string {
	if v.RateProfile == permit.ProviderTelemetryProfile {
		return pveLiveRenewURL(v)
	}
	in, ok := v.ProviderRefresh()
	if !ok {
		return ""
	}
	q := url.Values{}
	q.Set("scope", executions.ScopeProvider)
	for _, id := range in.RemoteIDs {
		q.Add("remote", id)
	}
	for _, m := range in.Methods {
		q.Add("method", m)
	}
	q.Set("days", strconv.Itoa(in.Days))
	if leaseIDRe.MatchString(v.ID) {
		q.Set("refresh", v.ID)
	}
	return "/leases/new?" + q.Encode()
}

// leaseProviderRow is one frozen remote of a provider lease detail page.
type leaseProviderRow struct {
	RemoteID, PinPrefix, Methods       string
	TrustGeneration, CredentialVersion string
	// Binding is executions.ProviderBindingCurrent, ProviderBindingStale
	// or "" (unknown).
	Binding string
	// Targets are the exact metrics targets of a telemetry lease.
	Targets []leaseMetricsTarget
}

// leaseMetricsTarget is one frozen metrics target, rendered as text.
type leaseMetricsTarget struct {
	Node, Kind, VMID, Generation string
}

// leaseMetricsTargets renders the metrics targets of one remote in
// document order (a node has no VMID or generation).
func leaseMetricsTargets(ms []permit.ProviderMetricsTarget) []leaseMetricsTarget {
	out := make([]leaseMetricsTarget, 0, len(ms))
	for _, m := range ms {
		t := leaseMetricsTarget{Node: m.Node, Kind: m.Kind}
		if m.Kind != permit.MetricsKindNode {
			t.VMID, t.Generation = strconv.FormatUint(m.VMID, 10), strconv.FormatUint(m.Generation, 10)
		}
		out = append(out, t)
	}
	return out
}

// leaseProviderRows renders the frozen remotes of a provider lease.
func leaseProviderRows(v executions.ReadGrantView) []leaseProviderRow {
	out := make([]leaseProviderRow, 0, len(v.Providers))
	for _, p := range v.Providers {
		out = append(out, leaseProviderRow{
			RemoteID: p.RemoteID, PinPrefix: p.PinPrefix, Methods: strings.Join(p.Methods, ", "),
			TrustGeneration:   strconv.FormatUint(p.TrustGeneration, 10),
			CredentialVersion: strconv.FormatInt(p.CredentialVersion, 10),
			Binding:           p.Binding, Targets: leaseMetricsTargets(p.MetricsTargets),
		})
	}
	return out
}

// pveLiveRenewURL is the PVE page of a telemetry lease's remote, where a
// new live-values lease is chosen from the current inventory; "" when v is
// not an active or expired telemetry lease of exactly one remote.
func pveLiveRenewURL(v executions.ReadGrantView) string {
	if (v.State != "active" && v.State != "expired") || v.RateProfile != permit.ProviderTelemetryProfile || len(v.Providers) != 1 ||
		!pvecontract.ValidRemoteID(v.Providers[0].RemoteID) {
		return ""
	}
	return "/pve/" + url.PathEscape(v.Providers[0].RemoteID) + "#live"
}

// leaseProviderMethodCount is the number of distinct methods over the
// remotes of a provider lease.
func leaseProviderMethodCount(v executions.ReadGrantView) int {
	seen := map[string]bool{}
	for _, p := range v.Providers {
		for _, m := range p.Methods {
			seen[m] = true
		}
	}
	return len(seen)
}

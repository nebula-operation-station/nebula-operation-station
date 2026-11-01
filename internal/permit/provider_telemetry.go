// SPDX-License-Identifier: AGPL-3.0-or-later

package permit

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
	"github.com/nebula-operation-station/nebula-operation-station/internal/schedgrant"
)

// ProviderTelemetryProfile is the read-grant-v2 rate profile for PVE
// metrics reads (spec 17 "SSH/provider telemetry leases", spec 12
// "Visible-target requests"). A telemetry grant binds exact remotes with
// their trust pin, generation and read credential version, the single
// method "metrics" and the exact metrics targets (node, guest kind, VMID
// and local guest generation). It is separate from ProviderReadProfile so
// that its shorter intervals never apply to inventory reads.
const ProviderTelemetryProfile = "provider_telemetry"

// ProviderMethodMetrics is the only method a provider telemetry grant names.
const ProviderMethodMetrics = "metrics"

// Provider telemetry limits (spec 17).
const (
	// ProviderTelemetryLiveInterval is the shortest interval between two
	// live (on-demand) reads of one metrics target.
	ProviderTelemetryLiveInterval = schedgrant.TelemetryLiveInterval
	// ProviderTelemetryHistoryInterval is the shortest interval between
	// two scheduled history reads of one metrics target.
	ProviderTelemetryHistoryInterval = schedgrant.TelemetryHistoryInterval
	// MaxProviderTelemetryBudget caps the approved metrics requests per
	// remote per rolling hour.
	MaxProviderTelemetryBudget = schedgrant.MaxTelemetryRunBudget
	// MaxProviderMetricsTargets bounds the metrics targets per remote.
	MaxProviderMetricsTargets = 64
)

// Metrics target kinds: the node itself, or one QEMU or LXC guest.
const (
	MetricsKindNode = "node"
	MetricsKindQEMU = "qemu"
	MetricsKindLXC  = "lxc"
)

// ProviderMetricsTarget is one exact metrics target. A node target has
// kind "node", VMID 0 and generation 0; a guest target names its node,
// kind, VMID and the local guest incarnation generation, so a recreated
// guest with a reused VMID needs a new grant.
type ProviderMetricsTarget struct {
	Node       string `json:"node"`
	Kind       string `json:"kind"`
	VMID       uint64 `json:"vmid"`
	Generation uint64 `json:"generation"`
}

// Valid reports whether m is a well-formed metrics target.
func (m ProviderMetricsTarget) Valid() bool {
	if !pvecontract.ValidNodeName(m.Node) {
		return false
	}
	switch m.Kind {
	case MetricsKindNode:
		return m.VMID == 0 && m.Generation == 0
	case MetricsKindQEMU, MetricsKindLXC:
		return m.VMID >= pvecontract.MinVMID && m.VMID <= pvecontract.MaxVMID &&
			m.Generation >= 1 && m.Generation <= pvecontract.MaxGuestGeneration
	}
	return false
}

// Key is the target's identity without its generation; one remote lists a
// node/kind/VMID at most once.
func (m ProviderMetricsTarget) Key() string {
	return m.Node + "/" + m.Kind + "/" + strconv.FormatUint(m.VMID, 10)
}

// validateProviderTelemetryGrant checks the members of a v2 grant whose
// rate profile is ProviderTelemetryProfile.
func validateProviderTelemetryGrant(d ReadGrantDoc) error {
	switch {
	case len(d.Actions) != 0 || len(d.Targets) != 0 || len(d.Credentials) != 0:
		return errors.New("a provider telemetry grant binds no SSH actions, hosts or credentials")
	case d.MinIntervalS < int64(ProviderTelemetryLiveInterval/time.Second) || d.MinIntervalS > int64(schedgrant.MaxInterval/time.Second):
		return fmt.Errorf("min_interval_s must be %d to %d", int64(ProviderTelemetryLiveInterval/time.Second), int64(schedgrant.MaxInterval/time.Second))
	case d.RunBudget < 1 || d.RunBudget > MaxProviderTelemetryBudget:
		return fmt.Errorf("run_budget must be 1 to %d", MaxProviderTelemetryBudget)
	case len(d.ProviderTargets) == 0 || len(d.ProviderTargets) > MaxProviderTargets:
		return fmt.Errorf("a provider telemetry grant has 1 to %d remotes", MaxProviderTargets)
	}
	seen := map[string]bool{}
	for _, t := range d.ProviderTargets {
		switch {
		case !pvecontract.ValidRemoteID(t.RemoteID) || !pvecontract.ValidTrustPin(t.TrustPin):
			return errors.New("a provider remote identity is malformed")
		case seen[t.RemoteID]:
			return fmt.Errorf("remote %s listed twice", t.RemoteID)
		case t.TrustGeneration < 1 || t.TrustGeneration > maxProviderTrustGeneration:
			return fmt.Errorf("remote %s: trust_generation out of range", t.RemoteID)
		case t.CredentialVersion < 1 || t.CredentialVersion > maxProviderCredentialVersion:
			return fmt.Errorf("remote %s: credential_version out of range", t.RemoteID)
		case !slices.Equal(t.Methods, []string{ProviderMethodMetrics}):
			return fmt.Errorf("remote %s: a provider telemetry grant names exactly the method %q", t.RemoteID, ProviderMethodMetrics)
		case len(t.MetricsTargets) == 0 || len(t.MetricsTargets) > MaxProviderMetricsTargets:
			return fmt.Errorf("remote %s: 1 to %d metrics targets", t.RemoteID, MaxProviderMetricsTargets)
		}
		seen[t.RemoteID] = true
		keys := map[string]bool{}
		for _, m := range t.MetricsTargets {
			if !m.Valid() || keys[m.Key()] {
				return fmt.Errorf("remote %s: a metrics target is malformed or listed twice", t.RemoteID)
			}
			keys[m.Key()] = true
		}
	}
	return nil
}

// ProviderMetricsRead is one metrics read the executor is about to make.
// The remote identity comes from the executor registry; the target and
// Live select work inside existing authority.
type ProviderMetricsRead struct {
	RemoteID          string
	TrustPin          string
	TrustGeneration   uint64
	CredentialVersion int64
	Target            ProviderMetricsTarget
	// Live selects the on-demand live path (10-s interval, trigger
	// on_demand); otherwise the read is a scheduled history sample
	// (5-min interval, trigger scheduled).
	Live bool
}

// trigger returns the grant trigger the read needs.
func (r ProviderMetricsRead) trigger() string {
	if r.Live {
		return TriggerOnDemand
	}
	return TriggerScheduled
}

// providerMetricsActionKey is the interval key of one metrics read: the
// exact target and path, so live and history keep separate cadences while
// sharing the remote's request budget.
func providerMetricsActionKey(r ProviderMetricsRead) string {
	path := "history"
	if r.Live {
		path = "live"
	}
	return "pve." + ProviderMethodMetrics + ":" + r.Target.Key() + ":" + path
}

// providerMetricsBudgetKey is the rolling-hour counter of one remote's
// metrics reads. It is separate from the inventory counter
// (providerBudgetKey): live charts must never starve the 60-second
// inventory collection, and each profile keeps its own approved budget.
func providerMetricsBudgetKey(remoteID string) string { return "pvemetrics:" + remoteID }

// coversMetrics reports whether t authorizes r: same remote, identical
// trust pin, generation and credential version, and the exact target
// including its guest generation.
func (t ProviderTarget) coversMetrics(r ProviderMetricsRead) bool {
	return t.RemoteID == r.RemoteID && slices.Equal(t.Methods, []string{ProviderMethodMetrics}) &&
		t.TrustPin == r.TrustPin && t.TrustGeneration == r.TrustGeneration && t.CredentialVersion == r.CredentialVersion &&
		slices.Contains(t.MetricsTargets, r.Target)
}

// AuthorizeProviderMetrics finds an active provider telemetry grant whose
// trigger covers the read's path and whose remote lists the exact target,
// and durably reserves one request of its per-remote budget and the
// target's live or history interval. Like AuthorizeProviderRead it is
// refused while reads are paused or recovery is pending; the returned
// claim must be re-checked before the request and before the result is
// returned.
func (a *Authority) AuthorizeProviderMetrics(r ProviderMetricsRead) (ProviderClaim, error) {
	if a.leases == nil {
		return ProviderClaim{}, fail(CodeLeaseUnavailable, "")
	}
	if !pvecontract.ValidRemoteID(r.RemoteID) || !r.Target.Valid() {
		return ProviderClaim{}, fail(CodeLeaseInvalid, "malformed provider metrics read")
	}
	trigger := r.trigger()
	floor := ProviderTelemetryHistoryInterval
	if r.Live {
		floor = ProviderTelemetryLiveInterval
	}
	return a.authorizeProvider(providerAuth{
		profile: ProviderTelemetryProfile, remoteID: r.RemoteID, actionKey: providerMetricsActionKey(r),
		budgetKey: providerMetricsBudgetKey(r.RemoteID),
		label:     ProviderMethodMetrics + " " + r.Target.Key(),
		listed: func(t ProviderTarget, d ReadGrantDoc) bool {
			if d.Trigger != trigger && d.Trigger != TriggerBoth {
				return false
			}
			return slices.ContainsFunc(t.MetricsTargets, func(m ProviderMetricsTarget) bool { return m.Key() == r.Target.Key() })
		},
		covers: func(t ProviderTarget) bool { return t.coversMetrics(r) },
		interval: func(d ReadGrantDoc) time.Duration {
			return max(time.Duration(d.MinIntervalS)*time.Second, floor)
		},
		notCovered: "no active provider telemetry grant covers this target and trigger",
	})
}

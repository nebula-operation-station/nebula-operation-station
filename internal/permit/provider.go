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

// ProviderReadProfile is the read-grant-v2 rate profile for typed PVE
// provider reads (ADR 0007 E08, spec 07 "Provider profile"). A provider
// grant binds exact remotes, their trust pin and generation, the read
// credential version and the typed methods; it binds no SSH actions or
// hosts.
const ProviderReadProfile = "provider"

// Provider profile limits (spec 07, 17). Non-metrics request budgets are
// approval-bound; these are the maxima the executor accepts.
const (
	// MaxProviderTargets bounds the remotes one provider grant names.
	MaxProviderTargets = 16
	// ProviderMinInterval is the shortest approved interval between two
	// reads of one method on one remote (the 60-second collection cadence).
	ProviderMinInterval = time.Minute
	// MaxProviderRequestBudget caps the approved requests per remote per
	// rolling hour, across all methods.
	MaxProviderRequestBudget = 4096
	// maxProviderTrustGeneration mirrors the registry's generation bound.
	maxProviderTrustGeneration = uint64(1)<<48 - 1
	// maxProviderCredentialVersion keeps versions exact in JSON numbers.
	maxProviderCredentialVersion = int64(1)<<53 - 1
)

// Provider read methods a grant may name. METRICS is deliberately absent:
// provider telemetry has its own live-target and request-rate rules.
const (
	ProviderMethodNodes       = "nodes"
	ProviderMethodGuests      = "guests"
	ProviderMethodGuestConfig = "guest_config"
	ProviderMethodGuestAgent  = "guest_agent"
	ProviderMethodStorage     = "storage"
	ProviderMethodSnapshots   = "snapshots"
	ProviderMethodCluster     = "cluster"
	ProviderMethodTasks       = "tasks"
	ProviderMethodBackups     = "backups"
)

var providerMethods = []string{
	ProviderMethodNodes, ProviderMethodGuests, ProviderMethodGuestConfig, ProviderMethodGuestAgent,
	ProviderMethodStorage, ProviderMethodSnapshots, ProviderMethodCluster, ProviderMethodTasks, ProviderMethodBackups,
}

// ValidProviderMethod reports whether m is a typed provider read method.
func ValidProviderMethod(m string) bool { return slices.Contains(providerMethods, m) }

// ProviderTarget is one remote in a provider grant's frozen scope. Any
// change of trust pin, trust generation or read credential version leaves
// the grant without effect for that remote; a new grant is required.
type ProviderTarget struct {
	RemoteID          string   `json:"remote_id"`
	TrustPin          string   `json:"trust_pin"`
	TrustGeneration   uint64   `json:"trust_generation"`
	CredentialVersion int64    `json:"credential_version"`
	Methods           []string `json:"methods"`
	// MetricsTargets binds the exact metrics targets of a provider
	// telemetry grant (ProviderTelemetryProfile); other provider grants
	// leave it empty.
	MetricsTargets []ProviderMetricsTarget `json:"metrics_targets,omitempty"`
}

// ProviderTarget returns the frozen provider target for remoteID.
func (d ReadGrantDoc) ProviderTarget(remoteID string) (ProviderTarget, bool) {
	for _, t := range d.ProviderTargets {
		if t.RemoteID == remoteID {
			return t, true
		}
	}
	return ProviderTarget{}, false
}

// validateProviderGrant checks the provider-specific members of a v2 grant
// whose rate profile is ProviderReadProfile.
func validateProviderGrant(d ReadGrantDoc) error {
	switch {
	case len(d.Actions) != 0 || len(d.Targets) != 0 || len(d.Credentials) != 0:
		return errors.New("a provider grant binds no SSH actions, hosts or credentials")
	case d.Trigger != TriggerScheduled && d.Trigger != TriggerBoth:
		return fmt.Errorf("a provider grant must cover %q reads", TriggerScheduled)
	case d.MinIntervalS < int64(ProviderMinInterval/time.Second) || d.MinIntervalS > int64(schedgrant.MaxInterval/time.Second):
		return fmt.Errorf("min_interval_s must be %d to %d", int64(ProviderMinInterval/time.Second), int64(schedgrant.MaxInterval/time.Second))
	case d.RunBudget < 1 || d.RunBudget > MaxProviderRequestBudget:
		return fmt.Errorf("run_budget must be 1 to %d", MaxProviderRequestBudget)
	case len(d.ProviderTargets) == 0 || len(d.ProviderTargets) > MaxProviderTargets:
		return fmt.Errorf("a provider grant has 1 to %d remotes", MaxProviderTargets)
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
		case len(t.Methods) == 0 || len(t.Methods) > len(providerMethods):
			return fmt.Errorf("remote %s: 1 to %d methods", t.RemoteID, len(providerMethods))
		case len(t.MetricsTargets) != 0:
			return fmt.Errorf("remote %s: only provider telemetry grants bind metrics targets", t.RemoteID)
		}
		seen[t.RemoteID] = true
		methods := map[string]bool{}
		for _, m := range t.Methods {
			if !ValidProviderMethod(m) || methods[m] {
				return fmt.Errorf("remote %s: method is unknown or listed twice", t.RemoteID)
			}
			methods[m] = true
		}
	}
	return nil
}

// ProviderRead is one typed provider read the executor is about to make,
// with the remote's current registry identity. The executor fills it from
// its own registry; nothing in it comes from the caller except the remote
// ID and method, which select work inside existing authority.
type ProviderRead struct {
	RemoteID string
	Method   string
	// VMID is the guest of a per-guest method (guest_config, guest_agent,
	// snapshots, backups) and 0 for remote-wide methods. It keys the
	// method's interval per guest; the request budget stays per remote.
	VMID              uint64
	TrustPin          string
	TrustGeneration   uint64
	CredentialVersion int64
}

// providerBudgetKey is the budget and interval target of one remote. The
// prefix keeps it disjoint from SSH host IDs, which cannot contain ':'.
func providerBudgetKey(remoteID string) string { return "pve:" + remoteID }

// providerGuestMethods are the methods that read one guest.
var providerGuestMethods = []string{ProviderMethodGuestConfig, ProviderMethodGuestAgent, ProviderMethodSnapshots, ProviderMethodBackups}

// maxProviderVMID is the largest guest ID a provider read may name.
const maxProviderVMID = pvecontract.MaxVMID

// validProviderRead reports whether r names a remote and method, with a
// guest exactly for the per-guest methods.
func validProviderRead(r ProviderRead) bool {
	if !pvecontract.ValidRemoteID(r.RemoteID) || !ValidProviderMethod(r.Method) {
		return false
	}
	if slices.Contains(providerGuestMethods, r.Method) {
		return r.VMID >= pvecontract.MinVMID && r.VMID <= maxProviderVMID
	}
	return r.VMID == 0
}

// providerActionKey is the interval key of one read: the method, and for
// per-guest methods the guest, so each guest keeps its own cadence.
func providerActionKey(r ProviderRead) string {
	if r.VMID != 0 {
		return "pve." + r.Method + ":" + strconv.FormatUint(r.VMID, 10)
	}
	return "pve." + r.Method
}

// covers reports whether the provider target authorizes r: same remote,
// method listed, and identical trust pin, generation and credential version.
func (t ProviderTarget) covers(r ProviderRead) bool {
	return t.RemoteID == r.RemoteID && slices.Contains(t.Methods, r.Method) &&
		t.TrustPin == r.TrustPin && t.TrustGeneration == r.TrustGeneration && t.CredentialVersion == r.CredentialVersion
}

// ProviderClaim is one reserved provider read. It carries no authority of
// its own: Check re-verifies the lock generation and the grant before and
// after the read, so a lock, restart or revocation during the request
// discards its result.
type ProviderClaim struct {
	// GrantID names the grant whose budget paid for the read.
	GrantID   string
	authority *Authority
	// profile and covers are the rate profile and the exact-scope test of
	// the reserved read; Check re-applies them to the paying grant.
	profile  string
	remoteID string
	covers   func(ProviderTarget) bool
	epoch    uint64
}

// AuthorizeProviderRead finds an active provider grant that covers r and
// durably reserves one request of its per-remote budget and per-method
// interval. Reads are refused while dispatch is paused (after lock or
// restart until local credential unlock) and during recovery.
func (a *Authority) AuthorizeProviderRead(r ProviderRead) (ProviderClaim, error) {
	if a.leases == nil {
		return ProviderClaim{}, fail(CodeLeaseUnavailable, "")
	}
	if !validProviderRead(r) {
		return ProviderClaim{}, fail(CodeLeaseInvalid, "malformed provider read")
	}
	return a.authorizeProvider(providerAuth{
		profile: ProviderReadProfile, remoteID: r.RemoteID, label: r.Method, actionKey: providerActionKey(r),
		budgetKey: providerBudgetKey(r.RemoteID),
		listed:    func(t ProviderTarget, _ ReadGrantDoc) bool { return slices.Contains(t.Methods, r.Method) },
		covers:    func(t ProviderTarget) bool { return t.covers(r) },
		interval: func(d ReadGrantDoc) time.Duration {
			return time.Duration(d.MinIntervalS) * time.Second
		},
		notCovered: "no active provider grant covers this remote and method",
	})
}

// providerAuth describes one provider reservation for authorizeProvider.
type providerAuth struct {
	profile  string
	remoteID string
	// label names the work in audit events (method or metrics target).
	label     string
	actionKey string
	// budgetKey names the rolling-hour counter the read spends.
	budgetKey string
	// listed reports whether a grant's target names this work at all;
	// covers additionally requires the exact frozen identity.
	listed     func(ProviderTarget, ReadGrantDoc) bool
	covers     func(ProviderTarget) bool
	interval   func(ReadGrantDoc) time.Duration
	notCovered string
}

// authorizeProvider finds the active grants of p.profile that cover the
// work and durably reserves one request of the per-remote budget and the
// per-work interval from the first one with room left.
func (a *Authority) authorizeProvider(p providerAuth) (ProviderClaim, error) {
	a.mu.Lock()
	epoch, paused := a.readEpoch, a.readPaused
	a.mu.Unlock()
	if paused {
		return ProviderClaim{}, fail(CodeLeaseInactive, "provider reads are paused until local credential unlock")
	}
	if err := a.checkReadRecovery(); err != nil {
		return ProviderClaim{}, err
	}
	now, err := a.leases.ReadGrantClock(a.now())
	if err != nil {
		return ProviderClaim{}, a.storageFailure("provider:"+p.remoteID, err)
	}
	grants, err := a.leases.ReadGrants()
	if err != nil {
		return ProviderClaim{}, a.storageFailure("provider:"+p.remoteID, err)
	}
	slices.SortFunc(grants, func(x, y StoredReadGrant) int {
		switch {
		case x.ID < y.ID:
			return -1
		case x.ID > y.ID:
			return 1
		}
		return 0
	})
	deny := func(code Code, detail string) error {
		a.emit(Event{Kind: "denied", Digest: "provider:" + p.remoteID, Code: code, Detail: p.label + ": " + detail})
		return &Error{Code: code, Detail: detail}
	}
	type candidate struct {
		id  string
		doc ReadGrantDoc
	}
	var candidates []candidate
	stale := false
	for _, g := range grants {
		if !g.RevokedAt.IsZero() || !now.Before(g.ExpiresAt) {
			continue
		}
		doc, digest, err := readGrantScope(g)
		if err != nil || digest != g.Digest || doc.ID != g.ID || doc.ExpiryUnix != g.ExpiresAt.Unix() {
			return ProviderClaim{}, a.storageFailure("readgrant:"+g.ID, fmt.Errorf("stored read grant does not verify: %v", err))
		}
		if doc.RateProfile != p.profile {
			continue
		}
		t, ok := doc.ProviderTarget(p.remoteID)
		if !ok || !p.listed(t, doc) {
			continue
		}
		if !p.covers(t) {
			stale = true
			continue
		}
		candidates = append(candidates, candidate{id: g.ID, doc: doc})
	}
	if len(candidates) == 0 {
		if stale {
			return ProviderClaim{}, deny(CodeLeaseNotCovered, "the remote's trust or credential changed; the provider grant needs replacement")
		}
		return ProviderClaim{}, deny(CodeLeaseNotCovered, p.notCovered)
	}
	budgetDenied := false
	for _, c := range candidates {
		reserved, err := a.leases.ReserveReadRun(c.id, p.actionKey, p.budgetKey, a.now(), int(c.doc.RunBudget), p.interval(c.doc))
		if errors.Is(err, ErrReadGrantInactive) {
			continue
		}
		if err != nil {
			return ProviderClaim{}, a.storageFailure("readgrant:"+c.id, err)
		}
		if !reserved {
			budgetDenied = true
			continue
		}
		a.emit(Event{Kind: "authorized", Digest: "readgrant:" + c.id, Detail: fmt.Sprintf("provider %s %s budget_claimed", p.remoteID, p.label)})
		return ProviderClaim{GrantID: c.id, authority: a, profile: p.profile, remoteID: p.remoteID, covers: p.covers, epoch: epoch}, nil
	}
	if budgetDenied {
		return ProviderClaim{}, deny(CodeLeaseBudget, "provider interval or rolling-hour request budget exhausted")
	}
	return ProviderClaim{}, deny(CodeLeaseInactive, "the provider grant was revoked or has expired")
}

// Check re-verifies a reserved provider read without spending again: the
// lock generation is unchanged, dispatch is not paused, recovery is not
// pending, and the paying grant is still active and still covers the read.
// The executor calls it before sending the request and again before
// returning the result; it is serialized with Lock and revocation.
func (c ProviderClaim) Check() error {
	a := c.authority
	if a == nil || c.covers == nil {
		return fail(CodeLeaseInactive, "no reserved provider read")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.readPaused || c.epoch != a.readEpoch {
		return fail(CodeLeaseInactive, "provider read was paused by lock")
	}
	if err := a.checkReadRecovery(); err != nil {
		return err
	}
	now, err := a.leases.ReadGrantClock(a.now())
	if err != nil {
		return a.storageFailure("readgrant:"+c.GrantID, err)
	}
	g, ok, err := a.leases.ReadGrant(c.GrantID)
	if err != nil {
		return a.storageFailure("readgrant:"+c.GrantID, err)
	}
	if !ok || !g.RevokedAt.IsZero() || !now.Before(g.ExpiresAt) {
		return fail(CodeLeaseInactive, "the provider grant was revoked or has expired")
	}
	doc, digest, err := readGrantScope(g)
	if err != nil || digest != g.Digest || doc.ID != g.ID {
		return a.storageFailure("readgrant:"+c.GrantID, fmt.Errorf("stored read grant does not verify: %v", err))
	}
	t, ok := doc.ProviderTarget(c.remoteID)
	if doc.RateProfile != c.profile || !ok || !c.covers(t) {
		return fail(CodeLeaseNotCovered, "the provider grant no longer covers this read")
	}
	return nil
}

// RevokeProviderGrants revokes every active provider grant that names
// remoteID (remote removed, blocked or re-pinned). It needs no approval and
// returns the number of grants revoked.
func (a *Authority) RevokeProviderGrants(remoteID, who string) (int, error) {
	if a.leases == nil {
		return 0, nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	grants, err := a.leases.ReadGrants()
	if err != nil {
		return 0, a.storageFailure("provider:"+remoteID, err)
	}
	n := 0
	for _, g := range grants {
		if !g.RevokedAt.IsZero() {
			continue
		}
		doc, _, err := readGrantScope(g)
		if err != nil || (doc.RateProfile != ProviderReadProfile && doc.RateProfile != ProviderTelemetryProfile) {
			continue
		}
		if _, ok := doc.ProviderTarget(remoteID); !ok {
			continue
		}
		ok, err := a.leases.RevokeReadGrant(g.ID, a.now())
		if err != nil {
			return n, a.storageFailure("readgrant:"+g.ID, err)
		}
		if ok {
			n++
			a.emit(Event{Kind: "read_grant_revoked", Detail: g.ID + " by " + who + " (provider remote " + remoteID + ")"})
		}
	}
	return n, nil
}

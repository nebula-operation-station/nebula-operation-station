// SPDX-License-Identifier: AGPL-3.0-or-later

package executions

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// Provider read leases (ADR 0007 E08, spec 07 "Provider profile"). The
// server freezes the chosen PVE remotes with the trust pin, trust
// generation and read credential version the executor reports for them
// into a read-grant-v2 document with the provider rate profile. The
// document binds typed provider methods only: no SSH actions, hosts or
// credentials. It goes through the same proposal, preview and approval
// flow as a host lease; the executor re-checks every binding against its
// registry before it records the proposal.

// Limits and fixed values of provider read-lease proposals.
const (
	// providerReadsPerHour is how often one remote-wide method can be read
	// per rolling hour at the provider minimum interval.
	providerReadsPerHour = int64(time.Hour / permit.ProviderMinInterval)
	// providerBudgetMargin multiplies the collector's hourly reads so that
	// guest-join identity reads (which spend the same per-remote budget)
	// and a poll pass running slightly early never exhaust the budget.
	providerBudgetMargin = 2
	// pveRemoteStateActive is the executor registry state of a usable
	// remote (executordb.StateActive).
	pveRemoteStateActive = "active"
)

// providerGuestMethods are the methods read once per guest; the number of
// guests is not known when the lease is proposed.
var providerGuestMethods = []string{
	permit.ProviderMethodGuestConfig, permit.ProviderMethodGuestAgent,
	permit.ProviderMethodSnapshots, permit.ProviderMethodBackups,
}

// ErrProviderRemotesUnavailable reports that the executor's PVE remote
// metadata could not be read or was ambiguous.
var ErrProviderRemotesUnavailable = errors.New("the executor's PVE remotes could not be listed")

// DefaultProviderReadMethods returns the methods a provider lease covers
// when the request names none, sorted: what the collector reads from every
// remote on each pass (nodes, guests, storage, cluster, tasks).
func DefaultProviderReadMethods() []string {
	return []string{
		permit.ProviderMethodCluster, permit.ProviderMethodGuests, permit.ProviderMethodNodes,
		permit.ProviderMethodStorage, permit.ProviderMethodTasks,
	}
}

// ProviderReadGrantRequest is what the provider lease form submits.
type ProviderReadGrantRequest struct {
	// RemoteIDs are the PVE remotes, 1 to permit.MaxProviderTargets.
	RemoteIDs []string
	// Methods are the typed provider methods; empty selects
	// DefaultProviderReadMethods.
	Methods []string
	Days    int // ReadGrantShortDays or ReadGrantLongDays
}

// ReadGrantPreviewProvider is one frozen PVE remote of a provider lease,
// exactly as the executor's canonical document binds it.
type ReadGrantPreviewProvider struct {
	RemoteID          string
	TrustPin          string
	TrustGeneration   uint64
	CredentialVersion int64
	Methods           []string
}

// providerRemoteLister reads the executor's PVE remote metadata (state,
// trust pin and generation, read credential version; never a token).
type providerRemoteLister interface {
	ListPVEAdminRemotes(ctx context.Context, in *pb.ListPVEAdminRemotesRequest, opts ...grpc.CallOption) (*pb.ListPVEAdminRemotesResponse, error)
}

// checkProviderReadGrantRequest validates the form input and returns the
// sorted remote IDs and methods.
func checkProviderReadGrantRequest(in ProviderReadGrantRequest) (remotes, methods []string, err error) {
	if in.Days != ReadGrantShortDays && in.Days != ReadGrantLongDays {
		return nil, nil, &ReadGrantInputError{fmt.Sprintf("a read lease lasts %d or %d days", ReadGrantShortDays, ReadGrantLongDays)}
	}
	if len(in.RemoteIDs) == 0 || len(in.RemoteIDs) > permit.MaxProviderTargets {
		return nil, nil, &ReadGrantInputError{fmt.Sprintf("choose 1 to %d PVE remotes", permit.MaxProviderTargets)}
	}
	seen := map[string]bool{}
	for _, id := range in.RemoteIDs {
		if !pvecontract.ValidRemoteID(id) || seen[id] {
			return nil, nil, &ReadGrantInputError{"a PVE remote is malformed or listed twice"}
		}
		seen[id] = true
	}
	methods = in.Methods
	if len(methods) == 0 {
		methods = DefaultProviderReadMethods()
	}
	seen = map[string]bool{}
	for _, m := range methods {
		if !permit.ValidProviderMethod(m) || seen[m] {
			return nil, nil, &ReadGrantInputError{"a provider method is unknown or listed twice"}
		}
		seen[m] = true
	}
	remotes = slices.Clone(in.RemoteIDs)
	sort.Strings(remotes)
	methods = slices.Clone(methods)
	sort.Strings(methods)
	return remotes, methods, nil
}

// providerRunBudget sizes the per-remote rolling-hour request budget. The
// executor spends one unit of it for every ReadPVE request on the remote,
// across all methods (permit.AuthorizeProviderRead, budget key per remote),
// and allows each method (each method and guest for per-guest methods) at
// most once per min_interval_s. The collector reads every remote-wide
// method once per pass (every 60 s), so remote-wide methods need
// providerReadsPerHour units each; the budget allows twice that. A
// per-guest method needs one unit per guest and pass, which cannot be
// bounded here, so it takes the executor's maximum.
func providerRunBudget(methods []string) int64 {
	for _, m := range methods {
		if slices.Contains(providerGuestMethods, m) {
			return permit.MaxProviderRequestBudget
		}
	}
	return min(int64(len(methods))*providerReadsPerHour*providerBudgetMargin, permit.MaxProviderRequestBudget)
}

// providerRemotes reads the executor's PVE remote metadata keyed by remote
// ID. A listing that names a remote twice is refused as ambiguous.
func (s *Service) providerRemotes(ctx context.Context, l providerRemoteLister) (map[string]*pb.PVEAdminRemote, error) {
	cctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	r, err := l.ListPVEAdminRemotes(cctx, &pb.ListPVEAdminRemotesRequest{})
	if err != nil {
		s.log.Warn("provider read grant remotes", "code", status.Code(err).String())
		return nil, ErrProviderRemotesUnavailable
	}
	out := make(map[string]*pb.PVEAdminRemote, len(r.GetRemotes()))
	for _, rm := range r.GetRemotes() {
		if _, dup := out[rm.GetRemoteId()]; dup {
			return nil, ErrProviderRemotesUnavailable
		}
		out[rm.GetRemoteId()] = rm
	}
	return out, nil
}

// providerTarget freezes one remote from the executor's metadata, or
// explains why it cannot be part of a lease.
func providerTarget(id string, rm *pb.PVEAdminRemote, ok bool, methods []string) (permit.ProviderTarget, error) {
	switch {
	case !ok:
		return permit.ProviderTarget{}, &ReadGrantInputError{fmt.Sprintf("PVE remote %s is not registered", id)}
	case rm.GetState() != pveRemoteStateActive:
		return permit.ProviderTarget{}, &ReadGrantInputError{fmt.Sprintf("PVE remote %s is not active (blocked until re-pinned, or removed)", id)}
	case !pvecontract.ValidTrustPin(rm.GetTrustPin()) || rm.GetTrustGeneration() < 1:
		return permit.ProviderTarget{}, &ReadGrantInputError{fmt.Sprintf("PVE remote %s has no valid trust pin", id)}
	case rm.GetReadRef() == "" || rm.GetReadVersion() < 1:
		return permit.ProviderTarget{}, &ReadGrantInputError{fmt.Sprintf("PVE remote %s has no read credential", id)}
	}
	return permit.ProviderTarget{
		RemoteID: id, TrustPin: rm.GetTrustPin(), TrustGeneration: rm.GetTrustGeneration(),
		CredentialVersion: rm.GetReadVersion(), Methods: slices.Clone(methods),
	}, nil
}

// ProposeProviderReadGrant freezes the chosen PVE remotes and methods into
// a provider read-grant-v2 document, proposes it to the executor and
// returns the executor's complete canonical scope for approval (security
// key, or `nebula read-grant approve` in hardened mode).
//
// The document is: Grant permit.ReadGrantFormat, the server issuer, a fresh
// ID, Created now and Expiry after Days, Trigger permit.TriggerBoth,
// RateProfile permit.ProviderReadProfile, MinIntervalS
// permit.ProviderMinInterval, RunBudget providerRunBudget, and one
// provider target per remote with the trust pin, trust generation and read
// credential version exactly as the executor's registry reports them. It
// has no actions, SSH targets or credentials.
func (s *Service) ProposeProviderReadGrant(ctx context.Context, user string, in ProviderReadGrantRequest) (ReadGrantPreview, error) {
	remotes, methods, err := checkProviderReadGrantRequest(in)
	if err != nil {
		return ReadGrantPreview{}, err
	}
	exec, ok := s.exec.(readGrantProposer)
	if !ok {
		return ReadGrantPreview{}, ErrReadGrantProposeUnsupported
	}
	lister, ok := s.exec.(providerRemoteLister)
	if !ok {
		return ReadGrantPreview{}, ErrReadGrantProposeUnsupported
	}
	known, err := s.providerRemotes(ctx, lister)
	if err != nil {
		return ReadGrantPreview{}, err
	}
	now := s.now()
	doc := permit.ReadGrantDoc{
		Grant: permit.ReadGrantFormat, Issuer: readGrantIssuer,
		CreatedUnix: now.Unix(), ExpiryUnix: now.Add(time.Duration(in.Days) * 24 * time.Hour).Unix(),
		Trigger: permit.TriggerBoth, RateProfile: permit.ProviderReadProfile,
		MinIntervalS: int64(permit.ProviderMinInterval / time.Second), RunBudget: providerRunBudget(methods),
	}
	if doc.ID, err = newUUID(); err != nil {
		return ReadGrantPreview{}, err
	}
	for _, id := range remotes {
		rm, ok := known[id]
		t, err := providerTarget(id, rm, ok, methods)
		if err != nil {
			return ReadGrantPreview{}, err
		}
		doc.ProviderTargets = append(doc.ProviderTargets, t)
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		return ReadGrantPreview{}, fmt.Errorf("encode provider read grant: %w", err)
	}
	cctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	r, err := exec.ProposeReadGrant(cctx, &pb.ProposeReadGrantRequest{GrantJson: raw})
	if err != nil {
		code := status.Code(err)
		s.log.Warn("provider read grant proposal refused", "code", code.String())
		if code == codes.Unimplemented {
			return ReadGrantPreview{}, ErrReadGrantProposeUnsupported
		}
		return ReadGrantPreview{}, ErrReadGrantProposeFailed
	}
	v, err := previewFromResponse(r, doc)
	if err != nil {
		s.log.Warn("provider read grant proposal answer rejected", "error", err.Error())
		return ReadGrantPreview{}, err
	}
	v.ScopeKind = ScopeProvider
	s.log.Info("audit", "kind", "provider_read_grant_proposed", "grant", v.ID, "digest", v.Digest, "user", user,
		"remotes", len(v.Providers), "methods", len(methods))
	return v, nil
}

// sameProviderTargets reports whether the executor's provider targets are
// exactly the proposed ones: same order (the executor canonicalizes the
// document in member order without reordering arrays), same remote, trust
// pin, trust generation, credential version and method list, and no
// metrics targets.
func sameProviderTargets(a, b []permit.ProviderTarget) bool {
	return slices.EqualFunc(a, b, func(x, y permit.ProviderTarget) bool {
		return x.RemoteID == y.RemoteID && x.TrustPin == y.TrustPin && x.TrustGeneration == y.TrustGeneration &&
			x.CredentialVersion == y.CredentialVersion && slices.Equal(x.Methods, y.Methods) &&
			len(x.MetricsTargets) == 0 && len(y.MetricsTargets) == 0
	})
}

// providerPinPrefixLen is how many hex characters of a trust pin the lease
// list shows.
const providerPinPrefixLen = 16

// ReadGrantProviderView is one frozen PVE remote of a listed provider
// grant.
type ReadGrantProviderView struct {
	RemoteID string
	// PinPrefix is the first providerPinPrefixLen hex characters of the
	// trust pin.
	PinPrefix         string
	TrustGeneration   uint64
	CredentialVersion int64
	// Methods are the document's methods in document order.
	Methods []string
}

// providerView checks one provider target of an executor-held document
// (untrusted input) and returns its list view. Every rendered member must
// be well formed; anything else makes the whole grant invalid.
func providerView(p permit.ProviderTarget) (ReadGrantProviderView, bool) {
	if !pvecontract.ValidRemoteID(p.RemoteID) || !pvecontract.ValidTrustPin(p.TrustPin) ||
		p.TrustGeneration < 1 || p.CredentialVersion < 1 || len(p.Methods) == 0 {
		return ReadGrantProviderView{}, false
	}
	seen := map[string]bool{}
	for _, m := range p.Methods {
		if (!permit.ValidProviderMethod(m) && m != permit.ProviderMethodMetrics) || seen[m] {
			return ReadGrantProviderView{}, false
		}
		seen[m] = true
	}
	return ReadGrantProviderView{RemoteID: p.RemoteID, PinPrefix: p.TrustPin[:providerPinPrefixLen],
		TrustGeneration: p.TrustGeneration, CredentialVersion: p.CredentialVersion, Methods: slices.Clone(p.Methods)}, true
}

// ProviderRefresh returns the pre-filled request for a new provider lease
// over the same remotes and methods (data for the lease form), and false
// when v is not an active or expired provider read lease. The methods are
// the union over the remotes, sorted; the lifetime follows the old lease
// like a host lease refresh. The pin, generation and credential version
// are not carried over: a new proposal reads them from the executor again.
func (v ReadGrantView) ProviderRefresh() (ProviderReadGrantRequest, bool) {
	if (v.State != "active" && v.State != "expired") || v.RateProfile != permit.ProviderReadProfile || len(v.Providers) == 0 {
		return ProviderReadGrantRequest{}, false
	}
	in := ProviderReadGrantRequest{Days: ReadGrantShortDays}
	seen := map[string]bool{}
	for _, p := range v.Providers {
		in.RemoteIDs = append(in.RemoteIDs, p.RemoteID)
		for _, m := range p.Methods {
			if !seen[m] && permit.ValidProviderMethod(m) {
				seen[m] = true
				in.Methods = append(in.Methods, m)
			}
		}
	}
	sort.Strings(in.Methods)
	if !v.Created.IsZero() && v.Expiry.Sub(v.Created) > time.Duration(ReadGrantShortDays)*24*time.Hour+time.Hour {
		in.Days = ReadGrantLongDays
	}
	return in, true
}

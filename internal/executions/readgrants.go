// SPDX-License-Identifier: AGPL-3.0-or-later

package executions

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sort"
	"time"
	"unicode/utf8"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/schedgrant"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui/invsort"
)

// Read grants (ADR 0007 E06, part 1). The executor is the source of truth
// for the approved read-grant registry; the server decodes each canonical
// document into a lease-page view and labels the frozen host list against
// the inventory (all / tag / environment). The server stores nothing here.

// ReadGrantView is the lease-page view of one executor-held read grant.
type ReadGrantView struct {
	ID     string
	Digest string
	// ScopeKind is how the frozen host list was selected: "all" (every
	// host), "tag" (one tag's hosts), "environment" (one environment's
	// hosts) or "hosts" (an explicit list matching no current selection).
	ScopeKind  string
	ScopeValue string // tag "key=value" or environment name; empty otherwise
	// Hosts is the frozen, complete target list in invsort order.
	Hosts   []string
	Actions []string
	// ApprovedBy and the times come from the executor's registry.
	ApprovedBy string
	Created    time.Time
	Expiry     time.Time
	Revoked    time.Time
	// State is "active", "expired", "revoked", "legacy" (read-schedule-v1,
	// never on-demand read authority) or "invalid" (unparsable).
	State  string
	Legacy bool // read-schedule-v1 document; never active read authority
}

// Errors of read grants. The text is fixed; the executor's own messages are
// untrusted input and never reach the user (spec 07).
var (
	ErrReadGrantNotFound     = errors.New("read grant not found")
	ErrReadGrantsUnavailable = errors.New("the read grants could not be listed")
	ErrReadGrantRevokeFailed = errors.New("the read grant could not be revoked")
)

// hostScopeLister lists the whole inventory (inventory.Store satisfies it).
// It is optional: without it the scope label falls back to "hosts".
type hostScopeLister interface {
	List(ctx context.Context) ([]inventory.Host, error)
}

// readGrantExecutor is the read-grant subset of the executor API. It is a
// separate interface (not added to Executor) so that the shared Executor
// interface stays satisfiable by the server's lazyExecutor and the browser
// test harness, which predate read grants; the production client implements
// it. A service whose executor does not support read grants reports the
// fixed unavailable error instead of failing to compile.
type readGrantExecutor interface {
	ListReadGrants(ctx context.Context, in *pb.ListReadGrantsRequest, opts ...grpc.CallOption) (*pb.ListReadGrantsResponse, error)
	RevokeReadGrant(ctx context.Context, in *pb.RevokeReadGrantRequest, opts ...grpc.CallOption) (*pb.RevokeReadGrantResponse, error)
}

// ReadGrants lists the executor's approved read grants as lease-page views.
func (s *Service) ReadGrants(ctx context.Context) ([]ReadGrantView, error) {
	exec, ok := s.exec.(readGrantExecutor)
	if !ok {
		return nil, ErrReadGrantsUnavailable
	}
	cctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	r, err := exec.ListReadGrants(cctx, &pb.ListReadGrantsRequest{})
	if err != nil {
		return nil, ErrReadGrantsUnavailable
	}
	inv, ok := s.listInventory(ctx)
	out := make([]ReadGrantView, 0, len(r.GetGrants()))
	for _, g := range r.GetGrants() {
		out = append(out, decodeReadGrant(g, inv, ok, s.now()))
	}
	return out, nil
}

// RevokeReadGrant revokes a read grant on the executor (no session or
// assertion) and audits it, like RevokeSchedule.
func (s *Service) RevokeReadGrant(ctx context.Context, user, id string) error {
	if id == "" || len(id) > maxViewIDLen || !utf8.ValidString(id) {
		return ErrReadGrantNotFound
	}
	exec, ok := s.exec.(readGrantExecutor)
	if !ok {
		return ErrReadGrantRevokeFailed
	}
	cctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	_, err := exec.RevokeReadGrant(cctx, &pb.RevokeReadGrantRequest{GrantId: id})
	if err != nil {
		if status.Code(err) == codes.NotFound {
			return ErrReadGrantNotFound
		}
		return ErrReadGrantRevokeFailed
	}
	s.log.Info("audit", "kind", "read_grant_revoked", "grant", id, "user", user)
	return nil
}

// listInventory returns the current inventory for scope labelling. The second
// result is false when the inventory cannot be listed (the scope label then
// falls back to "hosts").
func (s *Service) listInventory(ctx context.Context) ([]inventory.Host, bool) {
	l, ok := s.hosts.(hostScopeLister)
	if !ok {
		return nil, false
	}
	hosts, err := l.List(ctx)
	if err != nil {
		return nil, false
	}
	return hosts, true
}

// decodeReadGrant turns one executor-held read grant into its lease-page
// view. The canonical document is untrusted input: any decode failure yields
// State "invalid" with no hosts, never a panic.
func decodeReadGrant(g *pb.ReadGrant, inv []inventory.Host, haveInv bool, now time.Time) ReadGrantView {
	v := ReadGrantView{
		ID:         g.GetGrantId(),
		Digest:     g.GetGrantDigest(),
		ApprovedBy: g.GetApprovedBy(),
		Created:    time.Unix(g.GetCreatedUnix(), 0),
		Expiry:     time.Unix(g.GetExpiryUnix(), 0),
		Hosts:      []string{},
		Actions:    []string{},
	}
	// The executor sends RevokedUnix 0 for a grant that is not revoked.
	if r := g.GetRevokedUnix(); r != 0 {
		v.Revoked = time.Unix(r, 0)
	}
	raw := g.GetCanonicalGrant()
	if len(raw) == 0 || len(raw) > permit.MaxReadGrantDocSize || !utf8.Valid(raw) {
		return invalidView(v)
	}
	var doc permit.ReadGrantDoc
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil || (doc.Grant != schedgrant.ReadFormat && doc.Grant != schedgrant.Format) ||
		len(doc.Targets) > permit.MaxReadGrantTargets || len(doc.Actions) > permit.MaxReadGrantActions {
		return invalidView(v)
	}
	for _, t := range doc.Targets {
		if t.HostID == "" || len(t.HostID) > maxViewIDLen {
			return invalidView(v)
		}
	}
	for _, a := range doc.Actions {
		if a.ActionID == "" || len(a.ActionID) > maxViewIDLen {
			return invalidView(v)
		}
	}
	v.Legacy = doc.Grant == schedgrant.Format
	seen := map[string]bool{}
	for _, t := range doc.Targets {
		if !seen[t.HostID] {
			seen[t.HostID] = true
			v.Hosts = append(v.Hosts, t.HostID)
		}
	}
	sort.Slice(v.Hosts, func(i, j int) bool { return invsort.Less(v.Hosts[i], v.Hosts[j]) })
	for _, a := range doc.Actions {
		v.Actions = append(v.Actions, a.ActionID)
	}
	v.ScopeKind, v.ScopeValue = scopeLabel(v.Hosts, inv, haveInv)
	switch {
	case !v.Revoked.IsZero():
		v.State = "revoked"
	case !now.Before(v.Expiry):
		v.State = "expired"
	case v.Legacy:
		// A legacy read-schedule-v1 grant is never on-demand read authority.
		v.State = "legacy"
	default:
		v.State = "active"
	}
	return v
}

// maxViewIDLen bounds host and action IDs taken from the untrusted document.
const maxViewIDLen = 256

// invalidView marks a grant whose document could not be decoded safely.
func invalidView(v ReadGrantView) ReadGrantView {
	v.State = "invalid"
	v.Hosts = nil
	v.Actions = nil
	return v
}

// scopeLabel labels a grant's frozen host list against the inventory: "all"
// (every host), "tag" (one tag's hosts) or "environment" (one environment's
// hosts). A list matching none is "hosts" (an explicit selection).
func scopeLabel(hosts []string, inv []inventory.Host, haveInv bool) (string, string) {
	if !haveInv || len(inv) == 0 || len(hosts) == 0 {
		return "hosts", ""
	}
	set := make(map[string]bool, len(hosts))
	for _, h := range hosts {
		set[h] = true
	}
	invSet := make(map[string]bool, len(inv))
	for _, h := range inv {
		invSet[h.ID] = true
	}
	if sameSet(set, invSet) {
		return "all", ""
	}
	if tag, ok := matchLabel(set, tagGroups(inv)); ok {
		return "tag", tag
	}
	if env, ok := matchLabel(set, envGroups(inv)); ok {
		return "environment", env
	}
	return "hosts", ""
}

// tagGroups maps each "key=value" tag to the set of hosts carrying it.
func tagGroups(inv []inventory.Host) map[string]map[string]bool {
	g := map[string]map[string]bool{}
	for _, h := range inv {
		for k, val := range h.Tags {
			key := k + "=" + val
			if g[key] == nil {
				g[key] = map[string]bool{}
			}
			g[key][h.ID] = true
		}
	}
	return g
}

// envGroups maps each environment to the set of hosts in it.
func envGroups(inv []inventory.Host) map[string]map[string]bool {
	g := map[string]map[string]bool{}
	for _, h := range inv {
		if g[string(h.Environment)] == nil {
			g[string(h.Environment)] = map[string]bool{}
		}
		g[string(h.Environment)][h.ID] = true
	}
	return g
}

// matchLabel returns the smallest label whose host set equals set, or "".
func matchLabel(set map[string]bool, groups map[string]map[string]bool) (string, bool) {
	best := ""
	for label, members := range groups {
		if sameSet(set, members) {
			if best == "" || label < best {
				best = label
			}
		}
	}
	return best, best != ""
}

// sameSet reports whether a and b hold exactly the same keys.
func sameSet(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

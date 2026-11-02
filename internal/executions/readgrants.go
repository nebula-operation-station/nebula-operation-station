// SPDX-License-Identifier: AGPL-3.0-or-later

package executions

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"sort"
	"time"
	"unicode"
	"unicode/utf8"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
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
	// hosts), "hosts" (an explicit list matching no current selection) or
	// "provider" (a provider grant scoped to the PVE remotes in Remotes).
	ScopeKind  string
	ScopeValue string // tag "key=value" or environment name; empty otherwise
	// Hosts is the frozen, complete target list in invsort order.
	Hosts   []string
	Actions []string
	// Remotes is the sorted PVE remote list of a provider grant; empty for
	// SSH grants.
	Remotes []string
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
	if !validReadGrantID(id) {
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
	if !validReadGrantID(v.ID) {
		v.ID = ""
		return invalidView(v)
	}
	if !canonical.ValidSHA256Hex(v.Digest) {
		v.Digest = ""
		return invalidView(v)
	}
	if !validApprovedBy(v.ApprovedBy) {
		v.ApprovedBy = ""
		return invalidView(v)
	}
	raw := g.GetCanonicalGrant()
	if len(raw) == 0 || len(raw) > permit.MaxReadGrantDocSize || !utf8.Valid(raw) || rejectDuplicateMembers(raw) != nil {
		return invalidView(v)
	}
	var doc permit.ReadGrantDoc
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil || dec.More() || !knownReadGrantFormat(doc.Grant) ||
		len(doc.Targets) > permit.MaxReadGrantTargets || len(doc.Actions) > permit.MaxReadGrantActions ||
		len(doc.ProviderTargets) > permit.MaxProviderTargets ||
		!structurallyValid(doc) || !matchesRegistry(doc, g) {
		return invalidView(v)
	}
	// Host, action and remote IDs are rendered, so each must be a valid
	// identifier (bounded, ASCII) and listed once; anything else marks the
	// whole document invalid rather than showing a silently repaired scope.
	seen := map[string]bool{}
	for _, t := range doc.Targets {
		if !canonical.ValidHostID(t.HostID) || seen["t:"+t.HostID] {
			return invalidView(v)
		}
		seen["t:"+t.HostID] = true
		v.Hosts = append(v.Hosts, t.HostID)
	}
	for _, a := range doc.Actions {
		key := "a:" + a.ActionID + "@" + a.ModuleVersion
		if !canonical.ValidActionID(a.ActionID) || seen[key] {
			return invalidView(v)
		}
		seen[key] = true
		v.Actions = append(v.Actions, a.ActionID)
	}
	for _, p := range doc.ProviderTargets {
		if !pvecontract.ValidRemoteID(p.RemoteID) || seen["p:"+p.RemoteID] {
			return invalidView(v)
		}
		seen["p:"+p.RemoteID] = true
		v.Remotes = append(v.Remotes, p.RemoteID)
	}
	v.Legacy = doc.Grant == schedgrant.Format
	sort.Slice(v.Hosts, func(i, j int) bool { return invsort.Less(v.Hosts[i], v.Hosts[j]) })
	sort.Strings(v.Remotes)
	if len(v.Remotes) > 0 {
		// A provider grant's scope is its PVE remotes, not SSH hosts.
		v.ScopeKind = "provider"
	} else {
		v.ScopeKind, v.ScopeValue = scopeLabel(v.Hosts, inv, haveInv)
	}
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

// readGrantIDRe is the executor's grant id form: a lowercase UUIDv4, as
// permit and schedgrant require of every read and schedule grant document
// (both keep their pattern unexported).
var readGrantIDRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

// validReadGrantID reports whether id is a lowercase UUIDv4. It bounds both
// caller-supplied ids (before they reach the executor or the audit log) and
// the ids the executor reports.
func validReadGrantID(id string) bool { return readGrantIDRe.MatchString(id) }

// maxApprovedByLen bounds the executor-reported approver
// ("webauthn:<credential hex>" or "cli:<admin>").
const maxApprovedByLen = 256

// validApprovedBy reports whether the executor-reported approver is
// non-empty, bounded, valid UTF-8 and printable (no control or format
// characters that could disguise it when rendered).
func validApprovedBy(s string) bool {
	if s == "" || len(s) > maxApprovedByLen || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

// structurallyValid rejects documents no executor could have approved: an
// SSH grant needs at least one target and one action and no provider
// remotes; a provider grant (read-grant-v2 only) needs remotes and no SSH
// targets, actions or credentials; the older formats carry no v2 bindings,
// and a read-schedule-v1 document carries none of the read-grant members.
func structurallyValid(d permit.ReadGrantDoc) bool {
	if d.RateProfile == permit.ProviderReadProfile || d.RateProfile == permit.ProviderTelemetryProfile {
		return d.Grant == schedgrant.ReadFormat && len(d.ProviderTargets) > 0 &&
			len(d.Targets) == 0 && len(d.Actions) == 0 && len(d.Credentials) == 0
	}
	if len(d.ProviderTargets) != 0 || len(d.Targets) == 0 || len(d.Actions) == 0 {
		return false
	}
	switch d.Grant {
	case schedgrant.ReadFormat:
		return d.RateProfile == schedgrant.OrdinaryReadProfile || d.RateProfile == schedgrant.TelemetryReadProfile
	case previousReadGrantFormat:
		return d.RateProfile == "" && len(d.Credentials) == 0
	default: // schedgrant.Format
		return d.RateProfile == "" && len(d.Credentials) == 0 && d.Issuer == "" &&
			d.CreatedUnix == 0 && d.Trigger == "" && d.RunBudget == 0
	}
}

// matchesRegistry checks the document against the registry entry carrying
// it: the same id and expiry, and (except for read-schedule-v1, which has no
// created_unix) a document created no later than the registry's creation
// time, which is when the executor approved and stored the grant.
func matchesRegistry(d permit.ReadGrantDoc, g *pb.ReadGrant) bool {
	if d.ID != g.GetGrantId() || d.ExpiryUnix != g.GetExpiryUnix() {
		return false
	}
	if d.Grant == schedgrant.Format {
		return true
	}
	return d.CreatedUnix > 0 && d.CreatedUnix <= g.GetCreatedUnix() && d.CreatedUnix < d.ExpiryUnix
}

// previousReadGrantFormat is the stored read-grant-v1 format the executor
// still holds (permit keeps the constant unexported).
const previousReadGrantFormat = "read-grant-v1"

// knownReadGrantFormat reports whether format is one the executor's registry
// can hold: read-grant-v2, the stored read-grant-v1, or a legacy
// read-schedule-v1 document.
func knownReadGrantFormat(format string) bool {
	return format == schedgrant.ReadFormat || format == previousReadGrantFormat || format == schedgrant.Format
}

// memberNameRe is the form of every member name in a read-grant document.
var memberNameRe = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

// errJSONTooDeep reports a document nested beyond maxViewJSONDepth.
var errJSONTooDeep = errors.New("the document is nested too deep")

// maxViewJSONDepth bounds nesting while scanning the untrusted document.
const maxViewJSONDepth = 16

// rejectDuplicateMembers rejects a document that is not exactly one JSON
// object or that repeats a member name in any object, so one document cannot
// show one scope and carry another. It mirrors permit's unexported check and
// additionally requires every member name to be lowercase ASCII: the
// document's members all are, and encoding/json matches names
// case-insensitively (including Unicode folds such as U+212A for "k"), so
// "GRANT" next to "grant" would otherwise silently override it.
func rejectDuplicateMembers(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return errors.New("the top level must be an object")
	}
	if err := walkJSONValue(dec, tok, 1); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("trailing data after the document")
	}
	return nil
}

// walkJSONValue consumes the rest of a value whose first token is first.
func walkJSONValue(dec *json.Decoder, first json.Token, depth int) error {
	d, ok := first.(json.Delim)
	if !ok {
		return nil
	}
	if depth > maxViewJSONDepth {
		return errJSONTooDeep
	}
	seen := map[string]bool{}
	for {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		if e, ok := tok.(json.Delim); ok && (e == '}' || e == ']') {
			return nil
		}
		if d == '{' {
			name, ok := tok.(string)
			if !ok || !memberNameRe.MatchString(name) || seen[name] {
				return errors.New("malformed object or duplicate member")
			}
			seen[name] = true
			if tok, err = dec.Token(); err != nil {
				return err
			}
		}
		if err := walkJSONValue(dec, tok, depth+1); err != nil {
			return err
		}
	}
}

// invalidView marks a grant whose document could not be decoded safely.
func invalidView(v ReadGrantView) ReadGrantView {
	v.State = "invalid"
	v.Hosts = nil
	v.Actions = nil
	v.Remotes = nil
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

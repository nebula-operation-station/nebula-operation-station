// SPDX-License-Identifier: AGPL-3.0-or-later

package executions

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/actions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/schedgrant"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui/invsort"
)

// Read-grant proposals (ADR 0007 E06, part 3). The server resolves an
// "all", tag or environment selection against the inventory and the
// executor's pins into a frozen read-grant-v2 document, the executor
// validates and canonicalizes it, and the lease page shows the complete
// canonical document the executor returned (every host with its keys,
// every action, the expiry and the digest) before anything is approved.
// New enrollment or a changed tag never joins a proposed grant: the host
// list is frozen when the proposal is made.

// Limits and fixed values of read-grant proposals.
const (
	// ReadGrantShortDays and ReadGrantLongDays are the two lifetimes the
	// page offers: the ADR's default (7 days) and maximum (30 days).
	ReadGrantShortDays = 7
	ReadGrantLongDays  = 30
	// readGrantIssuer names the server as the proposing issuer.
	readGrantIssuer = "nebula-server"
	// maxScopeValueLen bounds a tag "key=value" or environment name.
	maxScopeValueLen = 200
	// maxReadGrantAssertionSize bounds the relayed assertion (the
	// executor's own limit is 16 KiB).
	maxReadGrantAssertionSize = 16 << 10
	// maxRequestOptionsSize bounds the WebAuthn options rendered into the
	// page.
	maxRequestOptionsSize = 16 << 10
)

// Scope kinds a proposal can select.
const (
	ScopeAll         = "all"
	ScopeTag         = "tag"
	ScopeEnvironment = "environment"
	// ScopeProvider is the scope of a provider lease: the PVE remotes in
	// ReadGrantPreview.Providers (ProposeProviderReadGrant).
	ScopeProvider = "provider"
)

// Errors of read-grant proposals. The text is fixed; the executor's own
// messages are untrusted input and never reach the user.
var (
	ErrReadGrantProposeFailed      = errors.New("the executor did not accept the read grant proposal")
	ErrReadGrantCredentials        = errors.New("the executor's SSH credential versions could not be read")
	ErrReadGrantProposalMismatch   = errors.New("the executor returned a read grant that differs from the proposal")
	ErrReadGrantProposalNotFound   = errors.New("the read grant proposal is unknown or expired")
	ErrReadGrantApprovalRefused    = errors.New("the security key approval was not accepted")
	ErrReadGrantCommitFailed       = errors.New("the read grant could not be approved")
	ErrReadGrantProposeUnsupported = errors.New("the executor does not support read grant proposals")
)

// ReadGrantInputError is an unusable proposal request (it describes the
// input, never the executor's answer).
type ReadGrantInputError struct{ Reason string }

func (e *ReadGrantInputError) Error() string { return e.Reason }

// ReadGrantRequest is what the lease form submits.
type ReadGrantRequest struct {
	ScopeKind  string // ScopeAll, ScopeTag or ScopeEnvironment
	ScopeValue string // tag "key=value" or environment name
	Actions    []string
	Days       int // ReadGrantShortDays or ReadGrantLongDays
}

// ReadGrantPreviewTarget is one frozen target of a proposal.
type ReadGrantPreviewTarget struct {
	HostID             string
	HostKeyFingerprint string
	CredentialRef      string
	CredentialVersion  string
}

// ReadGrantPreviewAction is one action of a proposal.
type ReadGrantPreviewAction struct {
	ActionID       string
	ModuleVersion  string
	ArtifactSHA256 string
	ParametersHash string
}

// ReadGrantExcluded is an inventory host of the selection that the frozen
// grant does not contain, with the reason.
type ReadGrantExcluded struct {
	HostID string
	Reason string
}

// ReadGrantPreview is the complete canonical scope the executor returned
// for a proposal, decoded strictly. It is what the user approves.
type ReadGrantPreview struct {
	ID, Digest            string
	ScopeKind, ScopeValue string
	Targets               []ReadGrantPreviewTarget // invsort order
	Actions               []ReadGrantPreviewAction
	// Providers are the frozen PVE remotes of a provider lease in document
	// order; empty for SSH leases (which have Targets and Actions).
	Providers            []ReadGrantPreviewProvider
	Excluded             []ReadGrantExcluded
	Issuer               string
	Created, Expiry      time.Time
	Trigger, RateProfile string
	MinInterval          time.Duration
	RunBudget            int64
	// CLI is set when the executor requires local CLI approval (hardened
	// mode); Options are then empty.
	CLI bool
	// Options are the WebAuthn request options for the browser approval.
	Options         []byte
	ChallengeExpiry time.Time
}

// readGrantProposer is the proposal subset of the executor API, separate
// from Executor for the reason given at readGrantExecutor.
type readGrantProposer interface {
	ProposeReadGrant(ctx context.Context, in *pb.ProposeReadGrantRequest, opts ...grpc.CallOption) (*pb.ProposeReadGrantResponse, error)
	CommitReadGrant(ctx context.Context, in *pb.CommitReadGrantRequest, opts ...grpc.CallOption) (*pb.CommitReadGrantResponse, error)
}

// credentialVersioner reads the executor's SSH public key of a credential
// reference; its fingerprint is the credential version a read-grant-v2
// document binds.
type credentialVersioner interface {
	GetSSHPublicKey(ctx context.Context, in *pb.GetSSHPublicKeyRequest, opts ...grpc.CallOption) (*pb.GetSSHPublicKeyResponse, error)
}

// ReadGrantActionIDs returns the actions a read lease can cover, sorted:
// the built-in actions of the approved ordinary read-only contract that
// are read-only and take no parameters (their parameters hash is that of
// "{}"; parameterized reads need their exact parameters bound, which the
// page does not offer).
func ReadGrantActionIDs() []string {
	var out []string
	for _, id := range permit.ReadOnlyAllowlist {
		if leaseableAction(id) {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}

// leaseableAction reports whether actionID can be part of a proposed lease.
func leaseableAction(id string) bool {
	if !permit.InReadOnlyAllowlist(id) || schedgrant.IsTelemetryAction(id) {
		return false
	}
	a, ok := actions.Lookup(id)
	return ok && a.ReadOnly && !a.Durable && len(a.Params) == 0
}

// credentialRefRe is permit's credential reference form (unexported there).
var credentialRefRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

// validScopeValue reports whether a tag or environment value is bounded,
// valid UTF-8 and printable.
func validScopeValue(s string) bool {
	if s == "" || len(s) > maxScopeValueLen || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

// checkReadGrantRequest validates the form input.
func checkReadGrantRequest(in ReadGrantRequest) error {
	switch in.ScopeKind {
	case ScopeAll:
		if in.ScopeValue != "" {
			return &ReadGrantInputError{"the scope \"all\" takes no value"}
		}
	case ScopeTag:
		k, v, ok := strings.Cut(in.ScopeValue, "=")
		if !validScopeValue(in.ScopeValue) || !ok || k == "" || v == "" {
			return &ReadGrantInputError{"a tag scope needs a value of the form key=value"}
		}
	case ScopeEnvironment:
		if !validScopeValue(in.ScopeValue) {
			return &ReadGrantInputError{"an environment scope needs an environment name"}
		}
	default:
		return &ReadGrantInputError{"the scope must be all, tag or environment"}
	}
	if in.Days != ReadGrantShortDays && in.Days != ReadGrantLongDays {
		return &ReadGrantInputError{fmt.Sprintf("a read lease lasts %d or %d days", ReadGrantShortDays, ReadGrantLongDays)}
	}
	if len(in.Actions) == 0 || len(in.Actions) > permit.MaxReadGrantActions {
		return &ReadGrantInputError{fmt.Sprintf("choose 1 to %d actions", permit.MaxReadGrantActions)}
	}
	seen := map[string]bool{}
	for _, a := range in.Actions {
		if seen[a] || !leaseableAction(a) {
			return &ReadGrantInputError{"an action is unknown, listed twice or not a read-only action"}
		}
		seen[a] = true
	}
	return nil
}

// selectHosts returns the inventory hosts the scope selects, in invsort
// order.
func selectHosts(inv []inventory.Host, kind, value string) []string {
	var out []string
	key, val, _ := strings.Cut(value, "=")
	for _, h := range inv {
		switch kind {
		case ScopeAll:
		case ScopeTag:
			if v, ok := h.Tags[key]; !ok || v != val {
				continue
			}
		case ScopeEnvironment:
			if string(h.Environment) != value {
				continue
			}
		}
		out = append(out, h.ID)
	}
	sort.Slice(out, func(i, j int) bool { return invsort.Less(out[i], out[j]) })
	return out
}

// ProposeReadGrant resolves the request into a frozen read-grant-v2
// document, proposes it to the executor and returns the executor's
// complete canonical scope for approval.
func (s *Service) ProposeReadGrant(ctx context.Context, user string, in ReadGrantRequest) (ReadGrantPreview, error) {
	if err := checkReadGrantRequest(in); err != nil {
		return ReadGrantPreview{}, err
	}
	exec, ok := s.exec.(readGrantProposer)
	if !ok {
		return ReadGrantPreview{}, ErrReadGrantProposeUnsupported
	}
	inv, ok := s.listInventory(ctx)
	if !ok {
		return ReadGrantPreview{}, &ReadGrantInputError{"the inventory could not be listed"}
	}
	selected := selectHosts(inv, in.ScopeKind, in.ScopeValue)
	if len(selected) == 0 {
		return ReadGrantPreview{}, &ReadGrantInputError{"no host in the inventory matches this scope"}
	}
	cctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	pins, err := s.exec.ListHostKeys(cctx, &pb.ListHostKeysRequest{})
	if err != nil {
		return ReadGrantPreview{}, ErrReadGrantProposeFailed
	}
	pinOf := map[string]*pb.HostKeyPin{}
	for _, p := range pins.GetHosts() {
		pinOf[p.GetHostId()] = p
	}
	now := s.now()
	doc := permit.ReadGrantDoc{
		Grant: permit.ReadGrantFormat, Issuer: readGrantIssuer,
		CreatedUnix: now.Unix(), ExpiryUnix: now.Add(time.Duration(in.Days) * 24 * time.Hour).Unix(),
		Trigger: permit.TriggerBoth, RateProfile: schedgrant.OrdinaryReadProfile,
		MinIntervalS: int64(schedgrant.MinInterval / time.Second), RunBudget: permit.DefaultRunBudget,
	}
	if doc.ID, err = newUUID(); err != nil {
		return ReadGrantPreview{}, err
	}
	empty, err := canonical.HashParameters([]byte(`{}`))
	if err != nil {
		return ReadGrantPreview{}, err
	}
	for _, id := range in.Actions {
		a, _ := actions.Lookup(id) // checked by checkReadGrantRequest
		doc.Actions = append(doc.Actions, permit.ReadGrantAction{ActionID: a.ID, ModuleVersion: a.Version, ArtifactSHA256: a.SHA256(), ParametersHash: empty})
	}
	var excluded []ReadGrantExcluded
	versions := map[string]string{}
	for _, h := range selected {
		p, ok := pinOf[h]
		switch {
		case !ok:
			excluded = append(excluded, ReadGrantExcluded{HostID: h, Reason: "not enrolled"})
			continue
		case p.GetBlocked():
			excluded = append(excluded, ReadGrantExcluded{HostID: h, Reason: "blocked after a host key mismatch"})
			continue
		case !canonical.ValidHostID(h) || !canonical.ValidHostKeyFingerprint(p.GetFingerprint()):
			excluded = append(excluded, ReadGrantExcluded{HostID: h, Reason: "no valid host key pin"})
			continue
		case !credentialRefRe.MatchString(p.GetCredentialRef()):
			excluded = append(excluded, ReadGrantExcluded{HostID: h, Reason: "no valid credential reference"})
			continue
		}
		ref := p.GetCredentialRef()
		if _, ok := versions[ref]; !ok {
			v, err := s.credentialVersion(ctx, ref)
			if err != nil {
				return ReadGrantPreview{}, err
			}
			versions[ref] = v
		}
		doc.Targets = append(doc.Targets, canonical.Target{HostID: h, HostKeyFingerprint: p.GetFingerprint()})
		doc.Credentials = append(doc.Credentials, permit.ReadGrantCredential{HostID: h, CredentialRef: ref, CredentialVersion: versions[ref]})
	}
	if len(doc.Targets) == 0 {
		return ReadGrantPreview{}, &ReadGrantInputError{"no enrolled, unblocked host matches this scope"}
	}
	if len(doc.Targets) > permit.MaxReadGrantTargets {
		return ReadGrantPreview{}, &ReadGrantInputError{fmt.Sprintf("a read lease covers at most %d hosts", permit.MaxReadGrantTargets)}
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		return ReadGrantPreview{}, fmt.Errorf("encode read grant: %w", err)
	}
	r, err := exec.ProposeReadGrant(cctx, &pb.ProposeReadGrantRequest{GrantJson: raw})
	if err != nil {
		s.log.Warn("read grant proposal refused", "code", status.Code(err).String())
		return ReadGrantPreview{}, ErrReadGrantProposeFailed
	}
	v, err := previewFromResponse(r, doc)
	if err != nil {
		s.log.Warn("read grant proposal answer rejected", "error", err.Error())
		return ReadGrantPreview{}, err
	}
	v.ScopeKind, v.ScopeValue, v.Excluded = in.ScopeKind, in.ScopeValue, excluded
	s.log.Info("audit", "kind", "read_grant_proposed", "grant", v.ID, "digest", v.Digest, "user", user,
		"hosts", len(v.Targets), "actions", len(v.Actions))
	return v, nil
}

// credentialVersion reads the SHA-256 fingerprint of the executor's SSH
// key for ref.
func (s *Service) credentialVersion(ctx context.Context, ref string) (string, error) {
	cv, ok := s.exec.(credentialVersioner)
	if !ok {
		return "", ErrReadGrantCredentials
	}
	cctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	r, err := cv.GetSSHPublicKey(cctx, &pb.GetSSHPublicKeyRequest{CredentialRef: ref})
	if err != nil {
		s.log.Warn("read grant credential version", "credential", ref, "code", status.Code(err).String())
		return "", ErrReadGrantCredentials
	}
	if !canonical.ValidHostKeyFingerprint(r.GetFingerprint()) {
		return "", ErrReadGrantCredentials
	}
	return r.GetFingerprint(), nil
}

// previewFromResponse decodes the executor's canonical document strictly,
// checks that it is exactly the proposed scope and builds the preview from
// it. Anything else is rejected rather than shown.
func previewFromResponse(r *pb.ProposeReadGrantResponse, sent permit.ReadGrantDoc) (ReadGrantPreview, error) {
	digest := r.GetGrantDigest()
	raw := r.GetCanonicalGrant()
	if !canonical.ValidSHA256Hex(digest) || len(raw) == 0 || len(raw) > permit.MaxReadGrantDocSize ||
		!utf8.Valid(raw) || rejectDuplicateMembers(raw) != nil {
		return ReadGrantPreview{}, ErrReadGrantProposalMismatch
	}
	var got permit.ReadGrantDoc
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&got); err != nil || dec.More() || !sameReadGrant(got, sent) {
		return ReadGrantPreview{}, ErrReadGrantProposalMismatch
	}
	v := ReadGrantPreview{
		ID: got.ID, Digest: digest, Issuer: got.Issuer,
		Created: time.Unix(got.CreatedUnix, 0).UTC(), Expiry: time.Unix(got.ExpiryUnix, 0).UTC(),
		Trigger: got.Trigger, RateProfile: got.RateProfile,
		MinInterval: time.Duration(got.MinIntervalS) * time.Second, RunBudget: got.RunBudget,
	}
	cred := map[string]permit.ReadGrantCredential{}
	for _, c := range got.Credentials {
		cred[c.HostID] = c
	}
	for _, t := range got.Targets {
		c := cred[t.HostID]
		v.Targets = append(v.Targets, ReadGrantPreviewTarget{HostID: t.HostID, HostKeyFingerprint: t.HostKeyFingerprint,
			CredentialRef: c.CredentialRef, CredentialVersion: c.CredentialVersion})
	}
	sort.Slice(v.Targets, func(i, j int) bool { return invsort.Less(v.Targets[i].HostID, v.Targets[j].HostID) })
	for _, a := range got.Actions {
		v.Actions = append(v.Actions, ReadGrantPreviewAction(a))
	}
	for _, p := range got.ProviderTargets {
		v.Providers = append(v.Providers, ReadGrantPreviewProvider{RemoteID: p.RemoteID, TrustPin: p.TrustPin,
			TrustGeneration: p.TrustGeneration, CredentialVersion: p.CredentialVersion, Methods: slices.Clone(p.Methods),
			MetricsTargets: slices.Clone(p.MetricsTargets)})
	}
	switch r.GetApprovalRequirement() {
	case pb.ApprovalRequirement_APPROVAL_REQUIREMENT_CLI_ONLY:
		v.CLI = true
	case pb.ApprovalRequirement_APPROVAL_REQUIREMENT_ASSERTION_PRESENCE,
		pb.ApprovalRequirement_APPROVAL_REQUIREMENT_ASSERTION_VERIFIED,
		pb.ApprovalRequirement_APPROVAL_REQUIREMENT_ASSERTION_VERIFIED_TYPED_COUNT:
		o := r.GetRequestOptionsJson()
		if len(o) == 0 || len(o) > maxRequestOptionsSize || !utf8.Valid(o) || !json.Valid(o) {
			return ReadGrantPreview{}, ErrReadGrantProposalMismatch
		}
		v.Options = o
		v.ChallengeExpiry = time.Unix(r.GetChallengeExpiryUnix(), 0).UTC()
	default:
		// A read grant is never approved without the user.
		return ReadGrantPreview{}, ErrReadGrantProposalMismatch
	}
	return v, nil
}

// sameReadGrant reports whether the executor's document is exactly the
// proposed one: every scalar member equal, the same targets, actions and
// credential bindings (as sets: canonicalization may reorder them), and
// exactly the same provider targets (sameProviderTargets; both empty for an
// SSH lease).
func sameReadGrant(a, b permit.ReadGrantDoc) bool {
	if a.Grant != b.Grant || a.ID != b.ID || a.Issuer != b.Issuer || a.CreatedUnix != b.CreatedUnix ||
		a.ExpiryUnix != b.ExpiryUnix || a.Trigger != b.Trigger || a.MinIntervalS != b.MinIntervalS ||
		a.RunBudget != b.RunBudget || a.RateProfile != b.RateProfile ||
		!sameProviderTargets(a.ProviderTargets, b.ProviderTargets) {
		return false
	}
	return sameSetOf(a.Targets, b.Targets) && sameSetOf(a.Actions, b.Actions) && sameSetOf(a.Credentials, b.Credentials)
}

// sameSetOf reports whether a and b hold the same distinct elements.
func sameSetOf[T comparable](a, b []T) bool {
	if len(a) != len(b) {
		return false
	}
	set := make(map[T]bool, len(a))
	for _, x := range a {
		if set[x] {
			return false
		}
		set[x] = true
	}
	for _, x := range b {
		if !set[x] {
			return false
		}
		delete(set, x)
	}
	return len(set) == 0
}

// CommitReadGrant relays the browser's assertion for a proposed read grant
// to the executor, which verifies it against the digest's challenge.
func (s *Service) CommitReadGrant(ctx context.Context, user, digest string, assertion []byte) error {
	if !canonical.ValidSHA256Hex(digest) {
		return ErrReadGrantProposalNotFound
	}
	if len(assertion) == 0 || len(assertion) > maxReadGrantAssertionSize || !utf8.Valid(assertion) || !json.Valid(assertion) {
		return &ReadGrantInputError{"the security key answer is malformed"}
	}
	exec, ok := s.exec.(readGrantProposer)
	if !ok {
		return ErrReadGrantProposeUnsupported
	}
	cctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	if _, err := exec.CommitReadGrant(cctx, &pb.CommitReadGrantRequest{GrantDigest: digest, AssertionJson: assertion}); err != nil {
		code := status.Code(err)
		s.log.Warn("read grant approval refused", "digest", digest, "code", code.String())
		switch code {
		case codes.NotFound:
			return ErrReadGrantProposalNotFound
		case codes.InvalidArgument, codes.PermissionDenied, codes.Unauthenticated, codes.FailedPrecondition:
			return ErrReadGrantApprovalRefused
		default:
			return ErrReadGrantCommitFailed
		}
	}
	s.log.Info("audit", "kind", "read_grant_approved", "digest", digest, "user", user)
	return nil
}

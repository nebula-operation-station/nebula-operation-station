// SPDX-License-Identifier: AGPL-3.0-or-later

package registrymeta

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"time"
	"unicode/utf8"

	"google.golang.org/grpc"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/schedgrant"
)

// Registry read leases, server side (ADR 0006, cu06 part 1, G13). The
// server freezes the executor's current record digest and version and
// credential identity and version of each chosen private registry, as
// ListPrivateRegistries reports them, into a read-grant-v2 document of rate
// profile schedgrant.RegistryReadProfile. The document binds repositories
// and typed methods only, never a credential value. It goes through the
// executor's ordinary read-grant proposal and user approval (WebAuthn or
// local CLI); the executor enforces it on every ReadPrivateRegistry call.

// Sentinel errors of registry read lease proposals.
var (
	// ErrLeaseRequest: the lease request is unusable (described in the
	// wrapped text, which never contains executor output).
	ErrLeaseRequest = errors.New("registrymeta: invalid registry read lease request")
	// ErrLeaseUnknownRegistry: a chosen registry is not (or no longer) an
	// executor private registry with a valid identity.
	ErrLeaseUnknownRegistry = errors.New("registrymeta: the private registry is unknown to the executor")
	// ErrLeaseProposeFailed: the executor did not accept the proposal.
	ErrLeaseProposeFailed = errors.New("registrymeta: the executor did not accept the registry read lease")
	// ErrLeaseProposalMismatch: the executor's canonical document is not
	// exactly the proposed one, or its approval answer is unusable.
	ErrLeaseProposalMismatch = errors.New("registrymeta: the executor returned a registry read lease that differs from the proposal")
)

// Fixed values of registry read lease proposals.
const (
	// LeaseIssuer names the server as the proposing issuer.
	LeaseIssuer = "nebula-server"
	// MaxLeaseDays bounds a registry read lease's lifetime in days
	// (schedgrant.RegistryReadMaxLifetime).
	MaxLeaseDays = int(schedgrant.RegistryReadMaxLifetime / (24 * time.Hour))
	// maxRequestOptionsSize bounds the WebAuthn request options relayed
	// to the browser.
	maxRequestOptionsSize = 16 << 10
)

// LeaseSelection is one registry of a lease request.
type LeaseSelection struct {
	RegistryID string
	// Repositories are exact repositories of the record's approved scope;
	// empty selects the whole scope as the executor reports it.
	Repositories []string
	// Methods are typed reads; empty selects tag_digest only.
	Methods []string
}

// LeaseRequest is a registry read lease request.
type LeaseRequest struct {
	// ID is the grant id, a lowercase UUIDv4 the caller generates.
	ID         string
	Registries []LeaseSelection
	// Days is the lifetime, 1 to MaxLeaseDays.
	Days int
	// RunBudget is the per-registry rolling-hour budget; 0 selects
	// schedgrant.RegistryDefaultRunBudget.
	RunBudget int64
}

func leaseErr(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrLeaseRequest, fmt.Sprintf(format, a...))
}

// BuildRegistryReadLease returns the read-grant-v2 document for req over
// the executor's current registries (ListPrivateIdentities), valid under
// permit's own rules at now. A repository outside a record's approved scope
// is ErrOutOfScope; a registry the executor does not list is
// ErrLeaseUnknownRegistry.
func BuildRegistryReadLease(regs []PrivateIdentity, req LeaseRequest, now time.Time) (permit.ReadGrantDoc, []byte, error) {
	if req.Days < 1 || req.Days > MaxLeaseDays {
		return permit.ReadGrantDoc{}, nil, leaseErr("a registry read lease lasts 1 to %d days", MaxLeaseDays)
	}
	if len(req.Registries) == 0 || len(req.Registries) > permit.MaxRegistryTargets {
		return permit.ReadGrantDoc{}, nil, leaseErr("choose 1 to %d private registries", permit.MaxRegistryTargets)
	}
	budget := req.RunBudget
	if budget == 0 {
		budget = schedgrant.RegistryDefaultRunBudget
	}
	if budget < 1 || budget > schedgrant.RegistryMaxRunBudget {
		return permit.ReadGrantDoc{}, nil, leaseErr("the budget is 1 to %d reads per registry and hour", schedgrant.RegistryMaxRunBudget)
	}
	doc := permit.ReadGrantDoc{
		Grant: permit.ReadGrantFormat, ID: req.ID, Issuer: LeaseIssuer,
		CreatedUnix: now.Unix(), ExpiryUnix: now.Add(time.Duration(req.Days) * 24 * time.Hour).Unix(),
		Trigger: permit.TriggerOnDemand, Actions: []permit.ReadGrantAction{},
		MinIntervalS: int64(schedgrant.RegistryMinInterval / time.Second), RunBudget: budget,
		RateProfile: schedgrant.RegistryReadProfile,
	}
	sel := slices.Clone(req.Registries)
	sort.Slice(sel, func(i, j int) bool { return sel[i].RegistryID < sel[j].RegistryID })
	for i, s := range sel {
		if i > 0 && sel[i-1].RegistryID == s.RegistryID {
			return permit.ReadGrantDoc{}, nil, leaseErr("a private registry is listed twice")
		}
		k := slices.IndexFunc(regs, func(r PrivateIdentity) bool { return r.ID == s.RegistryID })
		if !schedgrant.ValidRegistryID(s.RegistryID) || k < 0 {
			return permit.ReadGrantDoc{}, nil, ErrLeaseUnknownRegistry
		}
		r := regs[k]
		repos := s.Repositories
		if len(repos) == 0 {
			repos = r.Repositories
		}
		for _, repo := range repos {
			if !slices.Contains(r.Repositories, repo) {
				return permit.ReadGrantDoc{}, nil, ErrOutOfScope
			}
		}
		methods := s.Methods
		if len(methods) == 0 {
			methods = []string{schedgrant.RegistryReadTagDigest}
		}
		repos, methods = slices.Clone(repos), slices.Clone(methods)
		sort.Strings(repos)
		sort.Strings(methods)
		doc.RegistryTargets = append(doc.RegistryTargets, permit.RegistryTarget{
			RegistryID: r.ID, ConfigDigest: r.ConfigDigest, ConfigVersion: r.ConfigVersion,
			CredentialID: r.CredentialID, CredentialVersion: r.CredentialVersion,
			Repositories: repos, Methods: methods,
		})
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		return permit.ReadGrantDoc{}, nil, fmt.Errorf("encode registry read lease: %w", err)
	}
	// permit's own validation (methods, repositories, duplicates, limits,
	// identity shapes) decides; the server never proposes what the
	// executor's parser would refuse.
	if _, _, _, err := permit.ParseReadGrant(raw, now); err != nil {
		return permit.ReadGrantDoc{}, nil, leaseErr("the registry read lease does not validate: %v", err)
	}
	return doc, raw, nil
}

// LeaseProposer is the read-grant proposal subset of the executor API.
type LeaseProposer interface {
	ProposeReadGrant(ctx context.Context, in *pb.ProposeReadGrantRequest, opts ...grpc.CallOption) (*pb.ProposeReadGrantResponse, error)
}

// LeaseProposal is the executor's answer to a registry read lease
// proposal, checked against what was sent. The user approves Digest with
// Options (WebAuthn), or with the local CLI when CLI is set; the approval
// itself goes through the executor's CommitReadGrant by digest like every
// other read grant.
type LeaseProposal struct {
	Digest string
	Doc    permit.ReadGrantDoc
	// CLI is set when the executor requires local CLI approval.
	CLI             bool
	Options         []byte
	ChallengeExpiry time.Time
}

// ProposeRegistryReadLease lists the executor's registries, builds the
// lease document for req and proposes it. The executor's canonical answer
// must be exactly the built document.
func ProposeRegistryReadLease(ctx context.Context, exec interface {
	ExecutorRegistry
	LeaseProposer
}, req LeaseRequest, now time.Time) (LeaseProposal, error) {
	regs, err := ListPrivateIdentities(ctx, exec)
	if err != nil {
		return LeaseProposal{}, err
	}
	doc, raw, err := BuildRegistryReadLease(regs, req, now)
	if err != nil {
		return LeaseProposal{}, err
	}
	resp, err := exec.ProposeReadGrant(ctx, &pb.ProposeReadGrantRequest{GrantJson: raw})
	if err != nil {
		return LeaseProposal{}, ErrLeaseProposeFailed
	}
	return proposalFromResponse(resp, doc)
}

// proposalFromResponse checks the executor's answer: a valid digest, a
// canonical document that decodes strictly to exactly doc, and a user
// approval requirement.
func proposalFromResponse(r *pb.ProposeReadGrantResponse, doc permit.ReadGrantDoc) (LeaseProposal, error) {
	got := r.GetCanonicalGrant()
	if !canonical.ValidSHA256Hex(r.GetGrantDigest()) || len(got) == 0 || len(got) > permit.MaxReadGrantDocSize || !utf8.Valid(got) {
		return LeaseProposal{}, ErrLeaseProposalMismatch
	}
	var back permit.ReadGrantDoc
	dec := json.NewDecoder(bytes.NewReader(got))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&back); err != nil || dec.More() {
		return LeaseProposal{}, ErrLeaseProposalMismatch
	}
	a, errA := json.Marshal(back)
	b, errB := json.Marshal(doc)
	if errA != nil || errB != nil || !bytes.Equal(a, b) {
		return LeaseProposal{}, ErrLeaseProposalMismatch
	}
	p := LeaseProposal{Digest: r.GetGrantDigest(), Doc: back}
	switch r.GetApprovalRequirement() {
	case pb.ApprovalRequirement_APPROVAL_REQUIREMENT_CLI_ONLY:
		p.CLI = true
	case pb.ApprovalRequirement_APPROVAL_REQUIREMENT_ASSERTION_PRESENCE,
		pb.ApprovalRequirement_APPROVAL_REQUIREMENT_ASSERTION_VERIFIED,
		pb.ApprovalRequirement_APPROVAL_REQUIREMENT_ASSERTION_VERIFIED_TYPED_COUNT:
		o := r.GetRequestOptionsJson()
		if len(o) == 0 || len(o) > maxRequestOptionsSize || !utf8.Valid(o) || !json.Valid(o) {
			return LeaseProposal{}, ErrLeaseProposalMismatch
		}
		p.Options = o
		p.ChallengeExpiry = time.Unix(r.GetChallengeExpiryUnix(), 0).UTC()
	default:
		// A read lease is never approved without the user.
		return LeaseProposal{}, ErrLeaseProposalMismatch
	}
	return p, nil
}

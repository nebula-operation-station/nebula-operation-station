// SPDX-License-Identifier: AGPL-3.0-or-later

package permit

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
)

// ProviderMutationBinding names version 2 of the exact-target binding of a
// PVE mutation permit (ADR 0006 "Phase 2 actions, permits and
// reconciliation", ADR 0008 PV-01). The executor builds the binding from its
// own registry and live reads; nothing in it is taken from the caller.
// Version 2 (previously pve-mutation-v1) carries a versioned provider target
// (PveTargetVersion) that includes the guest generation.
const ProviderMutationBinding = "pve-mutation-v2"

// PveTargetVersion is the version of the ProviderMutationTarget layout. A
// target of any other version is malformed, and a permit approved for one
// target version never authorizes a mutation built with another.
const PveTargetVersion = "pve-target-v1"

// ProviderMutationActionPrefix is the namespace of typed PVE mutation
// actions. Only actions in it may carry a provider mutation binding.
const ProviderMutationActionPrefix = "pve."

// Provider mutation target kinds.
const (
	ProviderKindQemu = "qemu"
	ProviderKindLXC  = "lxc"
	ProviderKindNode = "node"
)

// maxProviderMutationParams bounds the action-specific parameters inside a
// binding; the whole document is bounded by canonical.MaxParametersSize.
const maxProviderMutationParams = 32 << 10

var (
	// ErrProviderMutationTarget is returned for a malformed provider
	// mutation target or action.
	ErrProviderMutationTarget = errors.New("permit: malformed provider mutation target")
	credRefRe                 = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
	hex64Re                   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	// pveGenerationRe is the PVE configuration digest (SHA-1, lowercase
	// hex) that a guest's config read returns.
	pveGenerationRe = regexp.MustCompile(`^[0-9a-f]{40}$`)
	pveNodeRe       = regexp.MustCompile(`^` + PveNodePattern + `$`)
)

// PveNodePattern is the one node-name grammar of PVE mutations: a single
// lowercase DNS label of 1..63 characters. PVE node names are host names
// without a domain, and the pveapi writer that dispatches mutations takes
// only lowercase node names. The permit target, the durable job record
// (executordb) and the node field of a stored UPID all use this pattern.
// So a target that passes authorization can always be recorded,
// dispatched and matched to its tasks.
const PveNodePattern = `[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?`

// ValidPveNodeName reports whether s matches PveNodePattern.
func ValidPveNodeName(s string) bool { return len(s) <= 63 && pveNodeRe.MatchString(s) }

// ValidateProviderMutationShape checks the caller-selected part of a
// mutation target (kind, node, vmid) on its own. The executor calls it
// before any read of the remote, so a malformed request never causes I/O
// with a credential.
func ValidateProviderMutationShape(kind, node string, vmid uint64) error {
	if !ValidPveNodeName(node) {
		return fmt.Errorf("%w: node", ErrProviderMutationTarget)
	}
	switch kind {
	case ProviderKindQemu, ProviderKindLXC:
		if vmid < pvecontract.MinVMID || vmid > pvecontract.MaxVMID {
			return fmt.Errorf("%w: vmid out of range", ErrProviderMutationTarget)
		}
	case ProviderKindNode:
		if vmid != 0 {
			return fmt.Errorf("%w: a node target has no vmid", ErrProviderMutationTarget)
		}
	default:
		return fmt.Errorf("%w: kind", ErrProviderMutationTarget)
	}
	return nil
}

// ProviderMutationTarget is the versioned exact target of one PVE mutation
// (ADR 0006: "versioned canonical provider targets"). Every member is bound
// into the permit's parameters hash. Any difference at dispatch time refuses
// the run and needs a new proposal: a re-pin, a new trust generation, a
// rotated action token, a changed API endpoint set, the guest moved to
// another node, VMID reuse, a changed configuration or guest generation, or
// another target version.
type ProviderMutationTarget struct {
	// Version is PveTargetVersion.
	Version         string `json:"target_version"`
	RemoteID        string `json:"remote_id"`
	TrustPin        string `json:"trust_pin"`
	TrustGeneration uint64 `json:"trust_generation"`
	// CredentialRef and CredentialVersion name the remote's action token.
	// A mutation never uses the read token.
	CredentialRef     string `json:"credential_ref"`
	CredentialVersion int64  `json:"credential_version"`
	// APIEndpoints is the remote's approved, ordered API endpoint set
	// (ADR 0006: failover may change the entry node only within it). A
	// changed set refuses the run.
	APIEndpoints []pvecontract.Endpoint `json:"api_endpoints"`
	Kind         string                 `json:"kind"`
	Node         string                 `json:"node"`
	// VMID is the guest; 0 for a node target.
	VMID uint64 `json:"vmid"`
	// ConfigDigest is the hex SHA-256 of the complete configuration the
	// approval was made against (precondition digest).
	ConfigDigest string `json:"config_digest"`
	// Generation is the guest generation: the configuration digest that PVE
	// itself returns with a guest's config (40 lowercase hex). PVE changes
	// it on every write of the guest's config file, including pending
	// changes and snapshot sections that ConfigDigest may not cover. It is
	// also the optimistic-lock token that PVE's own config writes accept.
	// Empty for a node target.
	Generation string `json:"generation"`
}

// Validate checks the shape of t.
func (t ProviderMutationTarget) Validate() error {
	switch {
	case t.Version != PveTargetVersion:
		return fmt.Errorf("%w: target version", ErrProviderMutationTarget)
	case !pvecontract.ValidRemoteID(t.RemoteID) || !pvecontract.ValidTrustPin(t.TrustPin):
		return fmt.Errorf("%w: remote identity", ErrProviderMutationTarget)
	case t.TrustGeneration < 1 || t.TrustGeneration > maxProviderTrustGeneration:
		return fmt.Errorf("%w: trust generation out of range", ErrProviderMutationTarget)
	case !credRefRe.MatchString(t.CredentialRef):
		return fmt.Errorf("%w: action credential reference", ErrProviderMutationTarget)
	case t.CredentialVersion < 1 || t.CredentialVersion > maxProviderCredentialVersion:
		return fmt.Errorf("%w: action credential version out of range", ErrProviderMutationTarget)
	case !validAPIEndpoints(t):
		return fmt.Errorf("%w: api endpoint set", ErrProviderMutationTarget)
	case !hex64Re.MatchString(t.ConfigDigest):
		return fmt.Errorf("%w: config digest", ErrProviderMutationTarget)
	}
	if err := ValidateProviderMutationShape(t.Kind, t.Node, t.VMID); err != nil {
		return err
	}
	if t.Kind == ProviderKindNode {
		if t.Generation != "" {
			return fmt.Errorf("%w: a node target has no guest generation", ErrProviderMutationTarget)
		}
	} else if !pveGenerationRe.MatchString(t.Generation) {
		return fmt.Errorf("%w: guest generation", ErrProviderMutationTarget)
	}
	return nil
}

// validAPIEndpoints checks the endpoint set of t with the registry rules of
// pvecontract (1..MaxEndpointsPerRemote valid, distinct host:port pairs).
func validAPIEndpoints(t ProviderMutationTarget) bool {
	_, err := pvecontract.ValidateRemote(pvecontract.Remote{
		RemoteID: t.RemoteID, Kind: pvecontract.KindCluster, Endpoints: t.APIEndpoints,
		TrustPin: t.TrustPin, TrustGeneration: t.TrustGeneration,
	})
	return err == nil
}

// diff names the first member in which t and u differ, or "" if they are
// equal. Member names are not secret.
func (t ProviderMutationTarget) diff(u ProviderMutationTarget) string {
	switch {
	case t.Version != u.Version:
		return "target version"
	case t.RemoteID != u.RemoteID:
		return "remote"
	case t.TrustPin != u.TrustPin || t.TrustGeneration != u.TrustGeneration:
		return "trust pin or generation"
	case t.CredentialRef != u.CredentialRef || t.CredentialVersion != u.CredentialVersion:
		return "action credential version"
	case !slices.Equal(t.APIEndpoints, u.APIEndpoints):
		return "api endpoint set"
	case t.Kind != u.Kind || t.Node != u.Node || t.VMID != u.VMID:
		return "node or vmid"
	case t.ConfigDigest != u.ConfigDigest:
		return "config digest"
	case t.Generation != u.Generation:
		return "guest generation"
	}
	return ""
}

// canonicalTarget is the replay and risk key of t inside the canonical
// request: a host ID derived from the exact resource, with the trust pin in
// the fingerprint slot. It is not an SSH host and grants nothing by itself.
// The versioned target is bound in the parameters, and
// AuthorizeProviderMutation compares it member by member. The key exists
// only because canonical.Request (protected, frozen spec) has no provider
// target slot yet; replacing it is an open maintainer decision.
func (t ProviderMutationTarget) canonicalTarget() (canonical.Target, error) {
	pin, err := hex.DecodeString(t.TrustPin)
	if err != nil || len(pin) != sha256.Size {
		return canonical.Target{}, fmt.Errorf("%w: trust pin", ErrProviderMutationTarget)
	}
	sum := sha256.Sum256([]byte(t.RemoteID + "\x00" + t.Kind + "\x00" + t.Node + "\x00" + strconv.FormatUint(t.VMID, 10)))
	return canonical.Target{
		HostID:             "pvm-" + hex.EncodeToString(sum[:16]),
		HostKeyFingerprint: "SHA256:" + base64.RawStdEncoding.EncodeToString(pin),
	}, nil
}

// RiskTarget returns the synthetic canonical target the authority binds
// and hands to the risk policy for t. Its host ID and fingerprint are what
// an executor criticality record must name to set the target's floor
// (ADR 0006: executor-owned remote/node/guest criticality).
func (t ProviderMutationTarget) RiskTarget() (canonical.Target, error) {
	return t.canonicalTarget()
}

// ProviderMutation is one typed PVE mutation as the executor presents it,
// both when proposing and again at dispatch time. Target and Parameters
// are rebuilt from the executor's registry and live reads each time.
type ProviderMutation struct {
	Target        ProviderMutationTarget
	ActionID      string
	ModuleVersion string
	// Artifact is the fixed description of the typed action; its hash is
	// bound like any artifact.
	Artifact []byte
	// Parameters is the action-specific JSON object.
	Parameters json.RawMessage
}

// providerMutationDoc is the parameters document of a mutation permit.
type providerMutationDoc struct {
	Binding    string                 `json:"binding"`
	Target     ProviderMutationTarget `json:"provider_target"`
	Parameters json.RawMessage        `json:"parameters"`
}

// BindingJSON returns the parameters document of m: the binding version,
// the exact target and the action parameters.
func (m ProviderMutation) BindingJSON() ([]byte, error) {
	if err := m.Target.Validate(); err != nil {
		return nil, err
	}
	if len(m.ActionID) <= len(ProviderMutationActionPrefix) || m.ActionID[:len(ProviderMutationActionPrefix)] != ProviderMutationActionPrefix {
		return nil, fmt.Errorf("%w: action %q is not a typed pve action", ErrProviderMutationTarget, m.ActionID)
	}
	p := bytes.TrimSpace(m.Parameters)
	if len(p) == 0 || len(p) > maxProviderMutationParams || p[0] != '{' || !json.Valid(p) {
		return nil, fmt.Errorf("%w: parameters must be a JSON object of at most %d bytes", ErrProviderMutationTarget, maxProviderMutationParams)
	}
	return json.Marshal(providerMutationDoc{Binding: ProviderMutationBinding, Target: m.Target, Parameters: p})
}

// ProviderMutationRequest builds the canonical request and parameters of a
// mutation permit. expiry, risk and the stage plan hash are chosen by the
// executor.
func ProviderMutationRequest(m ProviderMutation, executionID string, risk canonical.Risk, stagePlanHash string, expiry time.Time) (canonical.Request, []byte, error) {
	params, err := m.BindingJSON()
	if err != nil {
		return canonical.Request{}, nil, err
	}
	ph, err := canonical.HashParameters(params)
	if err != nil {
		return canonical.Request{}, nil, fmt.Errorf("hash provider mutation parameters: %w", err)
	}
	target, err := m.Target.canonicalTarget()
	if err != nil {
		return canonical.Request{}, nil, err
	}
	sum := sha256.Sum256(m.Artifact)
	return canonical.Request{
		ExecutionID: executionID, ActionID: m.ActionID, ModuleVersion: m.ModuleVersion,
		ArtifactSHA256: hex.EncodeToString(sum[:]), ParametersHash: ph,
		CredentialRefs: []string{m.Target.CredentialRef}, RiskClass: risk, StagePlanHash: stagePlanHash,
		ExpiryUnix: expiry.Unix(), ResolvedTargets: []canonical.Target{target},
	}, params, nil
}

// approvedMutationTarget returns the exact target bound in p, if p is a
// provider mutation permit.
func approvedMutationTarget(p *Permit) (ProviderMutationTarget, bool) {
	var doc providerMutationDoc
	if err := json.Unmarshal(p.Parameters, &doc); err != nil || doc.Binding != ProviderMutationBinding || doc.Target.Version != PveTargetVersion {
		return ProviderMutationTarget{}, false
	}
	return doc.Target, true
}

// MutationClaim is one authorized provider mutation. It carries no
// authority of its own: Check re-verifies before every dispatch step that
// the executor was not locked and the permit was not revoked since the
// claim. A claim never authorizes a second dispatch of the same step; the
// executor's durable job record enforces that.
type MutationClaim struct {
	// ExecutionID is the approved execution ID; it keys the durable job.
	ExecutionID string
	// Parameters are the approved canonical parameters.
	Parameters []byte
	digest     canonical.Digest
	hostID     string
	authority  *Authority
	epoch      uint64
	// token ties the claim to the use it made of the permit (Permit.claim).
	token uint64
}

// Release makes the claim's permit usable again. The executor calls it only
// when the run provably dispatched nothing: no step intent was recorded,
// for example because another mutation of the same target was still open.
// It fails (false) after a lock since the claim, and for a permit that was
// revoked, expired or is not approved. It also fails unless the current use
// of the permit is still the one this claim made: a claim releases at most
// once, and a stale claim never undoes a later claim's use. It reports
// whether the permit was released.
func (c MutationClaim) Release(reason string) bool {
	a := c.authority
	if a == nil || c.token == 0 {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if c.epoch != a.lockEpoch {
		return false
	}
	p, ok := a.permits[c.digest]
	if !ok || p.claim != c.token {
		return false
	}
	if !a.releaseHostLocked(c.digest, c.hostID, "provider mutation not dispatched: "+reason) {
		return false
	}
	p.claim = 0
	return true
}

// AuthorizeProviderMutation checks m, rebuilt by the executor from its
// current registry and live reads, against the approved permit d and
// consumes it: the exact target must equal the approved one member by
// member, and the action, artifact, parameters, action credential and risk
// floor are checked like every run. A permit authorizes one mutation.
func (a *Authority) AuthorizeProviderMutation(d canonical.Digest, m ProviderMutation) (MutationClaim, error) {
	params, err := m.BindingJSON()
	if err != nil {
		return MutationClaim{}, a.deny(d, "", CodeTargetNotPermitted, "malformed provider mutation")
	}
	target, err := m.Target.canonicalTarget()
	if err != nil {
		return MutationClaim{}, a.deny(d, "", CodeTargetNotPermitted, "malformed provider mutation")
	}
	a.mu.Lock()
	epoch := a.lockEpoch
	p, ok := a.permits[d]
	var approved ProviderMutationTarget
	bound := false
	if ok {
		approved, bound = approvedMutationTarget(p)
	}
	a.mu.Unlock()
	if !ok {
		return MutationClaim{}, a.deny(d, target.HostID, CodeNotFound, "")
	}
	if !bound {
		return MutationClaim{}, a.deny(d, target.HostID, CodeTargetNotPermitted, "permit has no provider mutation binding")
	}
	if field := approved.diff(m.Target); field != "" {
		return MutationClaim{}, a.deny(d, target.HostID, CodeTargetNotPermitted, "provider target "+field+" differs from approval")
	}
	g, err := a.AuthorizeGrant(d, Run{
		HostID: target.HostID, HostKeyFingerprint: target.HostKeyFingerprint, ActionID: m.ActionID,
		ModuleVersion: m.ModuleVersion, Artifact: m.Artifact, ParametersJSON: params, CredentialRef: m.Target.CredentialRef,
	})
	if err != nil {
		return MutationClaim{}, err
	}
	// The use just made belongs to this claim. A stale claim's Release
	// in between finds no matching token and does nothing.
	a.mu.Lock()
	a.claimSeq++
	token := a.claimSeq
	if p, ok := a.permits[d]; ok {
		p.claim = token
	}
	a.mu.Unlock()
	return MutationClaim{ExecutionID: g.ExecutionID, Parameters: g.Parameters, digest: d, hostID: target.HostID, authority: a, epoch: epoch, token: token}, nil
}

// Check reports whether the claim is still in force: no lock since it was
// made, and its permit is still approved, unexpired and not revoked. The
// executor calls it immediately before sending each mutation step; a
// failure stops undispatched work but cannot undo an accepted PVE task.
func (c MutationClaim) Check() error {
	a := c.authority
	if a == nil {
		return fail(CodeNotFound, "no authorized provider mutation")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if c.epoch != a.lockEpoch {
		return fail(CodeWrongState, "the executor was locked after authorization")
	}
	p, ok := a.permits[c.digest]
	if !ok || p.State != StateApproved {
		return fail(CodeNotFound, "the provider mutation permit was revoked")
	}
	if !a.now().Before(time.Unix(p.Request.ExpiryUnix, 0)) {
		return fail(CodeExpired, "")
	}
	return nil
}

// RevokeProviderMutations revokes every live mutation permit (pending or
// approved) bound to remoteID, e.g. when the remote is blocked, re-pinned,
// removed or its action token rotated. Mutations already in flight lose
// their claim before their next step. It returns the number revoked.
func (a *Authority) RevokeProviderMutations(remoteID, who string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	var revoked []canonical.Digest
	for d, p := range a.permits {
		if t, ok := approvedMutationTarget(p); ok && t.RemoteID == remoteID {
			revoked = append(revoked, d)
		}
	}
	slices.SortFunc(revoked, func(x, y canonical.Digest) int { return bytes.Compare(x[:], y[:]) })
	for _, d := range revoked {
		delete(a.permits, d)
		a.emit(Event{Kind: "revoked", Digest: d.String(), Detail: "provider remote " + remoteID + " by " + who})
	}
	return len(revoked)
}

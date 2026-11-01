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

// ProviderMutationBinding names version 1 of the exact-target binding of a
// PVE mutation permit (ADR 0006 "Phase 2 actions, permits and
// reconciliation", ADR 0008 PV-01). The executor builds the binding from its
// own registry and live reads; nothing in it is taken from the caller.
const ProviderMutationBinding = "pve-mutation-v1"

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
)

// ProviderMutationTarget is the exact target of one PVE mutation. Every
// member is bound into the permit digest; any difference at dispatch time
// (re-pin, new trust generation, rotated action token, changed API
// endpoint set, guest moved to
// another node, VMID reuse or a changed configuration) refuses the run and
// needs a new proposal.
type ProviderMutationTarget struct {
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
}

// Validate checks the shape of t.
func (t ProviderMutationTarget) Validate() error {
	switch {
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
	case !pvecontract.ValidNodeName(t.Node):
		return fmt.Errorf("%w: node", ErrProviderMutationTarget)
	case !hex64Re.MatchString(t.ConfigDigest):
		return fmt.Errorf("%w: config digest", ErrProviderMutationTarget)
	}
	switch t.Kind {
	case ProviderKindQemu, ProviderKindLXC:
		if t.VMID < pvecontract.MinVMID || t.VMID > pvecontract.MaxVMID {
			return fmt.Errorf("%w: vmid out of range", ErrProviderMutationTarget)
		}
	case ProviderKindNode:
		if t.VMID != 0 {
			return fmt.Errorf("%w: a node target has no vmid", ErrProviderMutationTarget)
		}
	default:
		return fmt.Errorf("%w: kind", ErrProviderMutationTarget)
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
	}
	return ""
}

// canonicalTarget is the permit target of t: a host ID derived from the
// exact resource and the trust pin as fingerprint. It is not an SSH host;
// the provider namespace "pvm-" cannot collide with an inventory host
// because the full tuple is bound in the parameters as well.
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
	if err := json.Unmarshal(p.Parameters, &doc); err != nil || doc.Binding != ProviderMutationBinding {
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
	authority  *Authority
	epoch      uint64
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
	return MutationClaim{ExecutionID: g.ExecutionID, Parameters: g.Parameters, digest: d, authority: a, epoch: epoch}, nil
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

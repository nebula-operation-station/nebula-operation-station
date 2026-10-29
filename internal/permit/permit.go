// SPDX-License-Identifier: AGPL-3.0-or-later

// Package permit implements the executor's authorization state: execution
// permits, their approval, the privileged session and the per-host run check.
//
// Invariants enforced here (docs/spec/05-authentication.md, 07-execution-model.md):
//
//   - A permit is bound to the digest the executor computed itself.
//   - A WebAuthn challenge is single-use and bound to digest, nonce and expiry.
//   - Approval strength follows the risk table; hardened mode forces the CLI
//     path for HIGH and CRITICAL.
//   - Every host in a permit can be authorized at most once.
//   - Artifact and parameters are hashed by the executor at run time and must
//     match the approved request.
//   - Locking revokes the privileged session and every permit.
//   - The proposed risk class is never below the minimum the executor derives
//     from its own data (RiskPolicy); every host run re-checks it.
//   - An execution ID is bound durably (Store) before its permit exists, so
//     a restart can never revive or re-bind it. Permits and the privileged
//     session are never persisted: a restart revokes them all.
package permit

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/stageplan"
	"github.com/nebula-operation-station/nebula-operation-station/internal/webauthnverify"
)

// Mode selects the approval policy.
type Mode int

const (
	// ModeStandard allows browser approval according to the risk table.
	ModeStandard Mode = iota
	// ModeHardened requires `nebula approve` for HIGH and CRITICAL.
	ModeHardened
)

// Requirement is what an approval must provide.
type Requirement int

// Requirements, ordered by strength.
const (
	RequireNone Requirement = iota + 1
	RequireAssertionPresence
	RequireAssertionVerified
	RequireAssertionVerifiedTypedCount
	RequireCLI
)

func (r Requirement) String() string {
	switch r {
	case RequireNone:
		return "none (privileged session)"
	case RequireAssertionPresence:
		return "WebAuthn, user presence"
	case RequireAssertionVerified:
		return "WebAuthn, user verification"
	case RequireAssertionVerifiedTypedCount:
		return "WebAuthn, user verification, typed target count"
	case RequireCLI:
		return "nebula approve (CLI only)"
	default:
		return "unknown"
	}
}

// RequirementFor returns the approval requirement for a risk class.
func RequirementFor(risk canonical.Risk, mode Mode) Requirement {
	switch risk {
	case canonical.RiskLow:
		return RequireNone
	case canonical.RiskMedium:
		return RequireAssertionPresence
	case canonical.RiskHigh:
		if mode == ModeHardened {
			return RequireCLI
		}
		return RequireAssertionVerified
	case canonical.RiskCritical:
		if mode == ModeHardened {
			return RequireCLI
		}
		return RequireAssertionVerifiedTypedCount
	default:
		// Unknown risk is rejected by canonical.Normalize; be strict anyway.
		return RequireCLI
	}
}

// State of a permit.
type State int

// Permit states.
const (
	StatePending State = iota + 1
	StateApproved
)

// Code classifies authorization failures. The string form is stable and is
// surfaced to callers and the audit log.
type Code string

// Failure codes.
const (
	CodeInvalidRequest     Code = "invalid_request"
	CodeExecutionIDReused  Code = "execution_id_reused"
	CodeSessionRequired    Code = "privileged_session_required"
	CodeNotFound           Code = "permit_not_found"
	CodeWrongState         Code = "permit_wrong_state"
	CodeExpired            Code = "permit_expired"
	CodeCLIRequired        Code = "cli_approval_required"
	CodeTypedCountMismatch Code = "typed_target_count_mismatch"
	CodeAssertionRejected  Code = "assertion_rejected"
	CodeTargetNotPermitted Code = "target_not_permitted"
	CodeHostAlreadyRun     Code = "host_already_authorized"
	CodeArtifactMismatch   Code = "artifact_mismatch"
	CodeParametersMismatch Code = "parameters_mismatch"
	CodeActionMismatch     Code = "action_mismatch"
	CodeCredentialMismatch Code = "credential_not_permitted"
	CodeLimit              Code = "limit_exceeded"
	CodeNoChallenge        Code = "no_session_challenge"
	CodeStorage            Code = "storage_error"
	// CodeRiskAboveApproval: the executor's minimum risk for this host run
	// is now higher than the risk the permit was approved at (trust was
	// withdrawn or a host became more critical after approval).
	CodeRiskAboveApproval Code = "risk_above_approval"
)

// Error is an authorization failure.
type Error struct {
	Code   Code
	Detail string
}

func (e *Error) Error() string {
	if e.Detail == "" {
		return string(e.Code)
	}
	return string(e.Code) + ": " + e.Detail
}

func fail(code Code, format string, args ...any) error {
	return &Error{Code: code, Detail: fmt.Sprintf(format, args...)}
}

// CodeOf returns the failure code of err, or "" if it is not an *Error.
func CodeOf(err error) Code {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

// Limits and timings.
const (
	ApprovalWindow       = 5 * time.Minute
	SessionChallengeTTL  = 2 * time.Minute
	DefaultSessionLength = 60 * time.Minute
	MaxPending           = 256
	MaxPermits           = 4096
	MaxExecutionIDs      = 65536
	MaxFailedAssertions  = 3
)

// Permit is one execution permit.
type Permit struct {
	Digest    canonical.Digest
	Request   canonical.Request
	Canonical []byte
	// Parameters is the RFC 8785 form of the approved parameters, kept so
	// that the CLI can show what is being approved and later milestones can
	// hand exactly these bytes to the host.
	Parameters     []byte
	Requirement    Requirement
	State          State
	Challenge      []byte
	ApprovalExpiry time.Time
	ApprovedAt     time.Time
	ApprovedBy     string
	// Plan is the approved stage plan (one stage of all targets for a
	// request without stages).
	Plan []stageplan.Stage

	failed int
	used   map[string]struct{}
	stages *stages
	// staged: the request carried a stage plan document.
	staged bool
}

// TargetCount is the number of hosts the permit covers.
func (p *Permit) TargetCount() int { return len(p.Request.ResolvedTargets) }

func (p *Permit) clone() Permit {
	c := *p
	c.Canonical = slices.Clone(p.Canonical)
	c.Parameters = slices.Clone(p.Parameters)
	c.Challenge = slices.Clone(p.Challenge)
	c.Plan = slices.Clone(p.Plan)
	for i := range c.Plan {
		c.Plan[i].Hosts = slices.Clone(c.Plan[i].Hosts)
	}
	c.used = nil
	c.stages = nil
	return c
}

// Event is an audit record emitted for every decision.
type Event struct {
	Time   time.Time
	Kind   string // proposed, approved, rejected, authorized, denied, session_opened, locked
	Digest string
	Host   string
	Code   Code
	Detail string
}

// Store durably records execution ID bindings (internal/executordb
// implements it). Execution IDs are single-use across restarts.
type Store interface {
	// BindExecution records that executionID is bound to digest. It must be
	// durable when it returns nil, and return ErrExecutionBound if the ID is
	// already bound, to any digest.
	BindExecution(executionID string, d canonical.Digest, expiresAt time.Time) error
	// LookupExecution returns the digest an execution ID is bound to.
	LookupExecution(executionID string) (d canonical.Digest, ok bool, err error)
}

// RiskPolicy derives the minimum risk class from data the executor holds
// itself (internal/riskpolicy implements it). The server's risk_class is
// never trusted below it.
type RiskPolicy interface {
	// MinimumRisk returns the lowest acceptable risk class for running r on
	// targets and a reason for the audit log (it may name hosts and trust
	// entries, so it is never returned to the caller). An error means the
	// floor is unknown.
	MinimumRisk(r canonical.Request, targets []canonical.Target) (canonical.Risk, string, error)
}

// ErrExecutionBound is returned by Store.BindExecution for an execution ID
// that is already bound.
var ErrExecutionBound = errors.New("permit: execution ID already bound")

// Options configure an Authority.
type Options struct {
	Mode          Mode
	Verifier      *webauthnverify.Verifier
	SessionLength time.Duration
	Now           func() time.Time
	Audit         func(Event)
	// Store persists execution ID bindings. Required.
	Store Store
	// RiskPolicy is the executor's minimum risk. Required.
	RiskPolicy RiskPolicy
	// Schedules persists schedule grants; nil disables them.
	Schedules ScheduleStore
	// Leases persists read grants; nil disables them.
	Leases ReadGrantStore
}

// Authority owns all permits and the privileged session. It is safe for
// concurrent use.
type Authority struct {
	mode     Mode
	verifier *webauthnverify.Verifier
	sessLen  time.Duration
	now      func() time.Time
	audit    func(Event)
	store    Store
	risk     RiskPolicy
	// schedules persists approved schedule grants (nil: disabled); grants
	// holds the proposed ones until approval.
	schedules ScheduleStore
	grants    map[string]*pendingGrant
	// leases persists approved read grants (nil: disabled); readGrants
	// holds the proposed ones until approval.
	leases     ReadGrantStore
	readGrants map[string]*pendingReadGrant
	// trusts holds browser trust requests until their assertion (M7-4).
	trusts map[string]*PendingTrust

	mu          sync.Mutex
	permits     map[canonical.Digest]*Permit
	executions  map[string]canonical.Digest // execution_id -> digest
	sessionTill time.Time
	sessChal    []byte
	sessChalExp time.Time

	scanMu sync.Mutex // guards scans; never held while taking mu
	scans  map[string]scanResult
}

// New returns an Authority. A verifier and a store are required. A new
// Authority holds no permits and no privileged session, whatever happened
// before: restarting the executor revokes everything except the spent
// execution IDs in the store.
func New(o Options) (*Authority, error) {
	if o.Verifier == nil {
		return nil, errors.New("permit: WebAuthn verifier is required")
	}
	if o.Store == nil {
		return nil, errors.New("permit: a persistent store is required")
	}
	if o.RiskPolicy == nil {
		return nil, errors.New("permit: a risk policy is required")
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.SessionLength <= 0 {
		o.SessionLength = DefaultSessionLength
	}
	if o.Audit == nil {
		o.Audit = func(Event) {}
	}
	return &Authority{
		mode:       o.Mode,
		verifier:   o.Verifier,
		sessLen:    o.SessionLength,
		now:        o.Now,
		audit:      o.Audit,
		store:      o.Store,
		risk:       o.RiskPolicy,
		permits:    map[canonical.Digest]*Permit{},
		executions: map[string]canonical.Digest{},
		schedules:  o.Schedules,
		grants:     map[string]*pendingGrant{},
		leases:     o.Leases,
		readGrants: map[string]*pendingReadGrant{},
		scans:      map[string]scanResult{},
		trusts:     map[string]*PendingTrust{},
	}, nil
}

// Mode returns the configured approval mode.
func (a *Authority) Mode() Mode { return a.mode }

// ProposeResult is returned by Propose.
type ProposeResult struct {
	Permit Permit // copy
}

// Propose registers an execution request and returns its permit. The
// parameters document must hash to the request's parameters_hash; the
// executor keeps its canonical form for display and execution. LOW risk is
// approved immediately when a privileged session is active.
//
// An execution ID is single-use: once its permit is gone (expired, discarded
// or revoked by Lock), proposing it again is rejected and the caller must
// create a new execution.
func (a *Authority) Propose(r canonical.Request, parametersJSON []byte) (ProposeResult, error) {
	return a.propose(r, parametersJSON, nil, false)
}

// ProposeStaged is Propose for a request with a stage plan (spec 07). The
// plan document must hash to the request's stage_plan_hash, cover every
// target exactly once and, for a HIGH or CRITICAL request, continue
// manually past every stage. raise is ProposeAtLeastMinimum's behaviour.
func (a *Authority) ProposeStaged(r canonical.Request, parametersJSON, planJSON []byte, raise bool) (ProposeResult, error) {
	if len(planJSON) == 0 {
		return ProposeResult{}, fail(CodeStagePlan, "the stage plan document is required")
	}
	return a.propose(r, parametersJSON, planJSON, raise)
}

// ProposeAtLeastMinimum is Propose, but a risk_class below the executor's
// minimum is raised to that minimum instead of being rejected. Raising
// only makes the approval stricter; the permit records the raised class.
func (a *Authority) ProposeAtLeastMinimum(r canonical.Request, parametersJSON []byte) (ProposeResult, error) {
	return a.propose(r, parametersJSON, nil, true)
}

func (a *Authority) propose(r canonical.Request, parametersJSON, planJSON []byte, raise bool) (ProposeResult, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	a.gcLocked(now)

	norm, canon, digest, err := canonical.Canonicalize(r, now)
	if err != nil {
		return ProposeResult{}, fail(CodeInvalidRequest, "%v", err)
	}
	if raise {
		floor, _, err := a.floor(norm, norm.ResolvedTargets, parametersJSON)
		if err != nil {
			return ProposeResult{}, a.storageFailure(digest.String(), err)
		}
		if floor.Rank() > norm.RiskClass.Rank() {
			r.RiskClass = floor
			if norm, canon, digest, err = canonical.Canonicalize(r, now); err != nil {
				return ProposeResult{}, fail(CodeInvalidRequest, "%v", err)
			}
		}
	}
	params, paramsHash, err := canonical.CanonicalParameters(parametersJSON)
	if err != nil {
		return ProposeResult{}, fail(CodeInvalidRequest, "%v", err)
	}
	if paramsHash != norm.ParametersHash {
		return ProposeResult{}, fail(CodeInvalidRequest, "parameters do not hash to parameters_hash")
	}
	if _, err := SecretRefs(params); err != nil {
		return ProposeResult{}, fail(CodeInvalidRequest, "parameters: %v", err)
	}

	prev, bound := a.executions[norm.ExecutionID]
	if !bound {
		// Not bound by this process; it may have been bound before a restart.
		d, ok, err := a.store.LookupExecution(norm.ExecutionID)
		if err != nil {
			return ProposeResult{}, a.storageFailure(digest.String(), err)
		}
		prev, bound = d, ok
	}
	if bound {
		if prev != digest {
			a.emit(Event{Kind: "rejected", Digest: digest.String(), Code: CodeExecutionIDReused})
			return ProposeResult{}, fail(CodeExecutionIDReused, "execution_id %s already bound to another request", norm.ExecutionID)
		}
		if p, live := a.permits[digest]; live {
			return ProposeResult{Permit: p.clone()}, nil
		}
		a.emit(Event{Kind: "rejected", Digest: digest.String(), Code: CodeExecutionIDReused, Detail: "execution already ended"})
		return ProposeResult{}, fail(CodeExecutionIDReused, "execution_id %s has ended; create a new execution", norm.ExecutionID)
	}

	// The server's risk_class may raise the approval strength, never lower
	// it below what the executor derives itself.
	floor, why, err := a.floor(norm, norm.ResolvedTargets, params)
	if err != nil {
		return ProposeResult{}, a.storageFailure(digest.String(), err)
	}
	if floor.Rank() == 0 {
		return ProposeResult{}, a.storageFailure(digest.String(), fmt.Errorf("risk policy returned unknown risk %q", floor))
	}
	if norm.RiskClass.Rank() < floor.Rank() {
		a.emit(Event{Kind: "rejected", Digest: digest.String(), Code: CodeInvalidRequest,
			Detail: fmt.Sprintf("risk_class %s below executor minimum %s (%s)", norm.RiskClass, floor, why)})
		return ProposeResult{}, fail(CodeInvalidRequest, "risk_class %s is below the executor's minimum %s", norm.RiskClass, floor)
	}

	plan := singleStagePlan(norm.ResolvedTargets)
	if planJSON != nil {
		hosts := make([]string, len(norm.ResolvedTargets))
		for i, t := range norm.ResolvedTargets {
			hosts[i] = t.HostID
		}
		sp, err := stageplan.Parse(planJSON, hosts)
		if err != nil {
			a.emit(Event{Kind: "rejected", Digest: digest.String(), Code: CodeStagePlan, Detail: err.Error()})
			return ProposeResult{}, fail(CodeStagePlan, "%v", err)
		}
		if sp.Hash != norm.StagePlanHash {
			a.emit(Event{Kind: "rejected", Digest: digest.String(), Code: CodeStagePlan, Detail: "plan does not hash to stage_plan_hash"})
			return ProposeResult{}, fail(CodeStagePlan, "the stage plan does not hash to stage_plan_hash")
		}
		// Decision 2 of the M6 plan: HIGH and CRITICAL rollouts never
		// continue on their own; every gate needs a fresh assertion.
		if sp.AutoContinue() && norm.RiskClass.Rank() >= canonical.RiskHigh.Rank() {
			a.emit(Event{Kind: "rejected", Digest: digest.String(), Code: CodeStagePlan, Detail: "automatic continue on a " + string(norm.RiskClass) + " rollout"})
			return ProposeResult{}, fail(CodeStagePlan, "a %s rollout must continue manually past every stage", norm.RiskClass)
		}
		plan = sp.Stages
	}

	req := RequirementFor(norm.RiskClass, a.mode)
	if req == RequireNone && !a.sessionActiveLocked(now) {
		a.emit(Event{Kind: "rejected", Digest: digest.String(), Code: CodeSessionRequired})
		return ProposeResult{}, fail(CodeSessionRequired, "LOW risk needs an active privileged session")
	}
	if a.pendingCountLocked() >= MaxPending {
		return ProposeResult{}, fail(CodeLimit, "too many pending permits")
	}
	if len(a.permits) >= MaxPermits {
		return ProposeResult{}, fail(CodeLimit, "too many live permits")
	}
	if len(a.executions) >= MaxExecutionIDs {
		return ProposeResult{}, fail(CodeLimit, "execution ID table full; restart the executor")
	}

	p := &Permit{
		Digest:      digest,
		Request:     norm,
		Canonical:   canon,
		Parameters:  params,
		Requirement: req,
		Plan:        plan,
		used:        map[string]struct{}{},
		stages:      newStages(plan),
		staged:      planJSON != nil,
	}
	if req == RequireNone {
		p.State = StateApproved
		p.ApprovedAt = now
		p.ApprovedBy = "privileged-session"
	} else {
		p.State = StatePending
		p.ApprovalExpiry = minTime(now.Add(ApprovalWindow), time.Unix(norm.ExpiryUnix, 0))
		ch, err := challengeFor(digest, p.ApprovalExpiry)
		if err != nil {
			return ProposeResult{}, err
		}
		p.Challenge = ch
	}
	// Bind durably before the permit exists. If the binding cannot be
	// stored, no permit is created and nothing is bound in memory.
	if err := a.store.BindExecution(norm.ExecutionID, digest, time.Unix(norm.ExpiryUnix, 0)); err != nil {
		if errors.Is(err, ErrExecutionBound) {
			a.emit(Event{Kind: "rejected", Digest: digest.String(), Code: CodeExecutionIDReused})
			return ProposeResult{}, fail(CodeExecutionIDReused, "execution_id %s already bound", norm.ExecutionID)
		}
		return ProposeResult{}, a.storageFailure(digest.String(), err)
	}
	a.permits[digest] = p
	a.executions[norm.ExecutionID] = digest
	a.emit(Event{Kind: "proposed", Digest: digest.String(), Detail: req.String()})
	if p.State == StateApproved {
		a.emit(Event{Kind: "approved", Digest: digest.String(), Detail: p.ApprovedBy})
	}
	return ProposeResult{Permit: p.clone()}, nil
}

// challengeFor returns SHA-256(digest || 32-byte nonce || expiry as big-endian
// int64 Unix seconds).
func challengeFor(d canonical.Digest, expiry time.Time) ([]byte, error) {
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, fmt.Errorf("permit: nonce: %w", err)
	}
	var exp [8]byte
	binary.BigEndian.PutUint64(exp[:], uint64(expiry.Unix()))
	h := sha256.New()
	h.Write(d[:])
	h.Write(nonce[:])
	h.Write(exp[:])
	return h.Sum(nil), nil
}

// floorRiseLocked rejects the approval when the executor's minimum risk
// rose above the permit's risk class since the proposal (trust withdrawn,
// a host made more critical, or the scanner). Called with a.mu held.
//
// The per-target risk reads (trust, host criticality) are store queries, so
// they must not run while a.mu is held: the request, its targets and the
// parameters are copied under the lock, the lock is dropped for the reads,
// then re-acquired and the permit re-validated — it may have been approved,
// expired or discarded while the store was read. If anything changed or a
// read fails, the approval is rejected, exactly as when the check ran under
// the lock. The reason (which may name hosts) goes to the audit log, not
// the reply.
func (a *Authority) floorRiseLocked(p *Permit) error {
	d := p.Digest
	req := p.Request
	params := p.Parameters
	var (
		floor canonical.Risk
		why   string
		ferr  error
	)
	func() {
		// Re-acquire even if the read panics, so the caller's deferred
		// Unlock never unlocks an unlocked mutex.
		a.mu.Unlock()
		defer a.mu.Lock()
		floor, why, ferr = a.floor(req, req.ResolvedTargets, params)
	}()
	// Re-validate: the permit may have changed while the store was read. It
	// must still be pending and the very same permit the caller holds; a
	// permit discarded and proposed again under the same digest is another
	// object, and approving the caller's stale copy would report an approval
	// that never reaches the live permit.
	q, err := a.pendingLocked(d, a.now())
	if err != nil {
		return err
	}
	if q != p {
		a.emit(Event{Kind: "rejected", Digest: d.String(), Code: CodeWrongState,
			Detail: "permit replaced during the risk check"})
		return fail(CodeWrongState, "permit changed during approval, try again")
	}
	if ferr != nil || floor.Rank() == 0 {
		a.emit(Event{Kind: "rejected", Digest: d.String(), Code: CodeStorage,
			Detail: fmt.Sprintf("risk policy: %v (floor %q)", ferr, floor)})
		return fail(CodeStorage, "executor state store unavailable")
	}
	if req.RiskClass.Rank() < floor.Rank() {
		a.emit(Event{Kind: "rejected", Digest: d.String(), Code: CodeRiskAboveApproval,
			Detail: fmt.Sprintf("approved as %s, executor minimum is now %s (%s)", req.RiskClass, floor, why)})
		return fail(CodeRiskAboveApproval, "approved as %s, executor minimum is now %s", req.RiskClass, floor)
	}
	return nil
}

// SubmitAssertion approves a pending permit with a WebAuthn assertion that
// the browser produced over the permit's challenge.
func (a *Authority) SubmitAssertion(d canonical.Digest, assertionJSON []byte, typedCount int) (Permit, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	a.gcLocked(now)

	p, err := a.pendingLocked(d, now)
	if err != nil {
		return Permit{}, err
	}
	switch p.Requirement {
	case RequireCLI:
		return Permit{}, a.reject(p, CodeCLIRequired, "hardened mode: use nebula approve")
	case RequireNone:
		return Permit{}, a.reject(p, CodeWrongState, "permit needs no assertion")
	}
	if !a.sessionActiveLocked(now) {
		return Permit{}, a.reject(p, CodeSessionRequired, "browser approval needs an active privileged session")
	}
	if p.Requirement == RequireAssertionVerifiedTypedCount && typedCount != p.TargetCount() {
		return Permit{}, a.countFailure(p, CodeTypedCountMismatch, "typed %d, permit covers %d targets", typedCount, p.TargetCount())
	}
	if err := a.floorRiseLocked(p); err != nil {
		return Permit{}, err
	}

	uv := p.Requirement >= RequireAssertionVerified
	credID, err := a.verifier.Verify(assertionJSON, p.Challenge, webauthnverify.Requirement{UserVerification: uv})
	if errors.Is(err, webauthnverify.ErrCounterStore) {
		// The assertion may be valid; the executor could not record its
		// counter. Not the approver's fault, so it is not counted as a
		// failed approval, and the store detail stays in the audit log.
		return Permit{}, a.storageFailure(d.String(), err)
	}
	if err != nil {
		return Permit{}, a.countFailure(p, CodeAssertionRejected, "%v", err)
	}

	p.State = StateApproved
	p.Challenge = nil // single use
	p.ApprovedAt = now
	p.ApprovedBy = "webauthn:" + hex.EncodeToString(credID)
	a.emit(Event{Kind: "approved", Digest: d.String(), Detail: p.ApprovedBy})
	return p.clone(), nil
}

// ApproveCLI approves a pending permit from the hardened CLI path. The caller
// (the executor RPC layer) has already established that the peer is an
// admin UID on the executor host.
func (a *Authority) ApproveCLI(d canonical.Digest, typedCount int, who string) (Permit, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	a.gcLocked(now)

	p, err := a.pendingLocked(d, now)
	if err != nil {
		return Permit{}, err
	}
	if p.Request.RiskClass == canonical.RiskCritical && typedCount != p.TargetCount() {
		return Permit{}, a.countFailure(p, CodeTypedCountMismatch, "typed %d, permit covers %d targets", typedCount, p.TargetCount())
	}
	if err := a.floorRiseLocked(p); err != nil {
		return Permit{}, err
	}
	p.State = StateApproved
	p.Challenge = nil
	p.ApprovedAt = now
	p.ApprovedBy = "cli:" + who
	a.emit(Event{Kind: "approved", Digest: d.String(), Detail: p.ApprovedBy})
	return p.clone(), nil
}

// Run describes one host run as presented at execution time.
type Run struct {
	HostID             string
	HostKeyFingerprint string
	ActionID           string
	ModuleVersion      string
	Artifact           []byte
	ParametersJSON     []byte
	CredentialRef      string
}

// MaxArtifactSize bounds the artifact bytes hashed per run.
const MaxArtifactSize = 8 << 20

// Grant is what an authorized host run may use. Parameters are the
// canonical bytes the executor held since the proposal: Milestone 4 hands
// exactly these to the host, never the bytes of the run request.
type Grant struct {
	ExecutionID string
	Parameters  []byte
}

// Authorize is AuthorizeGrant without the grant: it reserves the host like
// a run does (spec 07, one use per host). It serves the AuthorizeRun RPC,
// which only checks and reserves; nothing records an outcome for a host
// reserved this way, so it refuses permits proposed with a stage plan: such
// a host would hold its stage open for good, and a Skip gate refuses a used
// host without an outcome (decision 59). Staged permits run only through
// the executor's own run path.
func (a *Authority) Authorize(d canonical.Digest, run Run) error {
	a.mu.Lock()
	p, ok := a.permits[d]
	staged := ok && p.staged
	a.mu.Unlock()
	if staged {
		return a.deny(d, run.HostID, CodeStagePlan, "a staged permit runs only through the executor's run path")
	}
	_, err := a.AuthorizeGrant(d, run)
	return err
}

// AuthorizeGrant checks one host run against an approved permit and, if
// every check passes, marks the host as used. Nothing is marked on failure.
func (a *Authority) AuthorizeGrant(d canonical.Digest, run Run) (Grant, error) {
	// Hash outside the lock; artifacts can be large.
	if len(run.Artifact) == 0 || len(run.Artifact) > MaxArtifactSize {
		return Grant{}, fail(CodeArtifactMismatch, "artifact size %d outside 1..%d", len(run.Artifact), MaxArtifactSize)
	}
	artSum := sha256.Sum256(run.Artifact)
	a.observe(artSum, run.Artifact)
	paramHash, perr := canonical.HashParameters(run.ParametersJSON)

	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	a.gcLocked(now)

	p, ok := a.permits[d]
	if !ok {
		return Grant{}, a.deny(d, run.HostID, CodeNotFound, "")
	}
	if p.State != StateApproved {
		return Grant{}, a.deny(d, run.HostID, CodeWrongState, "permit is not approved")
	}
	if !now.Before(time.Unix(p.Request.ExpiryUnix, 0)) {
		return Grant{}, a.deny(d, run.HostID, CodeExpired, "")
	}

	idx := slices.IndexFunc(p.Request.ResolvedTargets, func(t canonical.Target) bool { return t.HostID == run.HostID })
	if idx < 0 {
		return Grant{}, a.deny(d, run.HostID, CodeTargetNotPermitted, "host not in permit")
	}
	if subtle.ConstantTimeCompare([]byte(p.Request.ResolvedTargets[idx].HostKeyFingerprint), []byte(run.HostKeyFingerprint)) != 1 {
		return Grant{}, a.deny(d, run.HostID, CodeTargetNotPermitted, "host key fingerprint differs from approval")
	}
	if _, done := p.used[run.HostID]; done {
		return Grant{}, a.deny(d, run.HostID, CodeHostAlreadyRun, "")
	}
	if err := a.checkStageLocked(p, d, run.HostID); err != nil {
		return Grant{}, err
	}
	if run.ActionID != p.Request.ActionID || run.ModuleVersion != p.Request.ModuleVersion {
		return Grant{}, a.deny(d, run.HostID, CodeActionMismatch, "")
	}
	if hex.EncodeToString(artSum[:]) != p.Request.ArtifactSHA256 {
		return Grant{}, a.deny(d, run.HostID, CodeArtifactMismatch, "artifact bytes do not hash to the approved value")
	}
	if perr != nil {
		return Grant{}, a.deny(d, run.HostID, CodeParametersMismatch, perr.Error())
	}
	if paramHash != p.Request.ParametersHash {
		return Grant{}, a.deny(d, run.HostID, CodeParametersMismatch, "parameters do not hash to the approved value")
	}
	if !slices.Contains(p.Request.CredentialRefs, run.CredentialRef) {
		return Grant{}, a.deny(d, run.HostID, CodeCredentialMismatch, "")
	}
	// Risk authorization per host run (spec 07): trust withdrawn or a host
	// made more critical after approval stops the run.
	floor, why, err := a.floor(p.Request, p.Request.ResolvedTargets[idx:idx+1], p.Parameters)
	if err != nil || floor.Rank() == 0 {
		detail := fmt.Sprintf("risk policy: %v (floor %q)", err, floor)
		a.emit(Event{Kind: "denied", Digest: d.String(), Host: run.HostID, Code: CodeStorage, Detail: detail})
		return Grant{}, fail(CodeStorage, "executor state store unavailable")
	}
	if p.Request.RiskClass.Rank() < floor.Rank() {
		a.emit(Event{Kind: "denied", Digest: d.String(), Host: run.HostID, Code: CodeRiskAboveApproval,
			Detail: fmt.Sprintf("approved as %s, executor minimum is now %s (%s)", p.Request.RiskClass, floor, why)})
		return Grant{}, fail(CodeRiskAboveApproval, "approved as %s, executor minimum for this host is now %s", p.Request.RiskClass, floor)
	}

	p.used[run.HostID] = struct{}{}
	a.emit(Event{Kind: "authorized", Digest: d.String(), Host: run.HostID})
	return Grant{ExecutionID: p.Request.ExecutionID, Parameters: slices.Clone(p.Parameters)}, nil
}

// ReleaseHost makes a host of an approved permit usable again after a run
// that provably never reached it: the executor calls it only when every
// endpoint failed before the host key was received, so no credential was
// offered and nothing ran (spec 07: the permit stays unused for this host;
// the stage engine's Retry of an unreachable host relies on it). It
// reports whether the host was released.
func (a *Authority) ReleaseHost(d canonical.Digest, hostID string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	p, ok := a.permits[d]
	if !ok || p.State != StateApproved || !a.now().Before(time.Unix(p.Request.ExpiryUnix, 0)) {
		return false
	}
	if _, used := p.used[hostID]; !used || p.stages.outcome[hostID] == OutcomeSkipped {
		return false
	}
	delete(p.used, hostID)
	a.emit(Event{Kind: "released", Digest: d.String(), Host: hostID, Detail: "host unreachable; nothing ran"})
	return true
}

// BeginSession returns a fresh challenge for opening the privileged session.
// A new call replaces any earlier unused challenge.
func (a *Authority) BeginSession() ([]byte, time.Time, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	c := make([]byte, 32)
	if _, err := rand.Read(c); err != nil {
		return nil, time.Time{}, err
	}
	a.sessChal = c
	a.sessChalExp = a.now().Add(SessionChallengeTTL)
	return slices.Clone(c), a.sessChalExp, nil
}

// CompleteSession opens the privileged session with a user-verified
// assertion over the challenge from BeginSession. The challenge is consumed
// whether or not verification succeeds.
func (a *Authority) CompleteSession(assertionJSON []byte) (time.Time, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	ch, exp := a.sessChal, a.sessChalExp
	a.sessChal, a.sessChalExp = nil, time.Time{}
	if ch == nil {
		return time.Time{}, fail(CodeNoChallenge, "call BeginPrivilegedSession first")
	}
	if !now.Before(exp) {
		return time.Time{}, fail(CodeExpired, "session challenge expired")
	}
	credID, err := a.verifier.Verify(assertionJSON, ch, webauthnverify.Requirement{UserVerification: true})
	if errors.Is(err, webauthnverify.ErrCounterStore) {
		return time.Time{}, a.storageFailure("", err)
	}
	if err != nil {
		a.emit(Event{Kind: "rejected", Code: CodeAssertionRejected, Detail: "privileged session: " + err.Error()})
		return time.Time{}, fail(CodeAssertionRejected, "%v", err)
	}
	a.sessionTill = now.Add(a.sessLen)
	a.emit(Event{Kind: "session_opened", Detail: "webauthn:" + hex.EncodeToString(credID)})
	return a.sessionTill, nil
}

// Session reports whether the privileged session is active and until when.
func (a *Authority) Session() (bool, time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	return a.sessionActiveLocked(now), a.sessionTill
}

// Lock ends the privileged session and revokes every permit.
func (a *Authority) Lock(who string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.sessionTill = time.Time{}
	a.sessChal, a.sessChalExp = nil, time.Time{}
	n := len(a.permits)
	a.permits = map[canonical.Digest]*Permit{}
	// Pending schedule grants go too; approved ones stay (they need an
	// unlocked keyring to run anyway, and are revoked one by one).
	a.grants = map[string]*pendingGrant{}
	a.readGrants = map[string]*pendingReadGrant{}
	a.trusts = map[string]*PendingTrust{}
	// Execution IDs stay reserved so a revoked request cannot be re-bound to
	// different content under the same ID.
	a.emit(Event{Kind: "locked", Detail: fmt.Sprintf("by %s, %d permits revoked", who, n)})
}

// Pending returns copies of all pending, unexpired permits.
func (a *Authority) Pending() []Permit {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.gcLocked(a.now())
	var out []Permit
	for _, p := range a.permits {
		if p.State == StatePending {
			out = append(out, p.clone())
		}
	}
	slices.SortFunc(out, func(x, y Permit) int { return x.ApprovalExpiry.Compare(y.ApprovalExpiry) })
	return out
}

// Counts returns the number of pending and approved permits.
func (a *Authority) Counts() (pending, approved int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.gcLocked(a.now())
	for _, p := range a.permits {
		if p.State == StatePending {
			pending++
		} else {
			approved++
		}
	}
	return pending, approved
}

// PermitState reports the state of the live permit for the digest without
// changing it: StatePending or StateApproved, or ok=false when there is no
// live permit (never proposed, approval window closed, request expired,
// consumed past expiry, or revoked by Lock). It reveals nothing about the
// permit's contents. Expired permits are collected first, exactly like
// Pending and Counts, so the answer matches what the executor would act on.
func (a *Authority) PermitState(d canonical.Digest) (State, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.gcLocked(a.now())
	p, ok := a.permits[d]
	if !ok {
		return 0, false
	}
	return p.State, true
}

func (a *Authority) pendingLocked(d canonical.Digest, now time.Time) (*Permit, error) {
	p, ok := a.permits[d]
	if !ok {
		return nil, fail(CodeNotFound, "")
	}
	if p.State != StatePending {
		return nil, fail(CodeWrongState, "permit is not pending")
	}
	if !now.Before(p.ApprovalExpiry) {
		delete(a.permits, d)
		return nil, fail(CodeExpired, "approval window closed")
	}
	return p, nil
}

func (a *Authority) countFailure(p *Permit, code Code, format string, args ...any) error {
	p.failed++
	err := a.reject(p, code, format, args...)
	if p.failed >= MaxFailedAssertions {
		delete(a.permits, p.Digest)
		a.emit(Event{Kind: "rejected", Digest: p.Digest.String(), Code: CodeLimit, Detail: "too many failed approvals, permit discarded"})
	}
	return err
}

func (a *Authority) reject(p *Permit, code Code, format string, args ...any) error {
	err := fail(code, format, args...)
	a.emit(Event{Kind: "rejected", Digest: p.Digest.String(), Code: code, Detail: err.Error()})
	return err
}

// storageFailure records a store error in the audit trail and returns a
// generic error: store details (paths, OS errors) stay on the executor.
func (a *Authority) storageFailure(digest string, err error) error {
	a.emit(Event{Kind: "rejected", Digest: digest, Code: CodeStorage, Detail: err.Error()})
	return fail(CodeStorage, "executor state store unavailable")
}

func (a *Authority) deny(d canonical.Digest, host string, code Code, detail string) error {
	a.emit(Event{Kind: "denied", Digest: d.String(), Host: host, Code: code, Detail: detail})
	return &Error{Code: code, Detail: detail}
}

func (a *Authority) sessionActiveLocked(now time.Time) bool {
	return now.Before(a.sessionTill)
}

func (a *Authority) pendingCountLocked() int {
	n := 0
	for _, p := range a.permits {
		if p.State == StatePending {
			n++
		}
	}
	return n
}

// gcLocked drops pending permits whose approval window closed and approved
// permits whose request expired.
func (a *Authority) gcLocked(now time.Time) {
	for d, p := range a.permits {
		if p.State == StatePending && !now.Before(p.ApprovalExpiry) {
			delete(a.permits, d)
			continue
		}
		if !now.Before(time.Unix(p.Request.ExpiryUnix, 0)) {
			delete(a.permits, d)
		}
	}
	// Execution IDs stay in memory for the lifetime of the process and are
	// persisted in the store, so they stay spent across restarts.
}

func (a *Authority) emit(e Event) {
	if e.Time.IsZero() {
		e.Time = a.now()
	}
	a.audit(e)
}

func minTime(x, y time.Time) time.Time {
	if x.Before(y) {
		return x
	}
	return y
}

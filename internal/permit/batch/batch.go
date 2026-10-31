// SPDX-License-Identifier: AGPL-3.0-or-later

// Package batch holds volatile approval of complete canonical batch plans.
// It grants no execution rights: member claims, dispatch and stage gates must
// use their own checks in addition to Check. RPC adapters must connect Lock to
// the executor's lock lifecycle and authenticate CLI peer UIDs independently.
package batch

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	"github.com/nebula-operation-station/nebula-operation-station/internal/scanner"
	"github.com/nebula-operation-station/nebula-operation-station/internal/webauthnverify"
)

const challengeDomain = "nebula:batch-approval:v1\x00"

// MaxRetainedBytes bounds the parameter, canonical-plan and preview bytes all
// pending and approved batch plans keep in executor memory together, so
// unapproved proposals cannot exhaust it (review PR #128).
const MaxRetainedBytes = 64 << 20

var (
	// ErrCritical rejects the entire proposal when any member is CRITICAL.
	ErrCritical = errors.New("CRITICAL members cannot be approved in a batch")
	// ErrInvalidated means a trust or risk change permanently revoked this plan.
	ErrInvalidated = errors.New("batch trust or risk changed; propose a fresh plan")
	// ErrAdminRequired means the caller is not the configured executor-local admin.
	ErrAdminRequired = errors.New("batch approval requires the executor-local admin UID")
)

// CriticalError identifies every CRITICAL member in a rejected proposal.
// The caller must display these identities as text; none was approved.
type CriticalError struct{ MemberIDs []string }

func (e *CriticalError) Error() string { return fmt.Sprintf("%v: %v", ErrCritical, e.MemberIDs) }

// Unwrap permits errors.Is(err, ErrCritical).
func (e *CriticalError) Unwrap() error { return ErrCritical }

// MemberInput supplies the exact artifact bytes and bounded parameter document
// for one member, in plan order. Secrets must be opaque references only.
type MemberInput struct {
	MemberID       string
	Artifact       []byte
	ParametersJSON []byte
}

// Snapshot is an executor-owned member verdict. Trust is a nonzero opaque
// digest of the current trust tuple/generation, including withdrawn trust.
// It must change whenever the applicable trust changes, even at the same risk.
type Snapshot struct {
	Risk  canonical.Risk
	Trust canonical.Digest
}

// Policy reads executor-owned trust and minimum risk for exact member bindings.
// Implementations must ignore the proposed RiskClass as a source of authority,
// include provider trust where applicable, and fail closed on unavailable state.
// Evaluate may do I/O; the authority never holds its mutex while calling it.
type Policy interface {
	Evaluate(context.Context, canonical.BatchMember) (Snapshot, error)
}

// Options provides executor-owned dependencies. Session can be permit.Authority.Session.
// AdminUID must come from local configuration; transport code must obtain CLI
// peer UIDs from authenticated local peer credentials, never request fields.
type Options struct {
	Mode     permit.Mode
	Verifier *webauthnverify.Verifier
	Policy   Policy
	Session  func() (active bool, until time.Time)
	AdminUID uint32
	Now      func() time.Time
	Audit    func(permit.Event)
	// Scan runs the Safety Scanner. Default permit.ScanBounded, which shares
	// the executor-wide scan limit with ordinary proposals; tests may inject.
	Scan func(context.Context, []byte) ([]scanner.Finding, canonical.Risk, error)
}

// Approval is a detached, complete review copy. Parameters and Findings use
// the same member order as Plan. It is not a bearer token or a member permit.
// UI/CLI code must show the full plan and render all labels as untrusted text.
type Approval struct {
	Digest         canonical.Digest
	Plan           canonical.Batch
	Canonical      []byte
	Parameters     [][]byte
	Findings       [][]scanner.Finding
	Risk           canonical.Risk
	Requirement    permit.Requirement
	State          permit.State
	Challenge      []byte
	ApprovalExpiry time.Time
	ApprovedAt     time.Time
	ApprovedBy     string
}

type entry struct {
	approval  Approval
	snapshots []Snapshot
	failed    int
	size      int64
}

// Authority serializes batch approval transitions. Plans, challenges and
// approvals exist only in memory and are revoked by Lock and process restart.
// Callbacks other than Policy must not reenter the authority.
type Authority struct {
	mu      sync.Mutex
	options Options
	entries map[canonical.Digest]*entry
	seen    map[string]struct{}
	epoch   uint64
	// retained is the sum of entry.size over entries (MaxRetainedBytes).
	retained int64
}

// New creates an authority with no pending or approved plans.
func New(o Options) (*Authority, error) {
	if o.Mode != permit.ModeStandard && o.Mode != permit.ModeHardened {
		return nil, errors.New("batch: invalid approval mode")
	}
	if o.Verifier == nil || o.Policy == nil || o.Session == nil {
		return nil, errors.New("batch: verifier, policy and privileged session source are required")
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Audit == nil {
		o.Audit = func(permit.Event) {}
	}
	if o.Scan == nil {
		o.Scan = permit.ScanBounded
	}
	return &Authority{options: o, entries: map[canonical.Digest]*entry{}, seen: map[string]struct{}{}}, nil
}

func failure(code permit.Code, detail string) error { return &permit.Error{Code: code, Detail: detail} }

// Propose validates the entire bounded batch and its artifact/parameter bytes,
// derives member risk, then hashes and freezes the resulting complete plan.
// LOW-only approval requires a privileged session; other proposals may be
// reviewed without a session, but browser approval always requires one.
func (a *Authority) Propose(ctx context.Context, raw []byte, inputs []MemberInput) (Approval, error) {
	a.mu.Lock()
	epoch := a.epoch
	a.mu.Unlock()
	plan, _, _, err := canonical.ParseBatch(raw, a.options.Now())
	if err != nil {
		return Approval{}, failure(permit.CodeInvalidRequest, "invalid canonical batch")
	}
	if len(inputs) != len(plan.Members) {
		return Approval{}, failure(permit.CodeInvalidRequest, "every member needs its exact artifact and parameters")
	}
	// Refuse duplicates and over-capacity proposals before any scanning, so
	// they cannot consume scan slots (review PR #128).
	if err := a.admit(epoch, plan.BatchID); err != nil {
		return Approval{}, err
	}
	p := Approval{Plan: plan, Parameters: make([][]byte, len(inputs)), Findings: make([][]scanner.Finding, len(inputs)), Risk: canonical.RiskLow, State: permit.StatePending}
	snapshots := make([]Snapshot, len(inputs))
	var critical []string
	for i, m := range plan.Members {
		if err := ctx.Err(); err != nil {
			return Approval{}, fmt.Errorf("propose batch: %w", err)
		}
		in := inputs[i]
		if in.MemberID != m.MemberID {
			return Approval{}, failure(permit.CodeInvalidRequest, "member input order or identity differs from plan")
		}
		if len(in.Artifact) == 0 || len(in.Artifact) > permit.MaxArtifactSize {
			return Approval{}, failure(permit.CodeArtifactMismatch, "invalid member artifact size")
		}
		sum := sha256.Sum256(in.Artifact)
		if canonical.Digest(sum).String() != m.Request.ArtifactSHA256 {
			return Approval{}, failure(permit.CodeArtifactMismatch, "member artifact hash differs from plan")
		}
		params, hash, err := canonical.CanonicalParameters(in.ParametersJSON)
		if err != nil || hash != m.Request.ParametersHash {
			return Approval{}, failure(permit.CodeParametersMismatch, "member parameters differ from plan")
		}
		refs, err := permit.SecretRefs(params)
		if err != nil {
			return Approval{}, failure(permit.CodeInvalidRequest, "invalid opaque secret references")
		}
		snapshot, err := a.evaluate(ctx, m)
		if err != nil {
			return Approval{}, err
		}
		snapshots[i] = snapshot
		findings, scanRisk, err := a.options.Scan(ctx, in.Artifact)
		if err != nil {
			return Approval{}, fmt.Errorf("propose batch: %w", err)
		}
		risk := canonical.MaxRisk(m.Request.RiskClass, canonical.MaxRisk(snapshot.Risk, scanRisk))
		if len(refs) > 0 {
			risk = canonical.MaxRisk(risk, canonical.RiskMedium)
		}
		plan.Members[i].Request.RiskClass = risk
		p.Parameters[i] = params
		p.Findings[i] = findings
		p.Risk = canonical.MaxRisk(p.Risk, risk)
		if risk == canonical.RiskCritical {
			critical = append(critical, m.MemberID)
		}
	}
	if len(critical) > 0 {
		return Approval{}, &CriticalError{MemberIDs: critical}
	}
	if p.Risk == canonical.RiskHigh {
		for _, stage := range plan.StagePlan.Stages {
			if stage.Gate == canonical.BatchGateAutomatic {
				return Approval{}, failure(permit.CodeStagePlan, "HIGH batch stages require manual gates")
			}
		}
	}
	plan, canon, digest, err := canonical.CanonicalizeBatch(plan, a.options.Now())
	if err != nil {
		return Approval{}, failure(permit.CodeInvalidRequest, "invalid derived batch")
	}
	p.Plan = plan
	p.Canonical = canon
	p.Digest = digest
	p.Requirement = permit.RequirementFor(p.Risk, a.options.Mode)
	now := a.options.Now()
	p.ApprovalExpiry = now.Add(permit.ApprovalWindow)
	if expiry := time.Unix(plan.ExpiryUnix, 0); expiry.Before(p.ApprovalExpiry) {
		p.ApprovalExpiry = expiry
	}
	if p.Requirement != permit.RequireNone && p.Requirement != permit.RequireCLI {
		var nonce [32]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return Approval{}, fmt.Errorf("batch approval nonce: %w", err)
		}
		p.Challenge = challengeFor(digest, nonce[:], p.ApprovalExpiry)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if epoch != a.epoch {
		return Approval{}, failure(permit.CodeWrongState, "executor locked during proposal")
	}
	a.gcLocked()
	if _, ok := a.seen[plan.BatchID]; ok {
		return Approval{}, failure(permit.CodeWrongState, "batch ID already proposed; use a fresh plan")
	}
	if len(a.entries) >= permit.MaxPending || len(a.seen) >= permit.MaxExecutionIDs {
		return Approval{}, failure(permit.CodeLimit, "batch approval capacity reached")
	}
	if p.Requirement == permit.RequireNone {
		if !a.sessionActive() {
			return Approval{}, failure(permit.CodeSessionRequired, "LOW batch requires a privileged session")
		}
		p.State = permit.StateApproved
		p.ApprovedAt = a.options.Now()
		p.ApprovedBy = "privileged-session"
	}
	size := retainedSize(p)
	if a.retained+size > MaxRetainedBytes {
		return Approval{}, failure(permit.CodeLimit, "batch approval memory budget reached")
	}
	e := &entry{approval: p, snapshots: snapshots, size: size}
	a.entries[digest] = e
	a.retained += size
	a.seen[plan.BatchID] = struct{}{}
	a.emit("batch_proposed", digest, "", "")
	if p.State == permit.StateApproved {
		a.emit("batch_approved", digest, "", p.ApprovedBy)
	}
	return cloneApproval(p), nil
}

// admit checks, before the expensive per-member work, that the batch ID is
// fresh and that capacity remains. Propose repeats the check under the same
// lock when it stores the plan.
func (a *Authority) admit(epoch uint64, batchID string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if epoch != a.epoch {
		return failure(permit.CodeWrongState, "executor locked during proposal")
	}
	a.gcLocked()
	if _, ok := a.seen[batchID]; ok {
		return failure(permit.CodeWrongState, "batch ID already proposed; use a fresh plan")
	}
	if len(a.entries) >= permit.MaxPending || len(a.seen) >= permit.MaxExecutionIDs || a.retained >= MaxRetainedBytes {
		return failure(permit.CodeLimit, "batch approval capacity reached")
	}
	return nil
}

// removeLocked drops an entry and returns its bytes to the budget.
func (a *Authority) removeLocked(d canonical.Digest) {
	if e, ok := a.entries[d]; ok {
		a.retained -= e.size
		delete(a.entries, d)
	}
}

// retainedSize is the memory an approval keeps: parameters, canonical plan
// and finding texts.
func retainedSize(p Approval) int64 {
	n := int64(len(p.Canonical) + len(p.Challenge))
	for _, b := range p.Parameters {
		n += int64(len(b))
	}
	for _, fs := range p.Findings {
		for _, f := range fs {
			n += int64(len(f.Category) + len(f.Excerpt) + 64)
		}
	}
	return n
}

func challengeFor(d canonical.Digest, nonce []byte, expiry time.Time) []byte {
	var exp [8]byte
	binary.BigEndian.PutUint64(exp[:], uint64(expiry.Unix()))
	h := sha256.New()
	h.Write([]byte(challengeDomain))
	h.Write(d[:])
	h.Write(nonce)
	h.Write(exp[:])
	return h.Sum(nil)
}

func (a *Authority) evaluate(ctx context.Context, m canonical.BatchMember) (Snapshot, error) {
	s, err := a.options.Policy.Evaluate(ctx, cloneMember(m))
	if err != nil || s.Risk.Rank() == 0 || s.Trust == (canonical.Digest{}) {
		return Snapshot{}, failure(permit.CodeStorage, "executor trust/risk state unavailable")
	}
	return s, nil
}

func (a *Authority) sessionActive() bool {
	active, until := a.options.Session()
	return active && a.options.Now().Before(until)
}

func (a *Authority) getLocked(d canonical.Digest, state permit.State) (*entry, error) {
	e, ok := a.entries[d]
	if !ok {
		return nil, failure(permit.CodeNotFound, "batch approval not found")
	}
	p := &e.approval
	now := a.options.Now()
	if !now.Before(time.Unix(p.Plan.ExpiryUnix, 0)) || (p.State == permit.StatePending && !now.Before(p.ApprovalExpiry)) {
		a.removeLocked(d)
		a.emit("batch_expired", d, permit.CodeExpired, "")
		return nil, failure(permit.CodeExpired, "batch approval expired")
	}
	if state != 0 && p.State != state {
		return nil, failure(permit.CodeWrongState, "batch approval is in the wrong state")
	}
	return e, nil
}

// freshLocked releases the mutex for executor state I/O, then revalidates the
// live object, state and expiry. The caller always regains the mutex.
func (a *Authority) freshLocked(ctx context.Context, d canonical.Digest, e *entry, state permit.State) error {
	var changed bool
	var checkErr error
	func() {
		a.mu.Unlock()
		defer a.mu.Lock()
		for i, m := range e.approval.Plan.Members {
			if err := ctx.Err(); err != nil {
				checkErr = fmt.Errorf("check batch: %w", err)
				return
			}
			s, err := a.evaluate(ctx, m)
			if err != nil {
				checkErr = err
				return
			}
			if s != e.snapshots[i] {
				changed = true
			}
		}
	}()
	live, err := a.getLocked(d, 0)
	if err != nil {
		return err
	}
	if live != e {
		return failure(permit.CodeWrongState, "batch changed during approval")
	}
	if changed {
		a.removeLocked(d)
		a.emit("batch_invalidated", d, permit.CodeRiskAboveApproval, "")
		return ErrInvalidated
	}
	// A concurrent approval must not hide an observed trust or risk change.
	if state != 0 && live.approval.State != state {
		return failure(permit.CodeWrongState, "batch approval is in the wrong state")
	}
	if checkErr != nil {
		a.emit("batch_denied", d, permit.CodeStorage, "")
		return checkErr
	}
	return nil
}

// SubmitAssertion approves the complete batch with exactly one assertion.
// Normal verifier RP/origin, presence/UV and durable counter checks apply.
func (a *Authority) SubmitAssertion(ctx context.Context, d canonical.Digest, assertionJSON []byte) (Approval, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	e, err := a.getLocked(d, permit.StatePending)
	if err != nil {
		return Approval{}, err
	}
	p := &e.approval
	if p.Requirement == permit.RequireCLI {
		return Approval{}, failure(permit.CodeCLIRequired, "hardened HIGH batch requires nebula approve")
	}
	if !a.sessionActive() {
		return Approval{}, failure(permit.CodeSessionRequired, "browser batch approval requires a privileged session")
	}
	if err := a.freshLocked(ctx, d, e, permit.StatePending); err != nil {
		return Approval{}, err
	}
	// Session expiry or lock while executor state was read cannot be bypassed.
	if !a.sessionActive() {
		return Approval{}, failure(permit.CodeSessionRequired, "browser batch approval requires a privileged session")
	}
	credID, err := a.options.Verifier.Verify(assertionJSON, p.Challenge, webauthnverify.Requirement{UserVerification: p.Requirement == permit.RequireAssertionVerified})
	if errors.Is(err, webauthnverify.ErrCounterStore) {
		return Approval{}, failure(permit.CodeStorage, "assertion counter store unavailable")
	}
	if err != nil {
		e.failed++
		if e.failed >= permit.MaxFailedAssertions {
			a.removeLocked(d)
		}
		a.emit("batch_rejected", d, permit.CodeAssertionRejected, "")
		return Approval{}, failure(permit.CodeAssertionRejected, "batch assertion rejected")
	}
	if _, err := a.getLocked(d, permit.StatePending); err != nil {
		return Approval{}, err
	}
	if !a.sessionActive() {
		return Approval{}, failure(permit.CodeSessionRequired, "browser batch approval requires a privileged session")
	}
	return a.approveLocked(e, "webauthn:"+hex.EncodeToString(credID)), nil
}

// ReviewCLI retrieves every frozen member, parameters and scanner findings for
// an authenticated executor-local admin. The CLI must display all of it before
// confirming; no browser session is necessary. Text escaping belongs to the UI.
func (a *Authority) ReviewCLI(ctx context.Context, d canonical.Digest, peerUID uint32) (Approval, error) {
	if peerUID != a.options.AdminUID {
		return Approval{}, ErrAdminRequired
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	e, err := a.getLocked(d, 0)
	if err != nil {
		return Approval{}, err
	}
	if err := a.freshLocked(ctx, d, e, 0); err != nil {
		return Approval{}, err
	}
	return cloneApproval(e.approval), nil
}

// ApproveCLI confirms the frozen digest as an authenticated local admin, after
// ReviewCLI's full executor-owned view. It needs no privileged browser session.
func (a *Authority) ApproveCLI(ctx context.Context, d canonical.Digest, peerUID uint32) (Approval, error) {
	if peerUID != a.options.AdminUID {
		return Approval{}, ErrAdminRequired
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	e, err := a.getLocked(d, permit.StatePending)
	if err != nil {
		return Approval{}, err
	}
	if err := a.freshLocked(ctx, d, e, permit.StatePending); err != nil {
		return Approval{}, err
	}
	return a.approveLocked(e, "cli:"+strconv.FormatUint(uint64(peerUID), 10)), nil
}

func (a *Authority) approveLocked(e *entry, who string) Approval {
	p := &e.approval
	p.State = permit.StateApproved
	p.Challenge = nil
	p.ApprovedAt = a.options.Now()
	p.ApprovedBy = who
	a.emit("batch_approved", p.Digest, "", p.ApprovedBy)
	return cloneApproval(*p)
}

// Check rechecks every member's trust and risk against the frozen snapshot.
// Any change revokes the entire batch permanently, including remaining members.
// This is an approval check only: dispatch must additionally claim an exact
// member once and enforce credentials, pins, parameters and stage conditions.
func (a *Authority) Check(ctx context.Context, d canonical.Digest) (Approval, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	e, err := a.getLocked(d, permit.StateApproved)
	if err != nil {
		return Approval{}, err
	}
	if err := a.freshLocked(ctx, d, e, permit.StateApproved); err != nil {
		return Approval{}, err
	}
	return cloneApproval(e.approval), nil
}

// Lock revokes all pending and approved batches, including in-flight approvals.
// The executor lifecycle adapter must call it whenever the executor locks.
func (a *Authority) Lock() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.epoch++
	clear(a.entries)
	a.retained = 0
	a.emit("batch_locked", canonical.Digest{}, "", "")
}

func (a *Authority) gcLocked() {
	now := a.options.Now()
	for d, e := range a.entries {
		p := e.approval
		if !now.Before(time.Unix(p.Plan.ExpiryUnix, 0)) || (p.State == permit.StatePending && !now.Before(p.ApprovalExpiry)) {
			a.removeLocked(d)
		}
	}
}

func (a *Authority) emit(kind string, d canonical.Digest, code permit.Code, detail string) {
	a.options.Audit(permit.Event{Time: a.options.Now(), Kind: kind, Digest: d.String(), Code: code, Detail: detail})
}

func cloneMember(m canonical.BatchMember) canonical.BatchMember {
	m.Request.CredentialRefs = slices.Clone(m.Request.CredentialRefs)
	m.Request.ResolvedTargets = slices.Clone(m.Request.ResolvedTargets)
	m.CredentialVersions = slices.Clone(m.CredentialVersions)
	m.PreconditionHashes = slices.Clone(m.PreconditionHashes)
	if m.Container != nil {
		c := *m.Container
		m.Container = &c
	}
	if m.ProviderTarget != nil {
		p := *m.ProviderTarget
		p.APIEndpoints = slices.Clone(p.APIEndpoints)
		m.ProviderTarget = &p
	}
	return m
}

func cloneApproval(p Approval) Approval {
	p.Canonical = bytes.Clone(p.Canonical)
	p.Challenge = bytes.Clone(p.Challenge)
	p.Parameters = slices.Clone(p.Parameters)
	p.Findings = slices.Clone(p.Findings)
	for i := range p.Parameters {
		p.Parameters[i] = bytes.Clone(p.Parameters[i])
		p.Findings[i] = slices.Clone(p.Findings[i])
	}
	p.Plan.Members = slices.Clone(p.Plan.Members)
	for i, m := range p.Plan.Members {
		p.Plan.Members[i] = cloneMember(m)
	}
	p.Plan.StagePlan.Stages = slices.Clone(p.Plan.StagePlan.Stages)
	for i, s := range p.Plan.StagePlan.Stages {
		s.MemberIDs = slices.Clone(s.MemberIDs)
		s.RequiredPostchecks = slices.Clone(s.RequiredPostchecks)
		p.Plan.StagePlan.Stages[i] = s
	}
	p.Plan.StagePlan.Dependencies = slices.Clone(p.Plan.StagePlan.Dependencies)
	for i := range p.Plan.StagePlan.Dependencies {
		p.Plan.StagePlan.Dependencies[i].DependsOn = slices.Clone(p.Plan.StagePlan.Dependencies[i].DependsOn)
	}
	return p
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package batch

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	"github.com/nebula-operation-station/nebula-operation-station/internal/webauthnverify"
)

// Batch member-gate codes (ADR 0007 E12). The stage/stop/abort/gate codes are
// shared with the host stage engine; these two are batch-specific.
const (
	// CodeDependencyNotMet means a member's dependency is not satisfied.
	CodeDependencyNotMet permit.Code = "batch_dependency_not_met"
	// CodeHostBusy means another member is running on the same host.
	CodeHostBusy permit.Code = "batch_host_busy"
)

const batchGateDomain = "nebula:batch-gate:v1\x00"

// GateKind is what a batch gate does.
type GateKind string

const (
	// GateOpenStage opens the next stage after the open one passed.
	GateOpenStage GateKind = "open_stage"
	// GateSkipMember skips one member of the open stage (audited).
	GateSkipMember GateKind = "skip_member"
)

// Gate is one batch gate decision. Stage is the 1-based next stage for
// GateOpenStage and must be 0 for GateSkipMember; MemberID is the member to
// skip for GateSkipMember and must be empty for GateOpenStage.
type Gate struct {
	Kind     GateKind
	Stage    int
	MemberID string
}

// String renders the gate for audit and error text.
func (g Gate) String() string {
	if g.Kind == GateSkipMember {
		return "skip " + g.MemberID
	}
	return fmt.Sprintf("open stage %d", g.Stage)
}

// GateChallenge is what a batch gate needs before it can be committed. LOW and
// MEDIUM gates need only an active privileged session; HIGH gates carry a
// challenge bound to the batch digest and stage number.
type GateChallenge struct {
	Requirement permit.Requirement
	Challenge   []byte
	Expiry      time.Time
}

// BatchStageView is one stage of a batch rollout, for review and display.
type BatchStageView struct {
	StageID  string
	Open     bool
	Passed   bool
	Outcomes map[string]permit.Outcome
}

// MemberRollout is the stage state of an approved batch: which stage is open,
// whether the rollout stopped or was aborted, the gate requirement, and each
// stage's member outcomes.
type MemberRollout struct {
	Open            int
	Stopped         string
	Aborted         bool
	GateRequirement permit.Requirement
	Stages          []BatchStageView
}

// memberRollout is the stage state of an approved batch: which stage is open,
// each member's outcome and postchecks, dependencies, and same-host ordering.
// It extends the host stage engine (ADR 0007) from host to member so several
// actions on one host cannot bypass ordering or reuse one another's permit.
type memberRollout struct {
	plan       []canonical.BatchStage
	stageOf    map[string]int
	deps       map[string][]string
	open       int
	outcome    map[string]permit.Outcome
	postchecks map[string]map[string]bool
	inFlight   map[string]bool
	hostBusy   map[string]string
	stopped    string
	aborted    bool
	gate       *pendingBatchGate
}

// pendingBatchGate is the in-flight HIGH gate challenge, bound to the exact
// gate decision that began it.
type pendingBatchGate struct {
	gate      Gate
	challenge []byte
	expiry    time.Time
}

// batchExecRef binds a claimed member's execution ID to its batch, member and
// ordering key, so outcomes and postchecks can be recorded by execution ID.
type batchExecRef struct {
	digest   canonical.Digest
	memberID string
	hostKey  string
}

// newMemberRollout builds the rollout state from the approved plan: the stage
// of every member and every dependency edge.
func newMemberRollout(plan *canonical.Batch) *memberRollout {
	r := &memberRollout{
		plan:       slices.Clone(plan.StagePlan.Stages),
		stageOf:    map[string]int{},
		deps:       map[string][]string{},
		outcome:    map[string]permit.Outcome{},
		postchecks: map[string]map[string]bool{},
		inFlight:   map[string]bool{},
		hostBusy:   map[string]string{},
	}
	for i, st := range plan.StagePlan.Stages {
		for _, mid := range st.MemberIDs {
			r.stageOf[mid] = i
		}
	}
	for _, dep := range plan.StagePlan.Dependencies {
		r.deps[dep.MemberID] = append(r.deps[dep.MemberID], dep.DependsOn...)
	}
	return r
}

// memberHostKey is the ordering key for a member: the physical resource it
// acts on. SSH members key by host; provider members key by the node and VM
// they run on, so two members on the same host or the same VM never run at
// once, while different hosts and VMs may.
func memberHostKey(m canonical.BatchMember) string {
	if p := m.ProviderTarget; p != nil {
		return fmt.Sprintf("node:%s:%s:%d", p.RemoteID, p.Node, p.VMID)
	}
	if len(m.Request.ResolvedTargets) > 0 {
		return "ssh:" + m.Request.ResolvedTargets[0].HostID
	}
	return "member:" + m.MemberID
}

// memberStats counts a stage's member outcomes.
type memberStats struct{ succeeded, failed, unreachable, skipped, done int }

// stats counts the outcomes of stage i.
func (r *memberRollout) stats(i int) memberStats {
	var st memberStats
	for _, mid := range r.plan[i].MemberIDs {
		switch r.outcome[mid] {
		case permit.OutcomeSucceeded:
			st.succeeded++
		case permit.OutcomeFailed:
			st.failed++
		case permit.OutcomeUnreachable:
			st.unreachable++
		case permit.OutcomeSkipped:
			st.skipped++
		default:
			continue
		}
		st.done++
	}
	return st
}

// stagePostchecksOK reports whether every required postcheck of stage i was
// recorded by some member of the stage.
func (r *memberRollout) stagePostchecksOK(i int) bool {
	for _, hash := range r.plan[i].RequiredPostchecks {
		ok := false
		for _, mid := range r.plan[i].MemberIDs {
			if r.postchecks[mid][hash] {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

// passed reports whether stage i is complete, within its thresholds, and has
// all its required postchecks.
func (r *memberRollout) passed(i int) (bool, string) {
	st, plan := r.stats(i), r.plan[i]
	switch {
	case st.done < len(plan.MemberIDs):
		return false, fmt.Sprintf("stage %s: %d members have no outcome yet", plan.StageID, len(plan.MemberIDs)-st.done)
	case st.failed > plan.FailureThreshold:
		return false, fmt.Sprintf("stage %s: %d members failed, at most %d allowed", plan.StageID, st.failed, plan.FailureThreshold)
	case st.unreachable > plan.UnreachableThreshold:
		return false, fmt.Sprintf("stage %s: %d members unreachable, at most %d allowed", plan.StageID, st.unreachable, plan.UnreachableThreshold)
	case !r.stagePostchecksOK(i):
		return false, fmt.Sprintf("stage %s: required postchecks not satisfied", plan.StageID)
	}
	return true, ""
}

// depSatisfied reports whether a dependency is satisfied: the dependency
// succeeded and its stage's required postchecks are met. Skipping never
// satisfies a dependency.
func (r *memberRollout) depSatisfied(dep string) bool {
	if r.outcome[dep] != permit.OutcomeSucceeded {
		return false
	}
	return r.stagePostchecksOK(r.stageOf[dep])
}

// dependenciesMet reports whether every dependency of memberID is satisfied.
func (r *memberRollout) dependenciesMet(memberID string) (bool, string) {
	for _, dep := range r.deps[memberID] {
		if !r.depSatisfied(dep) {
			return false, fmt.Sprintf("dependency %s is not satisfied", dep)
		}
	}
	return true, ""
}

// evaluateLocked stops the rollout when an open stage has more failures than
// allowed, and opens the next stage when the open one passed and continues
// automatically. The caller holds a.mu.
func (a *Authority) evaluateLocked(e *entry) {
	r := e.rollout
	for !r.aborted && r.stopped == "" {
		for i := 0; i <= r.open; i++ {
			if st := r.stats(i); st.failed > r.plan[i].FailureThreshold {
				r.stopped = fmt.Sprintf("stage %s: %d members failed, at most %d allowed", r.plan[i].StageID, st.failed, r.plan[i].FailureThreshold)
				a.emit("stage_failed", e.approval.Digest, permit.CodeRolloutStopped, r.stopped)
				return
			}
		}
		plan := r.plan[r.open]
		ok, _ := r.passed(r.open)
		if !ok || r.open+1 >= len(r.plan) {
			return
		}
		if plan.Gate != canonical.BatchGateAutomatic {
			a.emit("stage_passed", e.approval.Digest, "", "stage "+plan.StageID+": waiting at the gate")
			return
		}
		r.open++
		a.emit("stage_opened", e.approval.Digest, "", fmt.Sprintf("stage %d (%s), automatic", r.open+1, r.plan[r.open].StageID))
	}
}

// checkMemberGatesLocked enforces the batch stage, dependency and same-host
// ordering gates for a member claim (ADR 0007 E12): a member behind an
// unopened stage gate, with an unsatisfied dependency, or on a host where
// another member is running is not claimable. The caller holds a.mu.
func (a *Authority) checkMemberGatesLocked(e *entry, m canonical.BatchMember) error {
	r := e.rollout
	if r == nil {
		return failure(permit.CodeWrongState, "batch has no rollout")
	}
	switch {
	case r.aborted:
		return a.deny(e.approval.Digest, m.MemberID, permit.CodeRolloutAborted, "rollout aborted")
	case r.stopped != "":
		return a.deny(e.approval.Digest, m.MemberID, permit.CodeRolloutStopped, r.stopped)
	}
	if r.stageOf[m.MemberID] > r.open {
		return a.deny(e.approval.Digest, m.MemberID, permit.CodeStageNotOpen, fmt.Sprintf("member is in stage %d, stage %d is open", r.stageOf[m.MemberID]+1, r.open+1))
	}
	if ok, why := r.dependenciesMet(m.MemberID); !ok {
		return a.deny(e.approval.Digest, m.MemberID, CodeDependencyNotMet, why)
	}
	hk := memberHostKey(m)
	for busyKey, busy := range r.hostBusy {
		if hostKeysConflict(hk, busyKey) {
			return a.deny(e.approval.Digest, m.MemberID, CodeHostBusy, fmt.Sprintf("member %s is running on the same host", busy))
		}
	}
	return nil
}

// hostKeysConflict reports whether two ordering keys name overlapping
// physical resources. Equal keys always conflict. Provider keys on the same
// remote and node also conflict when either acts on the node itself (VMID 0,
// for example a node reboot) — a node action must not run while one of its
// guests is being changed, and vice versa (review PR #142).
func hostKeysConflict(a, b string) bool {
	if a == b {
		return true
	}
	ra, na, va, oka := parseNodeKey(a)
	rb, nb, vb, okb := parseNodeKey(b)
	return oka && okb && ra == rb && na == nb && (va == 0 || vb == 0)
}

// parseNodeKey splits a provider ordering key "node:<remote>:<node>:<vmid>".
func parseNodeKey(k string) (remote, node string, vmid uint64, ok bool) {
	rest, found := strings.CutPrefix(k, "node:")
	if !found {
		return "", "", 0, false
	}
	i := strings.LastIndexByte(rest, ':')
	if i < 0 {
		return "", "", 0, false
	}
	v, err := strconv.ParseUint(rest[i+1:], 10, 32)
	if err != nil {
		return "", "", 0, false
	}
	head := rest[:i]
	j := strings.IndexByte(head, ':')
	if j < 0 {
		return "", "", 0, false
	}
	return head[:j], head[j+1:], v, true
}

// deny records an audit event and returns the failure.
func (a *Authority) deny(d canonical.Digest, memberID string, code permit.Code, detail string) error {
	a.emit("member_denied", d, code, memberID+": "+detail)
	return failure(code, detail)
}

// gateRequirement is the requirement for a batch gate: LOW and MEDIUM gates
// are a privileged-session click; HIGH gates are fresh UV (CLI in hardened
// mode). This mirrors the host stage engine's gate requirement.
func (a *Authority) gateRequirement(p *Approval) permit.Requirement {
	switch p.Risk {
	case canonical.RiskLow, canonical.RiskMedium:
		return permit.RequireNone
	}
	if a.options.Mode == permit.ModeHardened {
		return permit.RequireCLI
	}
	return permit.RequireAssertionVerified
}

// batchGateChallengeFor binds a batch gate challenge to the batch digest, gate
// kind, stage number, member, nonce and expiry (ADR 0007: fresh UV bound to
// batch digest and stage number).
func batchGateChallengeFor(d canonical.Digest, g Gate, expiry time.Time) ([]byte, error) {
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, fmt.Errorf("batch gate nonce: %w", err)
	}
	var stage [4]byte
	binary.BigEndian.PutUint32(stage[:], uint32(g.Stage))
	var exp [8]byte
	binary.BigEndian.PutUint64(exp[:], uint64(expiry.Unix()))
	h := sha256.New()
	h.Write([]byte(batchGateDomain))
	h.Write(d[:])
	h.Write([]byte(string(g.Kind) + "\x00"))
	h.Write(stage[:])
	h.Write([]byte(g.MemberID + "\x00"))
	h.Write(nonce[:])
	h.Write(exp[:])
	return h.Sum(nil), nil
}

// checkGateLocked validates a batch gate decision against the rollout state.
// The caller holds a.mu.
func (a *Authority) checkGateLocked(r *memberRollout, g Gate) error {
	switch {
	case r.aborted:
		return failure(permit.CodeRolloutAborted, "rollout aborted")
	case r.stopped != "":
		return failure(permit.CodeRolloutStopped, r.stopped)
	}
	switch g.Kind {
	case GateOpenStage:
		if g.MemberID != "" || g.Stage != r.open+2 || g.Stage > len(r.plan) {
			return failure(permit.CodeGateInvalid, fmt.Sprintf("the next stage is %d of %d", r.open+2, len(r.plan)))
		}
		if ok, why := r.passed(r.open); !ok {
			return failure(permit.CodeStageNotDone, why)
		}
	case GateSkipMember:
		i, in := r.stageOf[g.MemberID]
		switch {
		case g.Stage != 0 || !in:
			return failure(permit.CodeGateInvalid, fmt.Sprintf("member %q is not in the plan", g.MemberID))
		case i > r.open:
			return failure(permit.CodeStageNotOpen, fmt.Sprintf("member is in stage %d, stage %d is open", i+1, r.open+1))
		case r.outcome[g.MemberID] != permit.OutcomeNone && r.outcome[g.MemberID] != permit.OutcomeUnreachable:
			return failure(permit.CodeGateInvalid, fmt.Sprintf("member %q already has the outcome %s", g.MemberID, r.outcome[g.MemberID]))
		case r.inFlight[g.MemberID]:
			return failure(permit.CodeGateInvalid, fmt.Sprintf("member %q is running", g.MemberID))
		}
	default:
		return failure(permit.CodeGateInvalid, "unknown gate")
	}
	return nil
}

// applyGateLocked applies a validated batch gate and re-evaluates the rollout.
// The caller holds a.mu.
func (a *Authority) applyGateLocked(e *entry, g Gate, by string) {
	r := e.rollout
	switch g.Kind {
	case GateOpenStage:
		r.open = g.Stage - 1
		a.emit("stage_opened", e.approval.Digest, "", fmt.Sprintf("stage %d (%s) by %s", g.Stage, r.plan[r.open].StageID, by))
	case GateSkipMember:
		r.outcome[g.MemberID] = permit.OutcomeSkipped
		delete(r.inFlight, g.MemberID)
		a.emit("member_skipped", e.approval.Digest, "", g.MemberID+" by "+by)
	}
	a.evaluateLocked(e)
}

// RecordOutcome records a member's final outcome by its single-use execution
// ID and re-evaluates the rollout. Outcomes are idempotent: a member with a
// final outcome is not overwritten, and unknown or mismatched IDs are ignored.
func (a *Authority) RecordOutcome(executionID, memberID string, o permit.Outcome) {
	a.mu.Lock()
	defer a.mu.Unlock()
	ref, ok := a.batchExecIndex[executionID]
	if !ok || ref.memberID != memberID {
		return
	}
	e, err := a.getLocked(ref.digest, permit.StateApproved)
	if err != nil || e.rollout == nil {
		return
	}
	r := e.rollout
	if _, in := r.stageOf[memberID]; !in || o == permit.OutcomeNone || o == permit.OutcomeSkipped {
		return
	}
	if cur := r.outcome[memberID]; cur != permit.OutcomeNone && cur != permit.OutcomeUnreachable {
		return
	}
	r.outcome[memberID] = o
	delete(r.inFlight, memberID)
	delete(r.hostBusy, ref.hostKey)
	a.emit("outcome", ref.digest, "", memberID+":"+string(o))
	a.evaluateLocked(e)
}

// RecordPostcheck records a postcheck for a member by its single-use execution
// ID and re-evaluates the rollout. Unknown or mismatched IDs are ignored.
func (a *Authority) RecordPostcheck(executionID, memberID, hash string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	ref, ok := a.batchExecIndex[executionID]
	if !ok || ref.memberID != memberID {
		return
	}
	e, err := a.getLocked(ref.digest, permit.StateApproved)
	if err != nil || e.rollout == nil {
		return
	}
	r := e.rollout
	if _, in := r.stageOf[memberID]; !in {
		return
	}
	if r.postchecks[memberID] == nil {
		r.postchecks[memberID] = map[string]bool{}
	}
	r.postchecks[memberID][hash] = true
	a.emit("postcheck", ref.digest, "", memberID+":"+hash)
	a.evaluateLocked(e)
}

// BeginGate checks that a batch gate is applicable and returns what it needs.
// A HIGH gate returns a challenge bound to the batch digest and stage number;
// LOW and MEDIUM gates return only the session requirement.
func (a *Authority) BeginGate(d canonical.Digest, g Gate) (GateChallenge, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	e, err := a.getLocked(d, permit.StateApproved)
	if err != nil {
		return GateChallenge{}, err
	}
	if e.rollout == nil {
		return GateChallenge{}, failure(permit.CodeWrongState, "batch has no rollout")
	}
	if err := a.checkGateLocked(e.rollout, g); err != nil {
		return GateChallenge{}, err
	}
	req := a.gateRequirement(&e.approval)
	out := GateChallenge{Requirement: req}
	if req == permit.RequireAssertionVerified {
		exp := minTime(a.options.Now().Add(permit.ApprovalWindow), time.Unix(e.approval.Plan.ExpiryUnix, 0))
		ch, err := batchGateChallengeFor(d, g, exp)
		if err != nil {
			return GateChallenge{}, err
		}
		e.rollout.gate = &pendingBatchGate{gate: g, challenge: ch, expiry: exp}
		out.Challenge, out.Expiry = slices.Clone(ch), exp
	}
	return out, nil
}

// CommitGate applies a batch gate from the web UI. LOW and MEDIUM gates need
// an active privileged session; HIGH gates need a fresh WebAuthn assertion
// bound to the batch digest and stage number (CLI in hardened mode).
func (a *Authority) CommitGate(ctx context.Context, d canonical.Digest, g Gate, assertionJSON []byte) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	e, err := a.getLocked(d, permit.StateApproved)
	if err != nil {
		return err
	}
	if e.rollout == nil {
		return failure(permit.CodeWrongState, "batch has no rollout")
	}
	if !a.sessionActive() {
		return a.gateReject(e, g, permit.CodeSessionRequired, "a gate needs an active privileged session")
	}
	if err := a.checkGateLocked(e.rollout, g); err != nil {
		a.emit("rejected", d, permit.CodeOf(err), g.String()+": "+err.Error())
		return err
	}
	switch a.gateRequirement(&e.approval) {
	case permit.RequireCLI:
		return a.gateReject(e, g, permit.CodeCLIRequired, "hardened mode: use nebula approve --stage or --skip")
	case permit.RequireNone:
		a.applyGateLocked(e, g, "privileged-session")
		return nil
	}
	pg := e.rollout.gate
	e.rollout.gate = nil
	if pg == nil || pg.gate != g {
		return a.gateReject(e, g, permit.CodeNoChallenge, "call BeginGate for this gate first")
	}
	if !a.options.Now().Before(pg.expiry) {
		return a.gateReject(e, g, permit.CodeExpired, "gate challenge expired")
	}
	credID, err := a.options.Verifier.Verify(assertionJSON, pg.challenge, webauthnverify.Requirement{UserVerification: true})
	if errors.Is(err, webauthnverify.ErrCounterStore) {
		return failure(permit.CodeStorage, "assertion counter store unavailable")
	}
	if err != nil {
		return a.gateReject(e, g, permit.CodeAssertionRejected, err.Error())
	}
	a.applyGateLocked(e, g, "webauthn:"+hex.EncodeToString(credID))
	return nil
}

// ApproveGateCLI applies a batch gate from the hardened CLI as the
// executor-local admin.
func (a *Authority) ApproveGateCLI(d canonical.Digest, g Gate, peerUID uint32) error {
	if peerUID != a.options.AdminUID {
		return ErrAdminRequired
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	e, err := a.getLocked(d, permit.StateApproved)
	if err != nil {
		return err
	}
	if e.rollout == nil {
		return failure(permit.CodeWrongState, "batch has no rollout")
	}
	if err := a.checkGateLocked(e.rollout, g); err != nil {
		return err
	}
	a.applyGateLocked(e, g, "cli:"+strconv.FormatUint(uint64(peerUID), 10))
	return nil
}

// Abort stops the rollout: no further member is claimable and no gate applies.
func (a *Authority) Abort(d canonical.Digest, who string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	e, err := a.getLocked(d, permit.StateApproved)
	if err != nil {
		return err
	}
	if e.rollout == nil {
		return failure(permit.CodeWrongState, "batch has no rollout")
	}
	if !e.rollout.aborted {
		e.rollout.aborted = true
		e.rollout.gate = nil
		a.emit("aborted", d, "", "by "+who)
	}
	return nil
}

// Rollout returns the stage state of an approved batch.
func (a *Authority) Rollout(d canonical.Digest) (MemberRollout, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	e, err := a.getLocked(d, permit.StateApproved)
	if err != nil {
		return MemberRollout{}, err
	}
	if e.rollout == nil {
		return MemberRollout{}, failure(permit.CodeWrongState, "batch has no rollout")
	}
	r := e.rollout
	out := MemberRollout{Open: r.open, Stopped: r.stopped, Aborted: r.aborted, GateRequirement: a.gateRequirement(&e.approval)}
	for i, st := range r.plan {
		sv := BatchStageView{StageID: st.StageID, Open: i <= r.open, Outcomes: map[string]permit.Outcome{}}
		sv.Passed, _ = r.passed(i)
		for _, mid := range st.MemberIDs {
			if o := r.outcome[mid]; o != permit.OutcomeNone {
				sv.Outcomes[mid] = o
			}
		}
		out.Stages = append(out.Stages, sv)
	}
	return out, nil
}

// gateReject records a rejected gate and returns the failure.
func (a *Authority) gateReject(e *entry, g Gate, code permit.Code, detail string) error {
	a.emit("gate_rejected", e.approval.Digest, code, g.String()+": "+detail)
	return failure(code, detail)
}

// minTime returns the earlier of two times.
func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

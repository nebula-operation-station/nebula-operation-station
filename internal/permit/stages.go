// SPDX-License-Identifier: AGPL-3.0-or-later

package permit

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/stageplan"
	"github.com/nebula-operation-station/nebula-operation-station/internal/webauthnverify"
)

// Stages (spec 07, Milestone 6). A permit carries the approved stage plan
// and enforces it: a host runs only once its stage is open; the first stage
// opens with the approval; a later stage opens through a gate (or by
// itself, if the plan says auto and the risk is LOW or MEDIUM) and only
// once the stage before it is complete and within its thresholds. The
// outcomes that decide this are the executor's own (RecordOutcome is
// called by the executor for its runs, never on the server's word). A
// stage with more failed hosts than allowed stops the rollout for good.
//
// Stage state lives with the permit and is never persisted: like every
// permit, a rollout ends with an executor restart or a lock.

// Outcome is a host's result as far as the stage engine is concerned.
type Outcome string

// Outcomes.
const (
	OutcomeNone        Outcome = ""
	OutcomeSucceeded   Outcome = "succeeded"
	OutcomeFailed      Outcome = "failed"
	OutcomeUnreachable Outcome = "unreachable"
	OutcomeSkipped     Outcome = "skipped"
)

// OutcomeOfClass maps a run's result class (spec 07) to an outcome:
// success succeeded, network_unreachable (nothing reached the host)
// unreachable, everything else failed.
func OutcomeOfClass(class string) Outcome {
	switch class {
	case "success":
		return OutcomeSucceeded
	case "network_unreachable":
		return OutcomeUnreachable
	}
	return OutcomeFailed
}

// Stage failure codes.
const (
	CodeStageNotOpen   Code = "stage_not_open"
	CodeStageNotDone   Code = "stage_not_done"
	CodeRolloutStopped Code = "rollout_stopped"
	CodeRolloutAborted Code = "rollout_aborted"
	CodeGateInvalid    Code = "gate_invalid"
	CodeStagePlan      Code = "stage_plan_invalid"
)

// GateKind is what a gate does.
type GateKind string

// Gate kinds.
const (
	GateOpenStage GateKind = "open_stage"
	GateSkipHost  GateKind = "skip_host"
)

// Gate is one gate decision: open stage Stage (1-based), or skip Host.
// Skipping needs the same approval as a gate (decision 4 of the M6 plan).
type Gate struct {
	Kind  GateKind
	Stage int
	Host  string
}

func (g Gate) String() string {
	if g.Kind == GateSkipHost {
		return "skip " + g.Host
	}
	return fmt.Sprintf("open stage %d", g.Stage)
}

type pendingGate struct {
	gate      Gate
	challenge []byte
	expiry    time.Time
}

// stages is the stage state of a permit.
type stages struct {
	plan    []stageplan.Stage
	stageOf map[string]int
	open    int // index of the highest open stage
	outcome map[string]Outcome
	stopped string
	aborted bool
	gate    *pendingGate
}

func newStages(plan []stageplan.Stage) *stages {
	s := &stages{plan: plan, stageOf: map[string]int{}, outcome: map[string]Outcome{}}
	for i, st := range plan {
		for _, h := range st.Hosts {
			s.stageOf[h] = i
		}
	}
	return s
}

// singleStagePlan is the plan of a request without stages: every host in
// one stage that opens with the approval.
func singleStagePlan(targets []canonical.Target) []stageplan.Stage {
	hosts := make([]string, len(targets))
	for i, t := range targets {
		hosts[i] = t.HostID
	}
	return []stageplan.Stage{{Name: "all", Hosts: hosts, MaxFailed: len(hosts), MaxUnreachable: len(hosts),
		Continue: stageplan.ContinueManual, TimeoutS: stageplan.MaxTimeout}}
}

type stageStats struct{ succeeded, failed, unreachable, skipped, done int }

func (s *stages) stats(i int) stageStats {
	var st stageStats
	for _, h := range s.plan[i].Hosts {
		switch s.outcome[h] {
		case OutcomeSucceeded:
			st.succeeded++
		case OutcomeFailed:
			st.failed++
		case OutcomeUnreachable:
			st.unreachable++
		case OutcomeSkipped:
			st.skipped++
		default:
			continue
		}
		st.done++
	}
	return st
}

// passed reports whether stage i is complete and within its thresholds.
func (s *stages) passed(i int) (bool, string) {
	st, plan := s.stats(i), s.plan[i]
	switch {
	case st.done < len(plan.Hosts):
		return false, fmt.Sprintf("stage %s: %d of %d hosts have no outcome yet", plan.Name, len(plan.Hosts)-st.done, len(plan.Hosts))
	case st.failed > plan.MaxFailed:
		return false, fmt.Sprintf("stage %s: %d hosts failed, at most %d allowed", plan.Name, st.failed, plan.MaxFailed)
	case st.unreachable > plan.MaxUnreachable:
		return false, fmt.Sprintf("stage %s: %d hosts unreachable, at most %d allowed (retry or skip them)", plan.Name, st.unreachable, plan.MaxUnreachable)
	}
	return true, ""
}

// evaluateLocked stops the rollout when the open stage has more failures
// than allowed (failures are final), and opens the next stage when the
// open one passed and continues automatically.
func (a *Authority) evaluateLocked(p *Permit) {
	s := p.stages
	for !s.aborted && s.stopped == "" {
		// Every open stage counts, not only the newest: a host of an
		// earlier stage that was retried after the stage passed can still
		// fail it (Hermes review of #34).
		for i := 0; i <= s.open; i++ {
			if st := s.stats(i); st.failed > s.plan[i].MaxFailed {
				s.stopped = fmt.Sprintf("stage %s: %d hosts failed, at most %d allowed", s.plan[i].Name, st.failed, s.plan[i].MaxFailed)
				a.emit(Event{Kind: "stage_failed", Digest: p.Digest.String(), Detail: s.stopped})
				return
			}
		}
		plan := s.plan[s.open]
		ok, _ := s.passed(s.open)
		if !ok || s.open+1 >= len(s.plan) {
			return
		}
		if plan.Continue != stageplan.ContinueAuto {
			a.emit(Event{Kind: "stage_passed", Digest: p.Digest.String(), Detail: "stage " + plan.Name + ": waiting at the gate"})
			return
		}
		s.open++
		a.emit(Event{Kind: "stage_opened", Digest: p.Digest.String(), Detail: fmt.Sprintf("stage %d (%s), automatic", s.open+1, s.plan[s.open].Name)})
	}
}

// checkStageLocked is the stage part of AuthorizeGrant.
func (a *Authority) checkStageLocked(p *Permit, d canonical.Digest, host string) error {
	s := p.stages
	switch {
	case s.aborted:
		return a.deny(d, host, CodeRolloutAborted, "")
	case s.stopped != "":
		return a.deny(d, host, CodeRolloutStopped, s.stopped)
	case s.stageOf[host] > s.open:
		return a.deny(d, host, CodeStageNotOpen, fmt.Sprintf("host is in stage %d, stage %d is open", s.stageOf[host]+1, s.open+1))
	case s.outcome[host] == OutcomeSkipped:
		return a.deny(d, host, CodeHostAlreadyRun, "host was skipped")
	}
	return nil
}

// RecordOutcome records the executor's own outcome of a host run of the
// execution and re-evaluates the open stage. Only the executor calls it,
// for runs it carried out; an outcome is final except unreachable, which
// a retry of the same host replaces.
func (a *Authority) RecordOutcome(executionID, host string, o Outcome) {
	a.mu.Lock()
	defer a.mu.Unlock()
	d, ok := a.executions[executionID]
	if !ok {
		return
	}
	p, ok := a.permits[d]
	if !ok || p.stages == nil {
		return
	}
	s := p.stages
	if _, in := s.stageOf[host]; !in || o == OutcomeNone || o == OutcomeSkipped {
		return
	}
	if cur := s.outcome[host]; cur != OutcomeNone && cur != OutcomeUnreachable {
		return
	}
	s.outcome[host] = o
	a.emit(Event{Kind: "outcome", Digest: d.String(), Host: host, Detail: string(o)})
	a.evaluateLocked(p)
}

// ReleaseUnreachable is ReleaseHost and RecordOutcome(unreachable) in one
// critical section, so no other run of the host can be authorized between
// the release and the outcome (Hermes review of #34). It reports whether
// the host was released; if not, the outcome is recorded anyway.
func (a *Authority) ReleaseUnreachable(d canonical.Digest, hostID string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	p, ok := a.permits[d]
	if !ok || p.stages == nil {
		return false
	}
	released := false
	if _, used := p.used[hostID]; used && p.State == StateApproved && a.now().Before(time.Unix(p.Request.ExpiryUnix, 0)) &&
		p.stages.outcome[hostID] != OutcomeSkipped {
		delete(p.used, hostID)
		released = true
		a.emit(Event{Kind: "released", Digest: d.String(), Host: hostID, Detail: "host unreachable; nothing ran"})
	}
	s := p.stages
	if _, in := s.stageOf[hostID]; in {
		if cur := s.outcome[hostID]; cur == OutcomeNone || cur == OutcomeUnreachable {
			s.outcome[hostID] = OutcomeUnreachable
			a.emit(Event{Kind: "outcome", Digest: d.String(), Host: hostID, Detail: string(OutcomeUnreachable)})
			a.evaluateLocked(p)
		}
	}
	return released
}

// GateChallenge is what a gate needs.
type GateChallenge struct {
	Requirement Requirement
	// Challenge is empty when the privileged session suffices.
	Challenge []byte
	Expiry    time.Time
}

// gateRequirement: LOW and MEDIUM gates need the privileged session (a
// click), HIGH and CRITICAL a fresh user-verified assertion bound to the
// digest and the gate (spec 07), or the CLI in hardened mode.
func (a *Authority) gateRequirement(p *Permit) Requirement {
	switch p.Request.RiskClass {
	case canonical.RiskLow, canonical.RiskMedium:
		return RequireNone
	}
	if a.mode == ModeHardened {
		return RequireCLI
	}
	return RequireAssertionVerified
}

// gateChallengeFor returns SHA-256("nebula-gate-v1" 0x00 || digest || kind
// 0x00 || stage as big-endian uint32 || host 0x00 || 32-byte nonce ||
// expiry as big-endian int64 Unix seconds): an assertion for one gate
// opens no other gate, stage or permit.
func gateChallengeFor(d canonical.Digest, g Gate, expiry time.Time) ([]byte, error) {
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, fmt.Errorf("permit: nonce: %w", err)
	}
	h := sha256.New()
	h.Write([]byte("nebula-gate-v1\x00"))
	h.Write(d[:])
	h.Write([]byte(string(g.Kind) + "\x00"))
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(g.Stage))
	h.Write(n[:])
	h.Write([]byte(g.Host + "\x00"))
	h.Write(nonce[:])
	var exp [8]byte
	binary.BigEndian.PutUint64(exp[:], uint64(expiry.Unix()))
	h.Write(exp[:])
	return h.Sum(nil), nil
}

// approvedLocked returns a live approved permit.
func (a *Authority) approvedLocked(d canonical.Digest, now time.Time) (*Permit, error) {
	p, ok := a.permits[d]
	switch {
	case !ok:
		return nil, fail(CodeNotFound, "")
	case p.State != StateApproved:
		return nil, fail(CodeWrongState, "permit is not approved")
	case !now.Before(time.Unix(p.Request.ExpiryUnix, 0)):
		return nil, fail(CodeExpired, "")
	case p.stages == nil:
		return nil, fail(CodeWrongState, "permit has no stages")
	}
	return p, nil
}

// checkGateLocked says whether g can be applied now.
func (a *Authority) checkGateLocked(p *Permit, g Gate) error {
	s := p.stages
	switch {
	case s.aborted:
		return fail(CodeRolloutAborted, "")
	case s.stopped != "":
		return fail(CodeRolloutStopped, "%s", s.stopped)
	}
	switch g.Kind {
	case GateOpenStage:
		if g.Host != "" || g.Stage != s.open+2 || g.Stage > len(s.plan) {
			return fail(CodeGateInvalid, "the next stage is %d of %d", s.open+2, len(s.plan))
		}
		if ok, why := s.passed(s.open); !ok {
			return fail(CodeStageNotDone, "%s", why)
		}
	case GateSkipHost:
		i, in := s.stageOf[g.Host]
		switch {
		case g.Stage != 0 || !in:
			return fail(CodeGateInvalid, "host %q is not in the plan", g.Host)
		case i > s.open:
			return fail(CodeStageNotOpen, "host is in stage %d, stage %d is open", i+1, s.open+1)
		case s.outcome[g.Host] != OutcomeNone && s.outcome[g.Host] != OutcomeUnreachable:
			return fail(CodeGateInvalid, "host %q already has the outcome %s", g.Host, s.outcome[g.Host])
		}
		// A used host without an outcome is running. An unreachable one
		// may still be used (a durable job that could not be dispatched is
		// not released): it can be skipped, never run again.
		if _, used := p.used[g.Host]; used && s.outcome[g.Host] != OutcomeUnreachable {
			return fail(CodeGateInvalid, "host %q is running or has run", g.Host)
		}
	default:
		return fail(CodeGateInvalid, "unknown gate")
	}
	return nil
}

func (a *Authority) applyGateLocked(p *Permit, g Gate, by string) {
	s := p.stages
	switch g.Kind {
	case GateOpenStage:
		s.open = g.Stage - 1
		a.emit(Event{Kind: "stage_opened", Digest: p.Digest.String(), Detail: fmt.Sprintf("stage %d (%s) by %s", g.Stage, s.plan[s.open].Name, by)})
	case GateSkipHost:
		p.used[g.Host] = struct{}{}
		s.outcome[g.Host] = OutcomeSkipped
		a.emit(Event{Kind: "host_skipped", Digest: p.Digest.String(), Host: g.Host, Detail: "by " + by})
	}
	a.evaluateLocked(p)
}

// BeginGate checks that g can be applied and returns what it needs. For a
// gate that needs an assertion it returns a fresh single-use challenge; a
// new call replaces an earlier unused one.
func (a *Authority) BeginGate(d canonical.Digest, g Gate) (GateChallenge, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	a.gcLocked(now)
	p, err := a.approvedLocked(d, now)
	if err != nil {
		return GateChallenge{}, err
	}
	if err := a.checkGateLocked(p, g); err != nil {
		return GateChallenge{}, err
	}
	req := a.gateRequirement(p)
	out := GateChallenge{Requirement: req}
	if req == RequireAssertionVerified {
		exp := minTime(now.Add(ApprovalWindow), time.Unix(p.Request.ExpiryUnix, 0))
		ch, err := gateChallengeFor(d, g, exp)
		if err != nil {
			return GateChallenge{}, err
		}
		p.stages.gate = &pendingGate{gate: g, challenge: ch, expiry: exp}
		out.Challenge, out.Expiry = slices.Clone(ch), exp
	}
	return out, nil
}

// CommitGate applies g from the web UI: with the privileged session for
// LOW and MEDIUM, with a user-verified assertion over the challenge from
// BeginGate for HIGH and CRITICAL. The challenge is consumed whether or
// not the assertion verifies.
func (a *Authority) CommitGate(d canonical.Digest, g Gate, assertionJSON []byte) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	a.gcLocked(now)
	p, err := a.approvedLocked(d, now)
	if err != nil {
		return err
	}
	if !a.sessionActiveLocked(now) {
		return a.gateReject(p, g, CodeSessionRequired, "a gate needs an active privileged session")
	}
	if err := a.checkGateLocked(p, g); err != nil {
		a.emit(Event{Kind: "rejected", Digest: d.String(), Host: g.Host, Code: CodeOf(err), Detail: g.String() + ": " + err.Error()})
		return err
	}
	switch a.gateRequirement(p) {
	case RequireCLI:
		return a.gateReject(p, g, CodeCLIRequired, "hardened mode: use nebula approve --stage or --skip")
	case RequireNone:
		a.applyGateLocked(p, g, "privileged-session")
		return nil
	}
	pg := p.stages.gate
	p.stages.gate = nil
	if pg == nil || pg.gate != g {
		return a.gateReject(p, g, CodeNoChallenge, "call BeginGate for this gate first")
	}
	if !now.Before(pg.expiry) {
		return a.gateReject(p, g, CodeExpired, "gate challenge expired")
	}
	credID, err := a.verifier.Verify(assertionJSON, pg.challenge, webauthnverify.Requirement{UserVerification: true})
	if errors.Is(err, webauthnverify.ErrCounterStore) {
		return a.storageFailure(d.String(), err)
	}
	if err != nil {
		return a.gateReject(p, g, CodeAssertionRejected, err.Error())
	}
	a.applyGateLocked(p, g, "webauthn:"+hex.EncodeToString(credID))
	return nil
}

// ApproveGateCLI applies g from the hardened CLI path; the caller has
// established that the peer is an admin on the executor host.
func (a *Authority) ApproveGateCLI(d canonical.Digest, g Gate, who string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	a.gcLocked(now)
	p, err := a.approvedLocked(d, now)
	if err != nil {
		return err
	}
	if err := a.checkGateLocked(p, g); err != nil {
		return err
	}
	a.applyGateLocked(p, g, "cli:"+who)
	return nil
}

func (a *Authority) gateReject(p *Permit, g Gate, code Code, detail string) error {
	a.emit(Event{Kind: "rejected", Digest: p.Digest.String(), Host: g.Host, Code: code, Detail: g.String() + ": " + detail})
	return fail(code, "%s", detail)
}

// Abort stops a rollout: no further host of the permit is authorized. It
// needs no approval, since it only takes permission away.
func (a *Authority) Abort(d canonical.Digest, who string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	a.gcLocked(now)
	p, err := a.approvedLocked(d, now)
	if err != nil {
		return err
	}
	if !p.stages.aborted {
		p.stages.aborted = true
		p.stages.gate = nil
		a.emit(Event{Kind: "aborted", Digest: d.String(), Detail: "by " + who})
	}
	return nil
}

// StageStatus is one stage of a rollout as the executor sees it.
type StageStatus struct {
	Stage    stageplan.Stage
	Open     bool
	Passed   bool
	Outcomes map[string]Outcome
}

// Rollout is the stage state of a permit.
type Rollout struct {
	Stages []StageStatus
	// Open is the index of the highest open stage.
	Open    int
	Stopped string
	Aborted bool
	// GateRequirement is what the next gate needs.
	GateRequirement Requirement
}

// Rollout returns the stage state of an approved permit.
func (a *Authority) Rollout(d canonical.Digest) (Rollout, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	a.gcLocked(now)
	p, err := a.approvedLocked(d, now)
	if err != nil {
		return Rollout{}, err
	}
	s := p.stages
	r := Rollout{Open: s.open, Stopped: s.stopped, Aborted: s.aborted, GateRequirement: a.gateRequirement(p)}
	for i, st := range s.plan {
		ss := StageStatus{Stage: st, Open: i <= s.open, Outcomes: map[string]Outcome{}}
		ss.Stage.Hosts = slices.Clone(st.Hosts)
		ss.Passed, _ = s.passed(i)
		for _, h := range st.Hosts {
			if o := s.outcome[h]; o != OutcomeNone {
				ss.Outcomes[h] = o
			}
		}
		r.Stages = append(r.Stages, ss)
	}
	return r, nil
}

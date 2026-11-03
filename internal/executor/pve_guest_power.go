// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pveapi"
	"github.com/nebula-operation-station/nebula-operation-station/internal/riskpolicy"
)

// Typed guest power actions (ADR 0006 "Phase 2 actions, permits and
// reconciliation", P2-01 lifecycle baseline): one action, pve.guest.power,
// with a verb. Graceful shutdown and reboot are MEDIUM, hard stop and reset
// HIGH; reset exists for QEMU only. Every verb needs the guest running,
// bound in the approval and re-read before dispatch. A failed or timed-out
// shutdown is never followed by a stop: there is no force fallback, and
// the shutdown step always sends forceStop=0 (pveapi).
//
// Each run is a single step on the PveMutations engine, so intent, UPID,
// lost-response identification and restart reconciliation are the
// engine's: a guest-level job, whose task is matched by node, VMID, task
// type and action token.

// PveGuestPowerAction is the action ID of the guest power actions.
const PveGuestPowerAction = "pve.guest.power"

// Guest power verbs.
const (
	PveGuestPowerShutdown = "shutdown"
	PveGuestPowerReboot   = "reboot"
	PveGuestPowerStop     = "stop"
	PveGuestPowerReset    = "reset"
)

// Guest power limits and fixed values.
const (
	// pveGuestPowerVersion is the module version of the power artifacts.
	pveGuestPowerVersion = "1.0.0"
	// pveGuestPowerDefaultTimeoutSec is the graceful shutdown or reboot
	// timeout when the request names none.
	pveGuestPowerDefaultTimeoutSec = 180
	// pveGuestRunning is the only status a power verb accepts.
	pveGuestRunning = "running"
	// maxPveGuestPowerStepArgs bounds the arguments of one power step.
	maxPveGuestPowerStepArgs = 128
	// maxPveGuestPowerBindings bounds the bindings held at one time (one
	// per proposal or run in progress).
	maxPveGuestPowerBindings = 256
)

var (
	// ErrPveGuestPowerVerb is returned for an unknown verb, a verb the
	// guest kind does not support (LXC reset) or a timeout outside the
	// verb's bounds. Nothing is read or sent.
	ErrPveGuestPowerVerb = errors.New("executor: unsupported pve guest power request")
	// ErrPveGuestState is returned when the guest is not in the state the
	// verb requires (running). Nothing is sent.
	ErrPveGuestState = errors.New("executor: pve guest is not in the state the power action requires")
	// ErrPveGuestPowerBusy is returned when too many power proposals or
	// runs are in progress at once.
	ErrPveGuestPowerBusy = errors.New("executor: too many pve guest power requests in progress")
	// ErrPveGuestPowerRisk is returned when the risk floor of a power
	// proposal cannot be evaluated (a criticality or linked-host source
	// failed). Nothing is proposed.
	ErrPveGuestPowerRisk = errors.New("executor: pve guest power risk floor unavailable")
)

// pveGuestPowerVerbs maps each verb to its base risk.
var pveGuestPowerVerbs = map[string]canonical.Risk{
	PveGuestPowerShutdown: canonical.RiskMedium,
	PveGuestPowerReboot:   canonical.RiskMedium,
	PveGuestPowerStop:     canonical.RiskHigh,
	PveGuestPowerReset:    canonical.RiskHigh,
}

// pveGuestPowerText describes each verb in its artifact.
var pveGuestPowerText = map[string]string{
	PveGuestPowerShutdown: "Graceful shutdown (ACPI, guest agent or LXC) of the exact running guest; never a force stop.",
	PveGuestPowerReboot:   "Graceful reboot of the exact running guest; never a force stop.",
	PveGuestPowerStop:     "Hard stop of the exact running guest (destructive: like pulling the power).",
	PveGuestPowerReset:    "Hard reset of the exact running QEMU guest (destructive: like pressing reset).",
}

// pveGuestPowerArtifact is the fixed artifact of verb. Its hash names the
// verb in the canonical request, so the risk floor and the approval see
// the verb without the parameters. nil for an unknown verb.
func pveGuestPowerArtifact(verb string) []byte {
	text, ok := pveGuestPowerText[verb]
	if !ok {
		return nil
	}
	return []byte(PveGuestPowerAction + " " + pveGuestPowerVersion + "\nverb: " + verb + "\n" + text + "\n")
}

// pveGuestPowerStagePlan is the stage plan hash of a power action (one
// exact guest, no stages).
var pveGuestPowerStagePlan = func() string {
	s, _ := canonical.HashParameters([]byte(`{"plan":"pve-guest-power-v1"}`))
	return s
}()

// pveGuestPowerMethod is one allowlisted power step method.
type pveGuestPowerMethod struct {
	kind, verb, taskType string
}

// pveGuestPowerMethods is the step method allowlist with the PVE task
// type each creates. There is no LXC reset.
var pveGuestPowerMethods = map[string]pveGuestPowerMethod{
	"guest.qemu.shutdown": {permit.ProviderKindQemu, PveGuestPowerShutdown, "qmshutdown"},
	"guest.qemu.reboot":   {permit.ProviderKindQemu, PveGuestPowerReboot, "qmreboot"},
	"guest.qemu.stop":     {permit.ProviderKindQemu, PveGuestPowerStop, "qmstop"},
	"guest.qemu.reset":    {permit.ProviderKindQemu, PveGuestPowerReset, "qmreset"},
	"guest.lxc.shutdown":  {permit.ProviderKindLXC, PveGuestPowerShutdown, "vzshutdown"},
	"guest.lxc.reboot":    {permit.ProviderKindLXC, PveGuestPowerReboot, "vzreboot"},
	"guest.lxc.stop":      {permit.ProviderKindLXC, PveGuestPowerStop, "vzstop"},
}

func pveGuestPowerMethodName(kind, verb string) (string, bool) {
	name := "guest." + kind + "." + verb
	m, ok := pveGuestPowerMethods[name]
	return name, ok && m.kind == kind && m.verb == verb
}

// graceful reports whether verb takes a timeout.
func graceful(verb string) bool {
	return verb == PveGuestPowerShutdown || verb == PveGuestPowerReboot
}

// pveGuestPowerArgs are the arguments of a power step. TimeoutSec is set
// for shutdown and reboot only.
type pveGuestPowerArgs struct {
	VMID       uint64 `json:"vmid"`
	TimeoutSec int    `json:"timeout_sec,omitempty"`
}

// pveGuestPowerParams are the action parameters bound in the approval.
type pveGuestPowerParams struct {
	Verb         string            `json:"verb"`
	Kind         string            `json:"kind"`
	ExpectStatus string            `json:"expect_status"`
	Steps        []PveMutationStep `json:"steps"`
}

// PveGuestPowerRequest names one power action on one exact guest.
type PveGuestPowerRequest struct {
	// Digest is the approved permit (Run only).
	Digest   canonical.Digest
	RemoteID string
	Kind     string
	Node     string
	VMID     uint64
	Verb     string
	// TimeoutSec is the shutdown or reboot timeout (0: the default); it
	// must be 0 for stop and reset.
	TimeoutSec int
}

// mutation validates r and builds the engine request. It does no I/O.
func (r PveGuestPowerRequest) mutation() (PveMutationRequest, error) {
	if _, ok := pveGuestPowerVerbs[r.Verb]; !ok || (r.Kind != permit.ProviderKindQemu && r.Kind != permit.ProviderKindLXC) {
		return PveMutationRequest{}, ErrPveGuestPowerVerb
	}
	method, ok := pveGuestPowerMethodName(r.Kind, r.Verb)
	if !ok {
		return PveMutationRequest{}, ErrPveGuestPowerVerb
	}
	timeout := r.TimeoutSec
	switch {
	case !graceful(r.Verb) && timeout != 0:
		return PveMutationRequest{}, ErrPveGuestPowerVerb
	case graceful(r.Verb) && timeout == 0:
		timeout = pveGuestPowerDefaultTimeoutSec
	}
	if graceful(r.Verb) && (timeout < pveapi.MinPowerTimeoutSec || timeout > pveapi.MaxPowerTimeoutSec) {
		return PveMutationRequest{}, ErrPveGuestPowerVerb
	}
	if err := permit.ValidateProviderMutationShape(r.Kind, r.Node, r.VMID); err != nil || !validVMID(r.VMID) {
		return PveMutationRequest{}, ErrPveMutationRequest
	}
	args, err := json.Marshal(pveGuestPowerArgs{VMID: r.VMID, TimeoutSec: timeout})
	if err != nil {
		return PveMutationRequest{}, ErrPveMutationPlan
	}
	params, err := json.Marshal(pveGuestPowerParams{Verb: r.Verb, Kind: r.Kind, ExpectStatus: pveGuestRunning,
		Steps: []PveMutationStep{{Method: method, Args: args}}})
	if err != nil {
		return PveMutationRequest{}, ErrPveMutationPlan
	}
	kind := r.Kind
	return PveMutationRequest{
		Digest: r.Digest, RemoteID: r.RemoteID, Kind: r.Kind, Node: r.Node, VMID: r.VMID,
		ActionID: PveGuestPowerAction, ModuleVersion: pveGuestPowerVersion, Artifact: pveGuestPowerArtifact(r.Verb),
		Parameters: params,
		precheck: func(live PveTargetState) error {
			// Exists (the read succeeded), same node (checked by the
			// engine), same kind and running. PVE reports a paused or
			// suspended QEMU guest as "running"; its QMP state must be
			// running as well (not reported: refused).
			if live.Kind != kind {
				return ErrPveTargetChanged
			}
			if live.Status != pveGuestRunning {
				return ErrPveGuestState
			}
			if kind == permit.ProviderKindQemu && live.QMPStatus != pveGuestRunning {
				return ErrPveGuestState
			}
			return nil
		},
	}, nil
}

// PveGuestPowerBindings holds the exact target and verb each bound
// parameters hash of a power action stands for, so GuestPowerRiskFloor can
// score the guest's node and remote (which the canonical request does not
// name) whenever the authority asks: when proposing, approving and
// authorizing the run. An entry lives while a call holds it and, for a
// proposed permit, until the permit's expiry. Like permits it is in
// memory only; a hash without an entry is scored HIGH.
type PveGuestPowerBindings struct {
	// Now is the clock. Default: time.Now.
	Now func() time.Time

	mu sync.Mutex
	m  map[string]*pveGuestPowerBinding
}

type pveGuestPowerBinding struct {
	target permit.ProviderMutationTarget
	verb   string
	refs   int
	until  time.Time
}

func (b *PveGuestPowerBindings) now() time.Time {
	if b.Now == nil {
		return time.Now()
	}
	return b.Now()
}

// hold records hash → (target, verb) until the returned release is called
// (and longer if keep extends it).
func (b *PveGuestPowerBindings) hold(hash string, t permit.ProviderMutationTarget, verb string) (func(), error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.m == nil {
		b.m = map[string]*pveGuestPowerBinding{}
	}
	now := b.now()
	for h, e := range b.m {
		if e.refs <= 0 && now.After(e.until) {
			delete(b.m, h)
		}
	}
	e, ok := b.m[hash]
	switch {
	case ok && (e.verb != verb || !sameBoundTarget(e.target, t)):
		// The hash binds the target and verb; a different pair under the
		// same hash cannot happen and is refused.
		return nil, ErrPveMutationPlan
	case ok:
		e.refs++
	case len(b.m) >= maxPveGuestPowerBindings:
		return nil, ErrPveGuestPowerBusy
	default:
		b.m[hash] = &pveGuestPowerBinding{target: t, verb: verb, refs: 1}
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			b.mu.Lock()
			defer b.mu.Unlock()
			if e := b.m[hash]; e != nil {
				if e.refs--; e.refs <= 0 && b.now().After(e.until) {
					delete(b.m, hash)
				}
			}
		})
	}, nil
}

// keep extends a held entry until until (a proposed permit's expiry).
func (b *PveGuestPowerBindings) keep(hash string, until time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if e := b.m[hash]; e != nil && until.After(e.until) {
		e.until = until
	}
}

func sameBoundTarget(a, b permit.ProviderMutationTarget) bool {
	x, errA := json.Marshal(a)
	y, errB := json.Marshal(b)
	return errA == nil && errB == nil && string(x) == string(y)
}

func (b *PveGuestPowerBindings) lookup(hash string) (permit.ProviderMutationTarget, string, bool) {
	if b == nil {
		return permit.ProviderMutationTarget{}, "", false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	e, ok := b.m[hash]
	if !ok || (e.refs <= 0 && b.now().After(e.until)) {
		// An entry nobody holds outlives neither the call nor the permit.
		return permit.ProviderMutationTarget{}, "", false
	}
	return e.target, e.verb, true
}

// PveGuestPower proposes and runs guest power actions on the executor's
// single PVE mutation engine.
type PveGuestPower struct {
	Mutations *PveMutations
	// Bindings must be the instance the authority's GuestPowerRiskFloor
	// reads.
	Bindings *PveGuestPowerBindings
	// Floor, if set, is evaluated by Propose itself (with the binding
	// held) and raises the proposed risk to it, so the approval carries
	// the full executor floor even when the authority's own policy does
	// not include GuestPowerRiskFloor. It can only raise the risk.
	Floor permit.RiskPolicy
}

func (g *PveGuestPower) checkDeps() error {
	if g.Mutations == nil || g.Bindings == nil {
		return errors.New("executor: pve guest power: Mutations and Bindings are required")
	}
	return g.Mutations.checkDeps()
}

// hold binds the exact target and verb of a proposal or run to its
// parameters hash for the risk floor.
func (g *PveGuestPower) hold(t permit.ProviderMutationTarget, verb, hash string) (func(), error) {
	return g.Bindings.hold(hash, t, verb)
}

// boundTarget reads the exact target from a mutation parameters document.
func boundTarget(params []byte) (permit.ProviderMutationTarget, error) {
	var doc struct {
		Target permit.ProviderMutationTarget `json:"provider_target"`
	}
	if err := json.Unmarshal(params, &doc); err != nil {
		return permit.ProviderMutationTarget{}, ErrPveMutationPlan
	}
	if err := doc.Target.Validate(); err != nil {
		return permit.ProviderMutationTarget{}, ErrPveMutationPlan
	}
	return doc.Target, nil
}

// Propose proposes req for the guest's current exact target, which must be
// running. The risk is the executor's floor (GuestPowerRiskFloor): the
// verb's base raised by guest, node, remote and linked-host criticality.
func (g *PveGuestPower) Propose(ctx context.Context, req PveGuestPowerRequest, executionID string, expiry time.Time) (permit.Permit, error) {
	mreq, err := req.mutation()
	if err != nil {
		return permit.Permit{}, err
	}
	if err := g.checkDeps(); err != nil {
		return permit.Permit{}, err
	}
	rq, params, err := g.Mutations.ProposalRequest(ctx, mreq, executionID, pveGuestPowerVerbs[req.Verb], pveGuestPowerStagePlan, expiry)
	if err != nil {
		return permit.Permit{}, err
	}
	t, err := boundTarget(params)
	if err != nil {
		return permit.Permit{}, err
	}
	release, err := g.hold(t, req.Verb, rq.ParametersHash)
	if err != nil {
		return permit.Permit{}, err
	}
	defer release()
	if g.Floor != nil {
		f, _, err := g.Floor.MinimumRisk(rq, rq.ResolvedTargets)
		if err != nil {
			return permit.Permit{}, fmt.Errorf("%w: %w", ErrPveGuestPowerRisk, err)
		}
		if f.Rank() > rq.RiskClass.Rank() {
			rq.RiskClass = f
		}
	}
	res, err := g.Mutations.Auth.ProposeAtLeastMinimum(rq, params)
	if err != nil {
		return permit.Permit{}, err
	}
	// The authority checks the floor again on approval and on the run:
	// the binding stays while the permit can be used.
	g.Bindings.keep(rq.ParametersHash, time.Unix(res.Permit.Request.ExpiryUnix, 0))
	g.Mutations.log().Info("audit", "kind", "pve_guest_power_proposed", "remote", t.RemoteID, "node", t.Node, "vmid", t.VMID,
		"verb", req.Verb, "risk", string(res.Permit.Request.RiskClass), "execution", executionID)
	return res.Permit, nil
}

// Run runs the approved power action req.Digest. The exact target is
// rebuilt from the registry and a live read, the guest must still be the
// approved one and running, before authorization and again immediately
// before the step is sent; otherwise nothing is sent.
func (g *PveGuestPower) Run(ctx context.Context, req PveGuestPowerRequest) (PveMutationResult, error) {
	mreq, err := req.mutation()
	if err != nil {
		return PveMutationResult{}, err
	}
	if err := g.checkDeps(); err != nil {
		return PveMutationResult{}, err
	}
	m := g.Mutations
	rm, err := m.activeRemote(mreq.RemoteID)
	if err != nil {
		return PveMutationResult{}, err
	}
	t, live, err := m.targetLive(ctx, rm, mreq)
	if err != nil {
		return PveMutationResult{}, err
	}
	if err := mreq.precheck(live); err != nil {
		return PveMutationResult{}, err
	}
	binding, err := mutationOf(mreq, t).BindingJSON()
	if err != nil {
		return PveMutationResult{}, ErrPveTargetChanged
	}
	hash, err := canonical.HashParameters(binding)
	if err != nil {
		return PveMutationResult{}, ErrPveMutationPlan
	}
	// The engine reads the target again; if it changed in between, the
	// floor finds no binding (HIGH) and the permit's target check refuses.
	release, err := g.hold(t, req.Verb, hash)
	if err != nil {
		return PveMutationResult{}, err
	}
	defer release()
	return m.Run(ctx, mreq)
}

// PveGuestRiskTargets returns the synthetic risk targets of a guest
// target: the guest itself (the permit's bound target), its node and its
// remote. Executor criticality records of these targets set the guest,
// node and remote criticality of power actions. The three are distinct in
// host ID and fingerprint (permit.ProviderRiskFingerprint,
// PveRemoteRiskTarget), so each can carry its own exact record; an admin
// records them with the host ID and fingerprint returned here.
func PveGuestRiskTargets(t permit.ProviderMutationTarget) (guest, node, remote canonical.Target, err error) {
	guest, err = t.RiskTarget()
	if err != nil {
		return canonical.Target{}, canonical.Target{}, canonical.Target{}, ErrPveRemoteChanged
	}
	n := permit.ProviderMutationTarget{RemoteID: t.RemoteID, TrustPin: t.TrustPin, Kind: permit.ProviderKindNode, Node: t.Node}
	node, err = n.RiskTarget()
	if err != nil {
		return canonical.Target{}, canonical.Target{}, canonical.Target{}, ErrPveRemoteChanged
	}
	remote, err = PveRemoteRiskTarget(t.TrustPin)
	if err != nil {
		return canonical.Target{}, canonical.Target{}, canonical.Target{}, err
	}
	return guest, node, remote, nil
}

// PveCriticality is the executor's host criticality record lookup
// (executordb implements it): the recorded class and whether the record
// matches host ID and key exactly.
type PveCriticality interface {
	HostCriticality(hostID, fingerprint string) (canonical.Risk, bool, error)
}

// PveRegistryLinkedHosts is the executor's production linked-host source
// for the PVE risk floors: the managed hosts the executor registry links,
// with admin confirmation, to a PVE guest or node target. Only such links
// are risk-relevant (spec 11 "PVE action profiles and risks", ADR 0006);
// display links the server keeps never count. The executor registry holds
// no host links yet, so no PVE target has a risk-relevant linked host and
// the result is empty. The guest, node and remote criticality records
// still apply, unknown ones as HIGH. When the registry gains confirmed
// links, this is where they must be returned.
func PveRegistryLinkedHosts(canonical.Request, canonical.Target) ([]canonical.Target, error) {
	return nil, nil
}

// NewGuestPowerRiskFloor returns the executor's production guest power
// floor: next for everything else and for artifact trust, the criticality
// records of crit, the executor registry's linked hosts and bindings.
func NewGuestPowerRiskFloor(next permit.RiskPolicy, crit PveCriticality, bindings *PveGuestPowerBindings) GuestPowerRiskFloor {
	return GuestPowerRiskFloor{Next: next, Criticality: crit, Linked: PveRegistryLinkedHosts, Bindings: bindings}
}

// NewExecutorRiskPolicy returns the risk policy of the executor's
// authority: riskpolicy over src (artifact trust and host criticality;
// the executor database in production), wrapped by the provisioning floor
// (GuestProvisionRiskFloor: node, remote and the registry's linked hosts;
// the remote is resolved in the registry if src is one, PveRemoteLister),
// by the guest snapshot floor and by the guest power floor, both over src,
// the registry's linked hosts and bindings. Power and snapshot requests
// share the bindings (their parameters hashes differ, and each floor only
// accepts its own op or verb and artifact). Pass the same bindings to
// Service.SetPveGuestPowerBindings.
func NewExecutorRiskPolicy(src riskpolicy.Source, bindings *PveGuestPowerBindings) (permit.RiskPolicy, error) {
	if src == nil || bindings == nil {
		return nil, errors.New("executor: risk policy needs a risk source and the guest power bindings")
	}
	base, err := riskpolicy.New(src)
	if err != nil {
		return nil, err
	}
	prov := GuestProvisionRiskFloor{Next: base, Linked: PveRegistryLinkedHosts}
	if reg, ok := src.(PveRemoteLister); ok {
		prov.Remote = PveRegistryRemoteOf(reg)
	}
	snap := NewGuestSnapshotRiskFloor(prov, src, bindings)
	return NewGuestPowerRiskFloor(snap, src, bindings), nil
}

// SetPveGuestPowerBindings makes the guest power and snapshot actions bind
// their targets in b, which must be the Bindings of the GuestPowerRiskFloor
// and GuestSnapshotRiskFloor the authority uses as its risk policy
// (NewExecutorRiskPolicy). The authority then re-evaluates the full floor
// (node, remote and linked hosts included) when the permit is approved and
// when the run is authorized. Call it before serving. Without it, or with
// another instance, the authority finds no binding and scores power and
// snapshot requests HIGH (fail closed).
func (s *Service) SetPveGuestPowerBindings(b *PveGuestPowerBindings) { s.pveGuestPowerBindings = b }

// GuestPowerRiskFloor wraps the executor's risk policy for pve.guest.power
// requests. Used as the authority's risk policy (cmd/nebula-executor, with
// the Service's bindings, see SetPveGuestPowerBindings) it is enforced
// when proposing, when approving and again when authorizing the run, so a
// criticality raised after the proposal stops the run. For a power request
// the floor is the maximum of:
//
//   - the verb's base: shutdown and reboot MEDIUM, stop and reset HIGH;
//   - the criticality of the guest, its node and its remote, and of every
//     host Linked returns for the guest or the node; a target without an
//     exact record is at least HIGH (unknown criticality is HIGH);
//   - Next's floor for the same targets (artifact trust and the rest of
//     the executor policy).
//
// Anything the floor cannot establish (no Next, Criticality, Linked or
// Bindings; no binding for the exact parameters; an artifact that is not
// the verb's; another target than the bound guest) makes it HIGH. Other
// requests get Next's floor unchanged, or HIGH without Next.
//
// The guest, node and remote risk targets of one remote each have their
// own synthetic host ID and fingerprint (PveGuestRiskTargets), so the
// executor database, which keeps at most one criticality record per
// fingerprint, can hold an exact record for each of them.
type GuestPowerRiskFloor struct {
	Next        permit.RiskPolicy
	Criticality PveCriticality
	// Linked names the managed hosts linked to a guest or node target.
	Linked   PveLinkedHosts
	Bindings *PveGuestPowerBindings
}

// MinimumRisk implements permit.RiskPolicy.
func (p GuestPowerRiskFloor) MinimumRisk(r canonical.Request, targets []canonical.Target) (canonical.Risk, string, error) {
	if r.ActionID != PveGuestPowerAction {
		if p.Next == nil {
			return canonical.RiskHigh, "no risk policy configured", nil
		}
		return p.Next.MinimumRisk(r, targets)
	}
	high := func(why string) (canonical.Risk, string, error) {
		return canonical.RiskHigh, "pve.guest.power: " + why + ": unknown criticality is HIGH", nil
	}
	if p.Next == nil || p.Criticality == nil || p.Linked == nil || p.Bindings == nil {
		return high("risk sources not configured")
	}
	t, verb, ok := p.Bindings.lookup(r.ParametersHash)
	if !ok {
		return high("no exact target bound to the parameters")
	}
	base, ok := pveGuestPowerVerbs[verb]
	if !ok || r.ArtifactSHA256 != sha256Hex(pveGuestPowerArtifact(verb)) {
		return high("artifact does not match the verb")
	}
	guest, node, remote, err := PveGuestRiskTargets(t)
	if err != nil || len(targets) != 1 || targets[0] != guest {
		return high("targets do not match the bound guest")
	}
	risk, reasons := base, []string{fmt.Sprintf("pve.guest.power %s is %s (ADR 0006)", verb, base)}
	ext := []canonical.Target{guest, node, remote}
	for _, at := range []canonical.Target{guest, node} {
		hosts, err := p.Linked(r, at)
		if err != nil {
			return "", "", fmt.Errorf("guest power risk floor: linked hosts: %w", err)
		}
		ext = append(ext, hosts...)
	}
	for _, at := range ext {
		c, exact, err := p.Criticality.HostCriticality(at.HostID, at.HostKeyFingerprint)
		if err != nil {
			return "", "", fmt.Errorf("guest power risk floor: criticality: %w", err)
		}
		if !exact && c.Rank() < canonical.RiskHigh.Rank() {
			c = canonical.RiskHigh
		}
		if c.Rank() > risk.Rank() {
			risk = c
			reasons = append(reasons, fmt.Sprintf("target %s criticality %s (exact record: %t)", at.HostID, c, exact))
		}
	}
	nr, why, err := p.Next.MinimumRisk(r, ext)
	if err != nil {
		return "", "", fmt.Errorf("guest power risk floor: %w", err)
	}
	if nr.Rank() > risk.Rank() {
		risk = nr
		if why != "" {
			reasons = append(reasons, why)
		}
	}
	return risk, strings.Join(reasons, "; "), nil
}

// GuestPowerStepTaskType returns the PVE task type of a power step
// method, for a PveMutationClient's TaskType.
func GuestPowerStepTaskType(method string) (string, bool) {
	m, ok := pveGuestPowerMethods[method]
	return m.taskType, ok
}

// GuestPowerStepTaskID returns the ID field (the VMID) of the PVE task a
// power step creates, for a PveMutationClient's PveStepTaskIDer.
func GuestPowerStepTaskID(step PveMutationStep) (string, bool) {
	if _, ok := pveGuestPowerMethods[step.Method]; !ok {
		return "", false
	}
	var a pveGuestPowerArgs
	if decodeStepArgsMax(step.Args, &a, maxPveGuestPowerStepArgs) != nil || !validVMID(a.VMID) {
		return "", false
	}
	return strconv.FormatUint(a.VMID, 10), true
}

// PveGuestPowerWriter is the part of pveapi.Writer the power steps use.
type PveGuestPowerWriter interface {
	ShutdownGuest(ctx context.Context, kind pveapi.GuestKind, node string, vmid int64, timeoutSec int) (string, error)
	RebootGuest(ctx context.Context, kind pveapi.GuestKind, node string, vmid int64, timeoutSec int) (string, error)
	StopGuest(ctx context.Context, kind pveapi.GuestKind, node string, vmid int64) (string, error)
	ResetGuest(ctx context.Context, node string, vmid int64) (string, error)
}

// DispatchGuestPowerStep decodes one power step strictly and sends it with
// w, for a PveMutationClient's Dispatch. Only the allowlisted methods
// exist (no LXC reset, no force flags); shutdown and reboot need a timeout
// within the pveapi bounds, stop and reset take none. A step refused
// before anything reached PVE, or refused by PVE, wraps ErrPveRejected.
func DispatchGuestPowerStep(ctx context.Context, w PveGuestPowerWriter, node string, step PveMutationStep) (string, error) {
	m, ok := pveGuestPowerMethods[step.Method]
	if !ok {
		return "", fmt.Errorf("dispatch power step: %w", ErrPveRejected)
	}
	var a pveGuestPowerArgs
	if err := decodeStepArgsMax(step.Args, &a, maxPveGuestPowerStepArgs); err != nil {
		return "", err
	}
	if !validVMID(a.VMID) {
		return "", fmt.Errorf("dispatch power step: vmid: %w", ErrPveRejected)
	}
	if graceful(m.verb) != (a.TimeoutSec != 0) ||
		(graceful(m.verb) && (a.TimeoutSec < pveapi.MinPowerTimeoutSec || a.TimeoutSec > pveapi.MaxPowerTimeoutSec)) {
		return "", fmt.Errorf("dispatch power step: timeout: %w", ErrPveRejected)
	}
	kind, vmid := pveapi.GuestKind(m.kind), int64(a.VMID)
	var upid string
	var err error
	switch m.verb {
	case PveGuestPowerShutdown:
		upid, err = w.ShutdownGuest(ctx, kind, node, vmid, a.TimeoutSec)
	case PveGuestPowerReboot:
		upid, err = w.RebootGuest(ctx, kind, node, vmid, a.TimeoutSec)
	case PveGuestPowerStop:
		upid, err = w.StopGuest(ctx, kind, node, vmid)
	case PveGuestPowerReset:
		if m.kind != permit.ProviderKindQemu {
			return "", fmt.Errorf("dispatch power step: %w", ErrPveRejected)
		}
		upid, err = w.ResetGuest(ctx, node, vmid)
	default:
		return "", fmt.Errorf("dispatch power step: %w", ErrPveRejected)
	}
	return pveWriteResult(step.Method, upid, err)
}

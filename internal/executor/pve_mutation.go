// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"regexp"
	"slices"
	"sync"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pveapi"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vault"
)

// This file is the minimal phase-2 PVE mutation foundation (ADR 0006
// "Phase 2 actions, permits and reconciliation", ADR 0008 PV-01): it
// dispatches the steps of one approved, exact-target mutation with the
// remote's action token, records each step durably around the dispatch and
// reconciles open steps after a restart or a lost response without ever
// sending a mutation again. Typed actions (start, provision, ...) and the
// pveapi write methods build on it; none is wired here.

// PVE mutation limits.
const (
	// pveTaskPollInterval is the default interval between task status
	// reads while waiting for a dispatched step.
	pveTaskPollInterval = 2 * time.Second
	// pveTaskMaxWait bounds the wait for one step's task; a step still
	// running then stays open for reconciliation.
	pveTaskMaxWait = 30 * time.Minute
	// pveTaskMatchSkew is the clock skew allowed when identifying a task
	// whose UPID was lost: its start time must lie within
	// [intent - skew, intent + pveTaskMatchWindow].
	pveTaskMatchSkew = 30 * time.Second
	// pveTaskMatchWindow bounds how long after the intent a lost task may
	// have started.
	pveTaskMatchWindow = 5 * time.Minute
	// pveTaskOK is the PVE exit status of a successful task. Anything else
	// (including "WARNINGS: n") is not success; action-specific postchecks
	// may refine this later.
	pveTaskOK = "OK"
)

var (
	// ErrPveReadOnly is returned for a remote without an action token: it
	// stays read-only.
	ErrPveReadOnly = errors.New("executor: pve remote has no action credential; it is read-only")
	// ErrPveRemoteChanged is returned when the remote's registry identity
	// (state, trust pin or generation, action token version) no longer
	// matches the mutation.
	ErrPveRemoteChanged = errors.New("executor: pve remote changed; the mutation needs a new approval")
	// ErrPveTargetChanged is returned when the live guest or node no longer
	// matches the request (moved, VMID reused, configuration changed).
	ErrPveTargetChanged = errors.New("executor: pve target changed; the mutation needs a new approval")
	// ErrPveMutationDenied is returned when no approved permit covers the
	// exact mutation, or the claim was voided by lock or revocation.
	ErrPveMutationDenied = errors.New("executor: no approved permit covers this pve mutation")
	// ErrPveMutationAlreadyRun is returned, together with
	// ErrPveMutationDenied, when the permit was already used by another
	// run of the same execution (which may be dispatching right now).
	ErrPveMutationAlreadyRun = errors.New("executor: pve mutation permit already used")
	// ErrPvePermitFinal is wrapped with ErrPveMutationDenied when the
	// permit can never authorize this run (gone, expired, its rollout
	// ended, or the approved target, action or artifact no longer
	// matches). Every other denial (a permit still pending, parameters
	// that differ in live facts such as capacity) may be transient and
	// leaves the approval usable.
	ErrPvePermitFinal = errors.New("executor: pve mutation permit can never authorize this run")
	// ErrPveMutationPlan is returned for approved parameters without a
	// valid step list.
	ErrPveMutationPlan = errors.New("executor: pve mutation has no valid step plan")
	// ErrPveDispatchUncertain is returned when a step may have reached the
	// remote but its UPID is not known; the step is reconciling, never
	// redispatched.
	ErrPveDispatchUncertain = errors.New("executor: pve mutation step outcome is uncertain; reconciling")
	// ErrPveTaskIDAmbiguous is returned by a PveJobTaskIDs when the task
	// ID a stored step's task must carry cannot be determined
	// unambiguously; the step is then never matched to a listed task.
	ErrPveTaskIDAmbiguous = errors.New("executor: pve step task id is ambiguous")
	// ErrPveStepFailed is returned when a step was refused or its task did
	// not finish with OK. Later steps are not dispatched.
	ErrPveStepFailed = errors.New("executor: pve mutation step failed")
	// ErrPveStepRunning is returned when a step's task is still running
	// when the wait ends; reconciliation observes it later.
	ErrPveStepRunning = errors.New("executor: pve mutation step still running; reconciling later")
	// ErrPveJobStore is returned when the durable job record could not be
	// written; nothing more is dispatched.
	ErrPveJobStore = errors.New("executor: pve job record unavailable")
	// ErrPveTargetBusy is returned when another mutation step on the same
	// target is still open (running or reconciling); nothing is
	// dispatched. Mutations of one target are serialized so a lost task is
	// never attributed to another job.
	ErrPveTargetBusy = errors.New("executor: another pve mutation of the target is still open")
	// ErrPveMutationRequest is returned for a request whose kind, node or
	// VMID is malformed; nothing is read from the remote.
	ErrPveMutationRequest = errors.New("executor: malformed pve mutation target")

	// ErrPveRejected is the sentinel a PveMutationClient wraps when the
	// remote answered and refused a mutation, so no task exists. Any other
	// dispatch error is treated as "may have been sent".
	ErrPveRejected = errors.New("pve: mutation refused by the remote")
	// ErrPveTaskNotFound is the sentinel a PveMutationClient wraps when the
	// remote answered that a task does not exist (its record is gone). Any
	// other TaskStatus error is treated as transient.
	ErrPveTaskNotFound = errors.New("pve: task not found on the remote")
)

// PveMutationStep is one typed write of a mutation, taken from the approved
// parameters. Method names a typed pveapi write method (allowlisted by the
// client); Args are its typed arguments. There is no URL or path input.
type PveMutationStep struct {
	Method string          `json:"method"`
	Args   json.RawMessage `json:"args"`
}

var pveStepMethodRe = regexp.MustCompile(`^[a-z][a-z0-9_.]{0,63}$`)

// PveTaskStatus is the observed status of one PVE task. ExitStatus is
// untrusted remote text.
type PveTaskStatus struct {
	Running    bool
	ExitStatus string
}

// PveMutationClient is the typed PVE surface the mutation engine uses. The
// pveapi write methods (PV-02) implement it; the token supplier passed in
// is the only credential available to each call.
type PveMutationClient interface {
	// TaskType returns the PVE task type (qmstart, qmclone, ...) the
	// remote creates for an allowlisted step method, and false for a method
	// it does not allow. A lost task is only identified by this type.
	TaskType(method string) (string, bool)
	// Dispatch sends one typed mutation step to the node with the action
	// token and returns the UPID of the task the remote created. An error
	// wrapping ErrPveRejected means the remote refused it; any other error
	// means the request may have been received.
	Dispatch(ctx context.Context, rm executordb.PveRemote, node string, step PveMutationStep, action pveapi.TokenSupplier) (string, error)
	// TaskStatus reads one task with the read token. An error wrapping
	// ErrPveTaskNotFound means the remote has no record of the task.
	TaskStatus(ctx context.Context, rm executordb.PveRemote, node, upid string, read pveapi.TokenSupplier) (PveTaskStatus, error)
	// RecentTasks lists the UPIDs of tasks on node that started at or after
	// since, with the read token.
	RecentTasks(ctx context.Context, rm executordb.PveRemote, node string, since time.Time, read pveapi.TokenSupplier) ([]string, error)
	// TargetState reads the live state of the target (a guest, or a node
	// when vmid is 0) with the read token.
	TargetState(ctx context.Context, rm executordb.PveRemote, kind, node string, vmid uint64, read pveapi.TokenSupplier) (PveTargetState, error)
}

// PveTargetState is the live state of a mutation target, read from the
// remote (untrusted; the engine validates every member).
type PveTargetState struct {
	// Node is the node the target lives on now.
	Node string
	// ConfigDigest is the hex SHA-256 of the target's complete
	// configuration.
	ConfigDigest string
	// Generation is the guest generation: the configuration digest PVE
	// returns with the guest's config (the "digest" member of
	// GET .../config, 40 lowercase hex). Empty for a node target; the
	// engine ignores it there.
	Generation string
	// Kind is the guest kind the remote reports ("qemu" or "lxc"); empty
	// for a node target or a client that does not report it. A reported
	// kind other than the requested one is a changed target.
	Kind string
	// Status is the guest's power status as the remote reports it
	// ("running", "stopped", ...); untrusted, compared only. Empty if not
	// reported.
	Status string
	// QMPStatus is a QEMU guest's QMP run state ("qmpstatus" of
	// GET .../status/current: "running", "paused", "suspended", ...);
	// untrusted, compared only. PVE reports a paused or suspended QEMU
	// guest with Status "running", so a power action on a QEMU guest
	// requires this to be "running" too; empty (not reported) fails
	// closed. Unused for LXC and node targets.
	QMPStatus string
}

// PveStepTaskIDer may be implemented by a PveMutationClient. TaskID returns
// the ID field (the VMID or storage) the PVE task of step carries. While
// the step runs, the engine then accepts and identifies only tasks with
// that ID, also for a node-level job.
type PveStepTaskIDer interface {
	TaskID(step PveMutationStep) (string, bool)
}

// PveJobTaskIDs resolves, from durable state, the ID field the PVE task of
// a stored step must carry. Reconciliation after a restart has only the
// stored job, not the step's arguments; for a node-level job (which binds
// no guest) this narrows the match to the guest the step acts on. ok false
// means the resolver does not narrow this job. An error wrapping
// ErrPveJobStore leaves the step for the next pass; any other error (such
// as ErrPveTaskIDAmbiguous) means the ID cannot be determined
// unambiguously, so no listed task is ever adopted for the step.
type PveJobTaskIDs interface {
	JobTaskID(job executordb.PveJob) (id string, ok bool, err error)
}

// pveSecrets is the part of the vault the engine needs.
type pveSecrets interface {
	State() (vault.State, error)
	OpenVersion(id string) ([]byte, int64, error)
}

// PveMutations dispatches and reconciles PVE mutations.
type PveMutations struct {
	DB     *executordb.DB
	Auth   *permit.Authority
	Vault  pveSecrets
	Client PveMutationClient
	// Now is the clock. Default: time.Now.
	Now func() time.Time
	// PollInterval is the task status interval. Default 2 s.
	PollInterval time.Duration
	// MaxWait bounds the wait for one step's task. Default 30 min.
	MaxWait time.Duration
	// Log receives non-secret audit events. Default: discarded.
	Log *slog.Logger
	// TaskIDs narrows the identification of lost node-level steps from
	// durable state (PveProvisioner implements it). Provisioning steps are
	// never identified without it.
	TaskIDs PveJobTaskIDs

	// powerBindings are the guest power and snapshot bindings of this
	// engine when the service has none shared with the authority (see
	// PveGuestPowerBindings); one engine, one set.
	powerBindings PveGuestPowerBindings

	// inflight counts the Run calls per execution ID; Reconcile leaves
	// their steps alone, so a step being dispatched right now is never
	// mistaken for one orphaned by a crash. One engine must serve both.
	mu       sync.Mutex
	inflight map[string]int
}

func (m *PveMutations) begin(executionID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.inflight == nil {
		m.inflight = make(map[string]int)
	}
	m.inflight[executionID]++
}

func (m *PveMutations) end(executionID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.inflight[executionID]--; m.inflight[executionID] <= 0 {
		delete(m.inflight, executionID)
	}
}

// inflight returns the number of runs (Run or Provision) of executionID
// in progress.
func (m *PveMutations) inflightRuns(executionID string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.inflight[executionID]
}

func (m *PveMutations) running(executionID string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.inflight[executionID] > 0
}

// PveMutationRequest selects one approved mutation. Kind, Node and VMID
// name the target; the registry identity, the action token version and the
// configuration digest are read by the executor itself.
type PveMutationRequest struct {
	Digest        canonical.Digest
	RemoteID      string
	Kind          string
	Node          string
	VMID          uint64
	ActionID      string
	ModuleVersion string
	Artifact      []byte
	// Parameters are the action parameters; they must carry the step plan
	// ({"steps":[{"method":...,"args":{...}}, ...], ...}).
	Parameters json.RawMessage
	// ExecutionID, if set, is the execution the caller prepared the run
	// for (for example the holder of a reservation); a permit with another
	// execution ID is refused before anything is dispatched.
	ExecutionID string

	// precheck, if set, checks the live state of the target (a typed
	// action's precondition, such as "guest running"). Run applies it to
	// the read made before authorization and again to a fresh read
	// immediately before each step's intent is recorded; a failure sends
	// nothing.
	precheck func(PveTargetState) error
	// liveCheck, if set, checks facts of the target that PveTargetState
	// does not carry (a guest's disk set, storage capabilities or snapshot
	// list) with a fresh read of its own, using the read token. Like
	// precheck it runs at proposal, before authorization and immediately
	// before each step's intent is recorded; a failure sends nothing.
	liveCheck pveLiveCheck
}

// pveLiveCheck is a typed action's own live precondition (see
// PveMutationRequest.liveCheck).
type pveLiveCheck func(ctx context.Context, rm executordb.PveRemote, live PveTargetState, read pveapi.TokenSupplier) error

// runLiveCheck applies check (if any) with the read token of rm.
func (m *PveMutations) runLiveCheck(ctx context.Context, rm executordb.PveRemote, live PveTargetState, check pveLiveCheck) error {
	if check == nil {
		return nil
	}
	read, err := m.readToken(rm)
	if err != nil {
		return err
	}
	return check(ctx, rm, live, read)
}

// PveMutationResult reports the durable job of one mutation.
type PveMutationResult struct {
	ExecutionID string
	Steps       []executordb.PveJob
	// PermitConsumed is set once the run consumed the single-use permit of
	// its execution: no later run of the execution can be authorized, so a
	// failure without a recorded step can never be retried.
	PermitConsumed bool
}

func (m *PveMutations) now() time.Time {
	if m.Now == nil {
		return time.Now()
	}
	return m.Now()
}

func (m *PveMutations) log() *slog.Logger {
	if m.Log == nil {
		return slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return m.Log
}

func (m *PveMutations) checkDeps() error {
	if m.DB == nil || m.Auth == nil || m.Vault == nil || m.Client == nil {
		return errors.New("executor: pve mutations: DB, Auth, Vault and Client are required")
	}
	st, err := m.Vault.State()
	if err != nil || st != vault.StateUnlocked {
		return vault.ErrLocked
	}
	return nil
}

// activeRemote loads the remote and checks it may be mutated.
func (m *PveMutations) activeRemote(remoteID string) (executordb.PveRemote, error) {
	rm, ok, err := m.DB.GetRemote(remoteID)
	if err != nil {
		return executordb.PveRemote{}, ErrPveJobStore
	}
	switch {
	case !ok || rm.State == executordb.StateRemoved:
		return executordb.PveRemote{}, executordb.ErrRemoteNotFound
	case rm.State != executordb.StateActive:
		return executordb.PveRemote{}, ErrPveRemoteChanged
	case rm.Credentials.ActionRef == "" || rm.Credentials.ActionVersion < 1:
		return executordb.PveRemote{}, ErrPveReadOnly
	case rm.Credentials.ActionRef != PveVaultID(rm.RemoteID, PvePurposeAction):
		return executordb.PveRemote{}, ErrPveRemoteChanged
	case rm.Credentials.ReadRef != PveVaultID(rm.RemoteID, PvePurposeRead) || rm.Credentials.ReadVersion < 1:
		return executordb.PveRemote{}, ErrPveRemoteChanged
	}
	return rm, nil
}

// sameRemote reports whether rm still has the identity the target binds.
func sameRemote(rm executordb.PveRemote, t permit.ProviderMutationTarget) bool {
	return rm.State == executordb.StateActive && rm.RemoteID == t.RemoteID && rm.TrustPin == t.TrustPin &&
		rm.TrustGeneration == t.TrustGeneration && rm.Credentials.ActionRef == t.CredentialRef &&
		rm.Credentials.ActionVersion == t.CredentialVersion && slices.Equal(rm.Endpoints, t.APIEndpoints)
}

// token opens one credential of rm at its registered version and returns a
// supplier of the Authorization header and the token's non-secret ID
// (user@realm!token), which PVE writes into the UPIDs of tasks the token
// starts. The secret never leaves the supplier.
func (m *PveMutations) token(ref string, version int64) (pveapi.TokenSupplier, string, error) {
	secret, v, err := m.Vault.OpenVersion(ref)
	if err != nil || v != version {
		clear(secret)
		return nil, "", ErrPveRemoteChanged
	}
	parts := pveTokenPattern.FindSubmatch(secret)
	if parts == nil {
		clear(secret)
		return nil, "", ErrPveRemoteChanged
	}
	principal := string(parts[1]) + "!" + string(parts[2])
	header := "PVEAPIToken=" + string(secret)
	clear(secret)
	return func(context.Context) (string, error) { return header, nil }, principal, nil
}

func (m *PveMutations) readToken(rm executordb.PveRemote) (pveapi.TokenSupplier, error) {
	tok, _, err := m.token(rm.Credentials.ReadRef, rm.Credentials.ReadVersion)
	return tok, err
}

// targetLive builds the exact target of req from the registry and a live
// read, and returns the live state it was built from. The caller-selected
// kind, node and VMID are validated before any read, so a malformed
// request never causes I/O with a credential.
func (m *PveMutations) targetLive(ctx context.Context, rm executordb.PveRemote, req PveMutationRequest) (permit.ProviderMutationTarget, PveTargetState, error) {
	if err := permit.ValidateProviderMutationShape(req.Kind, req.Node, req.VMID); err != nil {
		return permit.ProviderMutationTarget{}, PveTargetState{}, ErrPveMutationRequest
	}
	read, err := m.readToken(rm)
	if err != nil {
		return permit.ProviderMutationTarget{}, PveTargetState{}, err
	}
	live, err := m.Client.TargetState(ctx, rm, req.Kind, req.Node, req.VMID, read)
	if err != nil {
		return permit.ProviderMutationTarget{}, PveTargetState{}, ErrPveTargetChanged
	}
	if live.Node != req.Node || (live.Kind != "" && live.Kind != req.Kind) {
		return permit.ProviderMutationTarget{}, PveTargetState{}, ErrPveTargetChanged
	}
	generation := live.Generation
	if req.Kind == permit.ProviderKindNode {
		generation = ""
	}
	t := permit.ProviderMutationTarget{
		Version:  permit.PveTargetVersion,
		RemoteID: rm.RemoteID, TrustPin: rm.TrustPin, TrustGeneration: rm.TrustGeneration,
		CredentialRef: rm.Credentials.ActionRef, CredentialVersion: rm.Credentials.ActionVersion,
		APIEndpoints: slices.Clone(rm.Endpoints),
		Kind:         req.Kind, Node: live.Node, VMID: req.VMID, ConfigDigest: live.ConfigDigest, Generation: generation,
	}
	if err := t.Validate(); err != nil {
		return permit.ProviderMutationTarget{}, PveTargetState{}, ErrPveTargetChanged
	}
	return t, live, nil
}

// sameLiveTarget reports whether a fresh live read still shows the exact
// target t binds: same node, configuration, guest generation and kind.
func sameLiveTarget(live PveTargetState, t permit.ProviderMutationTarget) bool {
	if live.Node != t.Node || live.ConfigDigest != t.ConfigDigest || (live.Kind != "" && live.Kind != t.Kind) {
		return false
	}
	return t.Kind == permit.ProviderKindNode || live.Generation == t.Generation
}

// ProposalRequest builds the canonical request and parameters of a new
// mutation proposal for req from the registry and a live read, so the
// approval binds the exact current target. The caller proposes it with
// the authority (risk at least the executor minimum).
func (m *PveMutations) ProposalRequest(ctx context.Context, req PveMutationRequest, executionID string, risk canonical.Risk, stagePlanHash string, expiry time.Time) (canonical.Request, []byte, error) {
	if err := m.checkDeps(); err != nil {
		return canonical.Request{}, nil, err
	}
	rm, err := m.activeRemote(req.RemoteID)
	if err != nil {
		return canonical.Request{}, nil, err
	}
	steps, err := parsePveSteps(req.Parameters)
	if err != nil {
		return canonical.Request{}, nil, err
	}
	for _, s := range steps {
		if _, err := m.taskType(s); err != nil {
			return canonical.Request{}, nil, err
		}
	}
	t, live, err := m.targetLive(ctx, rm, req)
	if err != nil {
		return canonical.Request{}, nil, err
	}
	if req.precheck != nil {
		if err := req.precheck(live); err != nil {
			return canonical.Request{}, nil, err
		}
	}
	if err := m.runLiveCheck(ctx, rm, live, req.liveCheck); err != nil {
		return canonical.Request{}, nil, err
	}
	return permit.ProviderMutationRequest(mutationOf(req, t), executionID, risk, stagePlanHash, expiry)
}

func mutationOf(req PveMutationRequest, t permit.ProviderMutationTarget) permit.ProviderMutation {
	return permit.ProviderMutation{Target: t, ActionID: req.ActionID, ModuleVersion: req.ModuleVersion, Artifact: req.Artifact, Parameters: req.Parameters}
}

// parsePveSteps reads the step plan from action parameters.
func parsePveSteps(params []byte) ([]PveMutationStep, error) {
	var doc struct {
		Steps []PveMutationStep `json:"steps"`
	}
	if err := json.Unmarshal(params, &doc); err != nil || len(doc.Steps) == 0 || len(doc.Steps) > executordb.MaxPveJobSteps {
		return nil, ErrPveMutationPlan
	}
	for _, s := range doc.Steps {
		a := bytes.TrimSpace(s.Args)
		if !pveStepMethodRe.MatchString(s.Method) || len(a) == 0 || a[0] != '{' {
			return nil, ErrPveMutationPlan
		}
	}
	return doc.Steps, nil
}

// taskType returns the PVE task type the client expects for step. A
// guest snapshot step method is known only to a client that implements
// PveSnapshotClient; no other family can claim it.
func (m *PveMutations) taskType(step PveMutationStep) (string, error) {
	var tt string
	var ok bool
	if snapTT, isSnap := GuestSnapshotStepTaskType(step.Method); isSnap {
		_, client := m.Client.(PveSnapshotClient)
		tt, ok = snapTT, client
	} else {
		tt, ok = m.Client.TaskType(step.Method)
	}
	if !ok || !pveTaskTypeRe.MatchString(tt) {
		return "", ErrPveMutationPlan
	}
	return tt, nil
}

var pveTaskTypeRe = regexp.MustCompile(`^[a-z0-9]{1,32}$`)

// stepTaskID returns the ID field the PVE task of step carries, if known:
// from the snapshot step arguments, or from a client that implements
// PveStepTaskIDer.
func (m *PveMutations) stepTaskID(step PveMutationStep) (string, bool) {
	if _, isSnap := GuestSnapshotStepTaskType(step.Method); isSnap {
		return GuestSnapshotStepTaskID(step)
	}
	if ider, ok := m.Client.(PveStepTaskIDer); ok {
		return ider.TaskID(step)
	}
	return "", false
}

// dispatch sends one step: a guest snapshot step through the client's
// PveSnapshotClient surface (which rechecks the bound snapshot with the
// read token immediately before sending), everything else through
// Dispatch. A snapshot step on a client without that surface is refused
// before anything is sent.
func (m *PveMutations) dispatch(ctx context.Context, rm executordb.PveRemote, node string, step PveMutationStep, action, read pveapi.TokenSupplier) (string, error) {
	if _, isSnap := GuestSnapshotStepTaskType(step.Method); isSnap {
		sc, ok := m.Client.(PveSnapshotClient)
		if !ok {
			return "", fmt.Errorf("dispatch %s: %w", step.Method, ErrPveRejected)
		}
		return sc.DispatchSnapshot(ctx, rm, node, step, action, read)
	}
	return m.Client.Dispatch(ctx, rm, node, step, action)
}

// approvedSteps reads the step plan from the approved canonical binding.
func approvedSteps(binding []byte) ([]PveMutationStep, error) {
	var doc struct {
		Parameters json.RawMessage `json:"parameters"`
	}
	if err := json.Unmarshal(binding, &doc); err != nil {
		return nil, ErrPveMutationPlan
	}
	return parsePveSteps(doc.Parameters)
}

// requestDigest is the hex SHA-256 of the exact request one step sends:
// node and the canonical step.
func requestDigest(node string, step PveMutationStep) (string, error) {
	b, err := json.Marshal(struct {
		Node string          `json:"node"`
		Step PveMutationStep `json:"step"`
	}{node, step})
	if err != nil {
		return "", ErrPveMutationPlan
	}
	c, err := canonical.HashParameters(b)
	if err != nil {
		return "", ErrPveMutationPlan
	}
	return c, nil
}

// permitDenialFinal reports whether a permit denial code means the permit
// can never authorize the run. Unknown codes are not final: keeping state
// (a VMID reservation) until the proposal expires is the safe direction.
//
// Two codes are deliberately not final:
//   - CodeWrongState: the authority keeps only pending and approved
//     permits, so it means the permit is still pending and can yet be
//     approved (or the executor was locked after authorization). A used
//     permit answers CodeHostAlreadyRun, which Run maps to
//     ErrPveMutationAlreadyRun; a revoked or expired one is gone
//     (CodeNotFound, CodeExpired);
//   - CodeParametersMismatch: the bound parameters include live facts the
//     executor re-reads before every run (the capacity flags of a
//     provisioning), which can change back. The authority does not tell a
//     capacity change from another mismatch, so none is taken as final.
func permitDenialFinal(c permit.Code) bool {
	switch c {
	case permit.CodeNotFound, permit.CodeExpired,
		permit.CodeRolloutStopped, permit.CodeRolloutAborted, permit.CodeGateInvalid, permit.CodeStagePlan,
		permit.CodeInvalidRequest, permit.CodeTypedCountMismatch, permit.CodeTargetNotPermitted,
		permit.CodeArtifactMismatch, permit.CodeActionMismatch,
		permit.CodeCredentialMismatch:
		return true
	}
	return false
}

// Run executes one approved mutation. Before anything is sent it rebuilds
// the exact target from the registry and a live read and consumes the
// permit for it. For each step it then re-checks the claim (lock,
// revocation) and the registry, durably records the intent, dispatches
// with the action token, stores the returned UPID before going on and
// waits for the task. A lost response leaves the step reconciling; it is
// never sent again. Errors carry no remote text and no token.
func (m *PveMutations) Run(ctx context.Context, req PveMutationRequest) (PveMutationResult, error) {
	if err := m.checkDeps(); err != nil {
		return PveMutationResult{}, err
	}
	rm, err := m.activeRemote(req.RemoteID)
	if err != nil {
		return PveMutationResult{}, err
	}
	t, live, err := m.targetLive(ctx, rm, req)
	if err != nil {
		return PveMutationResult{}, err
	}
	if req.precheck != nil {
		// A failed precondition refuses the run before the permit is used.
		if err := req.precheck(live); err != nil {
			m.log().Warn("audit", "kind", "pve_mutation_precondition", "remote", rm.RemoteID, "action", req.ActionID, "node", t.Node, "vmid", t.VMID)
			return PveMutationResult{}, err
		}
	}
	if err := m.runLiveCheck(ctx, rm, live, req.liveCheck); err != nil {
		m.log().Warn("audit", "kind", "pve_mutation_precondition", "remote", rm.RemoteID, "action", req.ActionID, "node", t.Node, "vmid", t.VMID)
		return PveMutationResult{}, err
	}
	claim, err := m.Auth.AuthorizeProviderMutation(req.Digest, mutationOf(req, t))
	if err != nil {
		m.log().Warn("audit", "kind", "pve_mutation_denied", "remote", rm.RemoteID, "action", req.ActionID, "code", string(permit.CodeOf(err)))
		if permit.CodeOf(err) == permit.CodeHostAlreadyRun {
			return PveMutationResult{}, fmt.Errorf("%w: %w", ErrPveMutationDenied, ErrPveMutationAlreadyRun)
		}
		if permitDenialFinal(permit.CodeOf(err)) {
			return PveMutationResult{}, fmt.Errorf("%w: %w", ErrPveMutationDenied, ErrPvePermitFinal)
		}
		return PveMutationResult{}, ErrPveMutationDenied
	}
	if req.ExecutionID != "" && claim.ExecutionID != req.ExecutionID {
		m.log().Warn("audit", "kind", "pve_mutation_denied", "remote", rm.RemoteID, "action", req.ActionID, "code", "execution_mismatch")
		return PveMutationResult{}, ErrPveMutationDenied
	}
	// From here the permit of this execution is used.
	res := PveMutationResult{ExecutionID: claim.ExecutionID, PermitConsumed: true}
	steps, err := approvedSteps(claim.Parameters)
	if err != nil {
		return res, err
	}
	m.begin(claim.ExecutionID)
	defer m.end(claim.ExecutionID)
	digest := hex.EncodeToString(req.Digest[:])
	for i, step := range steps {
		n := i + 1
		err := m.runStep(ctx, claim, t, digest, req.ActionID, n, step, req.precheck, req.liveCheck)
		if n == 1 && errors.Is(err, ErrPveTargetBusy) && claim.Release("target busy") {
			// Nothing was recorded or sent: another mutation of the target
			// still holds it. The approval stays usable for a later run.
			m.log().Info("audit", "kind", "pve_mutation_permit_released", "remote", t.RemoteID, "execution", claim.ExecutionID, "reason", "target busy")
			res.PermitConsumed = false
		}
		recorded, serr := m.DB.PveJobSteps(claim.ExecutionID)
		if serr != nil {
			// What was recorded is unknown: stop and report a store
			// failure; callers must not take the result as complete.
			if err == nil {
				err = ErrPveJobStore
			}
			return res, err
		}
		res.Steps = recorded
		if err != nil {
			return res, err
		}
	}
	m.log().Info("audit", "kind", "pve_mutation_done", "remote", t.RemoteID, "action", req.ActionID, "execution", claim.ExecutionID)
	return res, nil
}

func (m *PveMutations) runStep(ctx context.Context, claim permit.MutationClaim, t permit.ProviderMutationTarget, digest, action string, n int, step PveMutationStep, precheck func(PveTargetState) error, liveCheck pveLiveCheck) error {
	// Lock or revocation since authorization stops undispatched work.
	if err := claim.Check(); err != nil {
		return ErrPveMutationDenied
	}
	rm, ok, err := m.DB.GetRemote(t.RemoteID)
	if err != nil {
		return ErrPveJobStore
	}
	if !ok || !sameRemote(rm, t) {
		return ErrPveRemoteChanged
	}
	rd, err := requestDigest(t.Node, step)
	if err != nil {
		return err
	}
	taskType, err := m.taskType(step)
	if err != nil {
		return err
	}
	actionTok, taskUser, err := m.token(rm.Credentials.ActionRef, rm.Credentials.ActionVersion)
	if err != nil {
		return err
	}
	readTok, err := m.readToken(rm)
	if err != nil {
		return err
	}
	// A node-level job does not bind a guest; a client that knows the task
	// ID of the step (the guest or storage it names) narrows the match, so a
	// returned task of another guest on the node is never taken for this
	// step. A lost task is identified with narrowTaskID instead.
	wantID, _ := m.stepTaskID(step)
	if precheck != nil || liveCheck != nil {
		// Identity and state are read again right before the intent: a
		// guest that changed since authorization gets nothing.
		live, err := m.Client.TargetState(ctx, rm, t.Kind, t.Node, t.VMID, readTok)
		if err != nil || !sameLiveTarget(live, t) {
			m.log().Warn("audit", "kind", "pve_mutation_target_changed", "remote", t.RemoteID, "node", t.Node, "vmid", t.VMID, "execution", claim.ExecutionID, "step", n)
			return ErrPveTargetChanged
		}
		if precheck != nil {
			if err := precheck(live); err != nil {
				m.log().Warn("audit", "kind", "pve_mutation_precondition", "remote", t.RemoteID, "node", t.Node, "vmid", t.VMID, "execution", claim.ExecutionID, "step", n)
				return err
			}
		}
		if liveCheck != nil {
			if err := liveCheck(ctx, rm, live, readTok); err != nil {
				m.log().Warn("audit", "kind", "pve_mutation_precondition", "remote", t.RemoteID, "node", t.Node, "vmid", t.VMID, "execution", claim.ExecutionID, "step", n)
				return err
			}
		}
	}
	job := executordb.PveJob{
		ExecutionID: claim.ExecutionID, Step: n, Digest: digest, Action: action, RemoteID: t.RemoteID,
		TrustGeneration: t.TrustGeneration, Kind: t.Kind, Node: t.Node, VMID: t.VMID, RequestDigest: rd,
		TaskType: taskType, TaskUser: taskUser,
	}
	// The intent is durable (synchronous=FULL) before anything is sent.
	if err := m.DB.CreatePveJobIntent(job); err != nil {
		if errors.Is(err, executordb.ErrPveTargetBusy) {
			m.log().Warn("audit", "kind", "pve_mutation_target_busy", "remote", t.RemoteID, "node", t.Node, "vmid", t.VMID, "execution", claim.ExecutionID, "step", n)
			return ErrPveTargetBusy
		}
		m.log().Error("pve job intent not recorded", "execution", claim.ExecutionID, "step", n)
		return ErrPveJobStore
	}
	// A lock that raced the intent still stops the dispatch.
	if err := claim.Check(); err != nil {
		_ = m.DB.FinishPveJob(claim.ExecutionID, n, executordb.PveJobFailed, "not dispatched: authorization withdrawn")
		return ErrPveMutationDenied
	}
	m.log().Info("audit", "kind", "pve_mutation_dispatch", "remote", t.RemoteID, "node", t.Node, "vmid", t.VMID, "action", action, "execution", claim.ExecutionID, "step", n, "method", step.Method)
	upid, err := m.dispatch(ctx, rm, t.Node, step, actionTok, readTok)
	if errors.Is(err, ErrPveRejected) {
		_ = m.DB.FinishPveJob(claim.ExecutionID, n, executordb.PveJobFailed, "refused by the remote")
		return ErrPveStepFailed
	}
	if err != nil {
		// Lost response: never retry, identify the task instead.
		return m.reconcileLost(ctx, rm, job, readTok, &step)
	}
	u, ok := executordb.ParsePveUPID(upid)
	if !ok || !taskMatches(u, job) || (wantID != "" && u.ID != wantID) {
		// A malformed or foreign task ID cannot be observed as this
		// step's task; treat it as lost.
		return m.reconcileLost(ctx, rm, job, readTok, &step)
	}
	err = m.DB.RecordPveJobUPID(claim.ExecutionID, n, upid, u.Node)
	if errors.Is(err, executordb.ErrPveUPIDRecorded) {
		// The remote answered with another step's task: not ours.
		return m.reconcileLost(ctx, rm, job, readTok, &step)
	}
	if err != nil {
		_ = m.DB.MarkPveJobReconciling(claim.ExecutionID, n)
		m.log().Error("pve job upid not recorded", "execution", claim.ExecutionID, "step", n)
		return ErrPveJobStore
	}
	job.UPID, job.TaskNode = upid, u.Node
	return m.await(ctx, rm, job, readTok)
}

// reconcileLost handles a step whose dispatch outcome is unknown.
func (m *PveMutations) reconcileLost(ctx context.Context, rm executordb.PveRemote, job executordb.PveJob, read pveapi.TokenSupplier, step *PveMutationStep) error {
	if err := m.DB.MarkPveJobReconciling(job.ExecutionID, job.Step); err != nil {
		return ErrPveJobStore
	}
	m.log().Warn("audit", "kind", "pve_mutation_reconciling", "remote", job.RemoteID, "execution", job.ExecutionID, "step", job.Step)
	// The stored record (intent time) is what identification matches.
	stored, ok, err := m.DB.PveJob(job.ExecutionID, job.Step)
	if err != nil || !ok {
		return ErrPveJobStore
	}
	job = stored
	if err := m.identify(ctx, rm, &job, read, step); err != nil {
		return err
	}
	if job.UPID == "" {
		return ErrPveDispatchUncertain
	}
	return m.await(ctx, rm, job, read)
}

// narrowTaskID returns the task ID a step's task must carry ("" for no
// narrowing). The client derives it from the step's arguments during a
// Run; TaskIDs derives it from durable state, also after a restart, and
// both must agree. A provisioning step is never left unnarrowed: its job
// is node-level, so without an ID a task of another guest made with the
// same action token on the node could be taken for it.
func (m *PveMutations) narrowTaskID(job executordb.PveJob, step *PveMutationStep) (string, error) {
	var stepID string
	if step != nil {
		stepID, _ = m.stepTaskID(*step)
	}
	if m.TaskIDs != nil {
		id, ok, err := m.TaskIDs.JobTaskID(job)
		if errors.Is(err, ErrPveJobStore) {
			return "", ErrPveJobStore
		}
		if err != nil {
			return "", ErrPveTaskIDAmbiguous
		}
		if ok {
			if id == "" || (stepID != "" && id != stepID) {
				return "", ErrPveTaskIDAmbiguous
			}
			return id, nil
		}
	}
	if job.Action == PveGuestProvisionAction {
		return "", ErrPveTaskIDAmbiguous
	}
	return stepID, nil
}

// taskMatches reports whether u can be the task of job: same node, the
// step's task type, started by the step's action token and, for a guest,
// naming the guest.
func taskMatches(u executordb.PveUPID, job executordb.PveJob) bool {
	if u.Node != job.Node || u.Type != job.TaskType || u.User != job.TaskUser {
		return false
	}
	return job.VMID == 0 || u.ID == fmt.Sprint(job.VMID)
}

// identify looks for the exact task of a step whose UPID is unknown. One
// candidate (same node, guest, task type, action token and start window,
// not already recorded for any step) is adopted; several mark the step
// unknown, and none marks it unknown only once the start window has
// passed (until then it stays reconciling). Nothing is ever dispatched. A read error leaves the step
// reconciling for the next pass.
// step is the step's arguments when a Run has them (nil after a restart);
// the candidate must also carry the task ID narrowTaskID derives. A task
// ID that cannot be determined unambiguously matches no task.
func (m *PveMutations) identify(ctx context.Context, rm executordb.PveRemote, job *executordb.PveJob, read pveapi.TokenSupplier, step *PveMutationStep) error {
	since := job.CreatedAt.Add(-pveTaskMatchSkew)
	wantID, err := m.narrowTaskID(*job, step)
	if errors.Is(err, ErrPveJobStore) {
		return ErrPveJobStore
	}
	if err != nil {
		if m.now().Before(job.CreatedAt.Add(pveTaskMatchWindow + pveTaskMatchSkew)) {
			return ErrPveDispatchUncertain
		}
		if err := m.DB.FinishPveJob(job.ExecutionID, job.Step, executordb.PveJobUnknown, ""); err != nil {
			return ErrPveJobStore
		}
		m.log().Warn("audit", "kind", "pve_mutation_unknown", "remote", job.RemoteID, "execution", job.ExecutionID, "step", job.Step, "reason", "task id ambiguous")
		return ErrPveDispatchUncertain
	}
	upids, err := m.Client.RecentTasks(ctx, rm, job.Node, since, read)
	if err != nil {
		return ErrPveDispatchUncertain
	}
	// Every listed task is filtered; a second match already makes the
	// step ambiguous, so the scan stops there.
	var match []string
	for _, upid := range upids {
		u, ok := executordb.ParsePveUPID(upid)
		if !ok || !taskMatches(u, *job) || (wantID != "" && u.ID != wantID) || u.StartTime.Before(since) || u.StartTime.After(job.CreatedAt.Add(pveTaskMatchWindow)) {
			continue
		}
		used, err := m.DB.PveUPIDRecorded(upid)
		if err != nil {
			return ErrPveJobStore
		}
		if used {
			// The task of another step (of this or any job) is never ours.
			continue
		}
		if match = append(match, upid); len(match) > 1 {
			break
		}
	}
	// The narrowing was decided before the listing; a provisioning that
	// started meanwhile (for example another clone of the same template)
	// can make it ambiguous. Decide again now that the candidates are
	// known: a changed answer adopts nothing.
	if len(match) == 1 {
		again, err := m.narrowTaskID(*job, step)
		if errors.Is(err, ErrPveJobStore) {
			return ErrPveJobStore
		}
		if err != nil || again != wantID {
			m.log().Warn("audit", "kind", "pve_mutation_narrowing_changed", "remote", job.RemoteID, "execution", job.ExecutionID, "step", job.Step)
			match = append(match, "")
		}
	}
	if len(match) == 0 && m.now().Before(job.CreatedAt.Add(pveTaskMatchWindow+pveTaskMatchSkew)) {
		// The task may still appear: identification is not complete while
		// its start window is open, so the step stays reconciling.
		return ErrPveDispatchUncertain
	}
	if len(match) != 1 {
		if err := m.DB.FinishPveJob(job.ExecutionID, job.Step, executordb.PveJobUnknown, ""); err != nil {
			return ErrPveJobStore
		}
		m.log().Warn("audit", "kind", "pve_mutation_unknown", "remote", job.RemoteID, "execution", job.ExecutionID, "step", job.Step, "candidates", len(match))
		return ErrPveDispatchUncertain
	}
	if err := m.DB.RecordPveJobUPID(job.ExecutionID, job.Step, match[0], job.Node); err != nil {
		return ErrPveJobStore
	}
	job.UPID, job.TaskNode = match[0], job.Node
	return nil
}

// await polls the task of a step with a stored UPID until it stops, the
// wait bound passes or ctx ends (the step then stays open).
func (m *PveMutations) await(ctx context.Context, rm executordb.PveRemote, job executordb.PveJob, read pveapi.TokenSupplier) error {
	interval, maxWait := m.PollInterval, m.MaxWait
	if interval <= 0 {
		interval = pveTaskPollInterval
	}
	if maxWait <= 0 {
		maxWait = pveTaskMaxWait
	}
	deadline := m.now().Add(maxWait)
	for {
		done, err := m.observe(ctx, rm, job, read)
		if done || err != nil {
			return err
		}
		if m.now().After(deadline) {
			return ErrPveStepRunning
		}
		select {
		case <-ctx.Done():
			return ErrPveStepRunning
		case <-time.After(interval):
		}
	}
}

// observe reads a step's task once and records a terminal state.
func (m *PveMutations) observe(ctx context.Context, rm executordb.PveRemote, job executordb.PveJob, read pveapi.TokenSupplier) (bool, error) {
	st, err := m.Client.TaskStatus(ctx, rm, job.TaskNode, job.UPID, read)
	if errors.Is(err, ErrPveTaskNotFound) {
		// The task record is gone: its outcome can never be observed.
		if err := m.DB.FinishPveJob(job.ExecutionID, job.Step, executordb.PveJobUnknown, ""); err != nil {
			return true, ErrPveJobStore
		}
		m.log().Warn("audit", "kind", "pve_mutation_unknown", "remote", job.RemoteID, "execution", job.ExecutionID, "step", job.Step, "reason", "task record gone")
		return true, ErrPveDispatchUncertain
	}
	if err != nil {
		// Unreadable task records preserve uncertainty.
		return false, nil
	}
	if st.Running {
		return false, nil
	}
	state := executordb.PveJobFailed
	if st.ExitStatus == pveTaskOK {
		state = executordb.PveJobSucceeded
	}
	if err := m.DB.FinishPveJob(job.ExecutionID, job.Step, state, st.ExitStatus); err != nil {
		return true, ErrPveJobStore
	}
	m.log().Info("audit", "kind", "pve_mutation_step", "remote", job.RemoteID, "execution", job.ExecutionID, "step", job.Step, "state", state)
	if state != executordb.PveJobSucceeded {
		return true, ErrPveStepFailed
	}
	return true, nil
}

// Reconcile observes every open step once, after a restart or a lost
// response, with the read token. A step without a UPID is identified or
// marked unknown; a step with one is polled once. Persisted steps confer
// observation authority only: Reconcile never dispatches, and a job whose
// step finishes here is not continued with its next step. It needs the
// vault unlocked and skips remotes that are not active (trust failure); a
// step recorded under an older trust generation is observed through the
// remote's current pin after a re-pin, with an audit event. It also
// skips the steps of jobs a Run of the same engine is executing.
func (m *PveMutations) Reconcile(ctx context.Context) error {
	if m.DB == nil || m.Vault == nil || m.Client == nil {
		return errors.New("executor: pve mutations: DB, Vault and Client are required")
	}
	if st, err := m.Vault.State(); err != nil || st != vault.StateUnlocked {
		return vault.ErrLocked
	}
	open, err := m.DB.OpenPveJobs()
	if err != nil {
		return ErrPveJobStore
	}
	for _, job := range open {
		if err := ctx.Err(); err != nil {
			return err
		}
		if m.running(job.ExecutionID) {
			// A Run of this engine owns the step (it may be dispatching
			// right now); it observes the step itself.
			continue
		}
		rm, ok, err := m.DB.GetRemote(job.RemoteID)
		if err != nil {
			return ErrPveJobStore
		}
		if !ok || rm.State != executordb.StateActive || rm.TrustGeneration < job.TrustGeneration {
			// No pinned identity to observe through; the step stays open.
			continue
		}
		if rm.TrustGeneration > job.TrustGeneration {
			// The remote was re-pinned after the step's intent. Observing
			// through the current pin is a read with the read token, and
			// identification stays bound to the step's stored node, guest,
			// task type and token user; otherwise the step (and its target)
			// would stay open forever.
			m.log().Warn("audit", "kind", "pve_mutation_reconcile_repinned", "remote", job.RemoteID, "execution", job.ExecutionID, "step", job.Step,
				"step_gen", job.TrustGeneration, "gen", rm.TrustGeneration)
		}
		read, err := m.readToken(rm)
		if err != nil {
			continue
		}
		if job.UPID == "" {
			if job.State == executordb.PveJobDispatching {
				if err := m.DB.MarkPveJobReconciling(job.ExecutionID, job.Step); err != nil {
					return ErrPveJobStore
				}
			}
			if err := m.identify(ctx, rm, &job, read, nil); errors.Is(err, ErrPveJobStore) {
				return err
			}
			if job.UPID == "" {
				continue
			}
		}
		if _, err := m.observe(ctx, rm, job, read); errors.Is(err, ErrPveJobStore) {
			return err
		}
	}
	return nil
}

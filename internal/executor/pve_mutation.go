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
	// ErrPveMutationPlan is returned for approved parameters without a
	// valid step list.
	ErrPveMutationPlan = errors.New("executor: pve mutation has no valid step plan")
	// ErrPveDispatchUncertain is returned when a step may have reached the
	// remote but its UPID is not known; the step is reconciling, never
	// redispatched.
	ErrPveDispatchUncertain = errors.New("executor: pve mutation step outcome is uncertain; reconciling")
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
	// TargetState reads the live node and the hex SHA-256 of the complete
	// configuration of the target (a guest, or a node when vmid is 0),
	// with the read token.
	TargetState(ctx context.Context, rm executordb.PveRemote, kind, node string, vmid uint64, read pveapi.TokenSupplier) (liveNode, configDigest string, err error)
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
}

// PveMutationResult reports the durable job of one mutation.
type PveMutationResult struct {
	ExecutionID string
	Steps       []executordb.PveJob
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

// target builds the exact target of req from the registry and a live read.
func (m *PveMutations) target(ctx context.Context, rm executordb.PveRemote, req PveMutationRequest) (permit.ProviderMutationTarget, error) {
	read, err := m.readToken(rm)
	if err != nil {
		return permit.ProviderMutationTarget{}, err
	}
	liveNode, digest, err := m.Client.TargetState(ctx, rm, req.Kind, req.Node, req.VMID, read)
	if err != nil {
		return permit.ProviderMutationTarget{}, ErrPveTargetChanged
	}
	if liveNode != req.Node {
		return permit.ProviderMutationTarget{}, ErrPveTargetChanged
	}
	t := permit.ProviderMutationTarget{
		RemoteID: rm.RemoteID, TrustPin: rm.TrustPin, TrustGeneration: rm.TrustGeneration,
		CredentialRef: rm.Credentials.ActionRef, CredentialVersion: rm.Credentials.ActionVersion,
		APIEndpoints: slices.Clone(rm.Endpoints),
		Kind:         req.Kind, Node: liveNode, VMID: req.VMID, ConfigDigest: digest,
	}
	if err := t.Validate(); err != nil {
		return permit.ProviderMutationTarget{}, ErrPveTargetChanged
	}
	return t, nil
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
	t, err := m.target(ctx, rm, req)
	if err != nil {
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

// taskType returns the PVE task type the client expects for step.
func (m *PveMutations) taskType(step PveMutationStep) (string, error) {
	tt, ok := m.Client.TaskType(step.Method)
	if !ok || !pveTaskTypeRe.MatchString(tt) {
		return "", ErrPveMutationPlan
	}
	return tt, nil
}

var pveTaskTypeRe = regexp.MustCompile(`^[a-z0-9]{1,32}$`)

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
	t, err := m.target(ctx, rm, req)
	if err != nil {
		return PveMutationResult{}, err
	}
	claim, err := m.Auth.AuthorizeProviderMutation(req.Digest, mutationOf(req, t))
	if err != nil {
		m.log().Warn("audit", "kind", "pve_mutation_denied", "remote", rm.RemoteID, "action", req.ActionID, "code", string(permit.CodeOf(err)))
		return PveMutationResult{}, ErrPveMutationDenied
	}
	steps, err := approvedSteps(claim.Parameters)
	if err != nil {
		return PveMutationResult{}, err
	}
	m.begin(claim.ExecutionID)
	defer m.end(claim.ExecutionID)
	res := PveMutationResult{ExecutionID: claim.ExecutionID}
	digest := hex.EncodeToString(req.Digest[:])
	for i, step := range steps {
		n := i + 1
		err := m.runStep(ctx, claim, t, digest, req.ActionID, n, step)
		res.Steps, _ = m.DB.PveJobSteps(claim.ExecutionID)
		if err != nil {
			return res, err
		}
	}
	m.log().Info("audit", "kind", "pve_mutation_done", "remote", t.RemoteID, "action", req.ActionID, "execution", claim.ExecutionID)
	return res, nil
}

func (m *PveMutations) runStep(ctx context.Context, claim permit.MutationClaim, t permit.ProviderMutationTarget, digest, action string, n int, step PveMutationStep) error {
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
	upid, err := m.Client.Dispatch(ctx, rm, t.Node, step, actionTok)
	if errors.Is(err, ErrPveRejected) {
		_ = m.DB.FinishPveJob(claim.ExecutionID, n, executordb.PveJobFailed, "refused by the remote")
		return ErrPveStepFailed
	}
	if err != nil {
		// Lost response: never retry, identify the task instead.
		return m.reconcileLost(ctx, rm, job, readTok)
	}
	u, ok := executordb.ParsePveUPID(upid)
	if !ok || !taskMatches(u, job) {
		// A malformed or foreign task ID cannot be observed as this
		// step's task; treat it as lost.
		return m.reconcileLost(ctx, rm, job, readTok)
	}
	err = m.DB.RecordPveJobUPID(claim.ExecutionID, n, upid, u.Node)
	if errors.Is(err, executordb.ErrPveUPIDRecorded) {
		// The remote answered with another step's task: not ours.
		return m.reconcileLost(ctx, rm, job, readTok)
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
func (m *PveMutations) reconcileLost(ctx context.Context, rm executordb.PveRemote, job executordb.PveJob, read pveapi.TokenSupplier) error {
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
	if err := m.identify(ctx, rm, &job, read); err != nil {
		return err
	}
	if job.UPID == "" {
		return ErrPveDispatchUncertain
	}
	return m.await(ctx, rm, job, read)
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
func (m *PveMutations) identify(ctx context.Context, rm executordb.PveRemote, job *executordb.PveJob, read pveapi.TokenSupplier) error {
	since := job.CreatedAt.Add(-pveTaskMatchSkew)
	upids, err := m.Client.RecentTasks(ctx, rm, job.Node, since, read)
	if err != nil {
		return ErrPveDispatchUncertain
	}
	// Every listed task is filtered; a second match already makes the
	// step ambiguous, so the scan stops there.
	var match []string
	for _, upid := range upids {
		u, ok := executordb.ParsePveUPID(upid)
		if !ok || !taskMatches(u, *job) || u.StartTime.Before(since) || u.StartTime.After(job.CreatedAt.Add(pveTaskMatchWindow)) {
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
// vault unlocked and skips remotes that are not active (trust failure), and
// it skips the steps of jobs a Run of the same engine is executing.
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
		if !ok || rm.State != executordb.StateActive || rm.TrustGeneration != job.TrustGeneration {
			// No pinned identity to observe through; the step stays open.
			continue
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
			if err := m.identify(ctx, rm, &job, read); errors.Is(err, ErrPveJobStore) {
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

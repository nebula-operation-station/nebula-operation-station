// SPDX-License-Identifier: AGPL-3.0-or-later

package executions

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/actions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// Batch planning (ADR 0007 E13). The server expands a requested change
// plan into one member per action and host (12 updates and 3 container
// restarts are 15 members, never a wildcard), freezes every member's exact
// request, proposes the complete plan with the E19b ProposeBatch RPC and
// stores it with one outcome per member. The executor derives the risk,
// holds the approval and every member permit; the server only records the
// plan and what happened.
//
// A batch is not a transaction: every member keeps its own outcome. The
// server never retries, redispatches or rolls back a member; that needs a
// new batch with a fresh approval.

// Batch limits (canonical batch-v1 bounds; repeated here so the planner
// refuses an oversize plan before it asks the executor).
const (
	MaxBatchMembers = canonical.MaxBatchMembers
	MaxBatchStages  = canonical.MaxBatchStages
	// maxBatchList bounds the batch list page.
	maxBatchList = 200
	// maxContainerBindingAge is how old the docker.inspect observation a
	// container member is bound to may be.
	maxContainerBindingAge = time.Hour
	// maxBatchDetail bounds a stored outcome detail (the column allows 1000).
	maxBatchDetail = 1000
)

// Errors of batch planning. Callers branch on them.
var (
	ErrBatchCredentials = errors.New("the executor's credential versions could not be read")
	ErrBatchNotFound    = errors.New("batch not found")
	ErrBatchNotPending  = errors.New("the batch is not waiting for approval")
	ErrBatchCritical    = errors.New("CRITICAL members cannot be approved in a batch")
	ErrBatchAnswer      = errors.New("the executor's batch answer does not match the proposed plan")
	ErrBatchContainer   = errors.New("no fresh container details for this container; refresh them first")
	// ErrBatchExecutionUnavailable refuses a proposal or approval because
	// the executor does not advertise batch execution: a batch approved
	// there would never run.
	ErrBatchExecutionUnavailable = errors.New("the executor does not run batches")
	// ErrBatchExecutionUnknown refuses a proposal or approval because the
	// executor could not be asked whether it runs batches (transient).
	ErrBatchExecutionUnknown = errors.New("the executor could not be asked whether it runs batches; try again")
)

// BatchInputError describes an invalid batch request (shown to the user).
type BatchInputError struct{ Reason string }

func (e *BatchInputError) Error() string { return e.Reason }

func batchInput(format string, args ...any) error {
	return &BatchInputError{Reason: fmt.Sprintf(format, args...)}
}

// BatchCriticalError names the CRITICAL members of a refused proposal.
// The admin must remove them and approve them separately; nothing of the
// batch was approved.
type BatchCriticalError struct {
	Members []BatchMemberView
}

func (e *BatchCriticalError) Error() string {
	ids := make([]string, len(e.Members))
	for i, m := range e.Members {
		ids[i] = m.MemberID
	}
	return fmt.Sprintf("%v: %s", ErrBatchCritical, strings.Join(ids, ", "))
}

// Unwrap permits errors.Is(err, ErrBatchCritical).
func (e *BatchCriticalError) Unwrap() error { return ErrBatchCritical }

// BatchExecutor is the batch part of the executor client (server role).
type BatchExecutor interface {
	ListHostKeys(ctx context.Context, in *pb.ListHostKeysRequest, opts ...grpc.CallOption) (*pb.ListHostKeysResponse, error)
	ProposeBatch(ctx context.Context, in *pb.ProposeBatchRequest, opts ...grpc.CallOption) (*pb.ProposeBatchResponse, error)
	CommitBatch(ctx context.Context, in *pb.CommitBatchRequest, opts ...grpc.CallOption) (*pb.CommitBatchResponse, error)
	GetBatchStatus(ctx context.Context, in *pb.GetBatchStatusRequest, opts ...grpc.CallOption) (*pb.GetBatchStatusResponse, error)
}

// ContainerBindings resolves the exact container incarnation a container
// member is bound to.
type ContainerBindings interface {
	ContainerBinding(ctx context.Context, hostID, containerID string) (canonical.BatchContainer, error)
}

// BatchOptions are the dependencies of a batch planner.
type BatchOptions struct {
	Exec  BatchExecutor
	DB    *sql.DB
	Hosts Hosts
	Log   *slog.Logger
	// Now defaults to time.Now.
	Now func() time.Time
	// CredentialVersion returns the executor's version of a credential
	// reference. Nil makes every proposal fail with ErrBatchCredentials:
	// a batch never binds a guessed version.
	CredentialVersion func(ctx context.Context, ref string) (uint64, error)
	// Containers resolves container incarnations. Nil uses the latest
	// docker.inspect results in the execution history (InspectBindings).
	Containers ContainerBindings
	// Actions resolves module and runbook actions at an exact version
	// (Service.Action). Nil limits batches to the built-in actions.
	Actions ActionResolver
}

// ActionResolver resolves a module or runbook action at an exact version.
// Service satisfies it.
type ActionResolver interface {
	Action(ctx context.Context, id, version string) (actions.Action, bool, error)
}

// Batches plans, proposes and follows batches. It is safe for concurrent
// use.
type Batches struct {
	exec       BatchExecutor
	db         *sql.DB
	hosts      Hosts
	log        *slog.Logger
	now        func() time.Time
	credVer    func(ctx context.Context, ref string) (uint64, error)
	containers ContainerBindings
	actions    ActionResolver
}

// NewBatches returns a batch planner.
func NewBatches(o BatchOptions) (*Batches, error) {
	if o.Exec == nil || o.DB == nil || o.Hosts == nil {
		return nil, errors.New("batches: executor, database and inventory are required")
	}
	b := &Batches{exec: o.Exec, db: o.DB, hosts: o.Hosts, log: o.Log, now: o.Now, credVer: o.CredentialVersion, containers: o.Containers, actions: o.Actions}
	if b.log == nil {
		b.log = slog.New(slog.DiscardHandler)
	}
	if b.now == nil {
		b.now = time.Now
	}
	if b.containers == nil {
		b.containers = &InspectBindings{DB: o.DB, Now: b.now}
	}
	return b, nil
}

// BatchMemberSpec is one requested member: one action on one host.
type BatchMemberSpec struct {
	ActionID string
	// Version is the exact module or runbook version (for example "1.0.0",
	// or "3.0.0" for runbook version 3). Empty selects the built-in action;
	// a module or runbook action always needs it, so the frozen plan never
	// binds "whatever is latest".
	Version string
	HostID  string
	Params  map[string]string
}

// BatchStageSpec is one requested stage. Thresholds are absolute counts;
// zero (the default) stops all undispatched work on the first failed or
// unreachable member.
type BatchStageSpec struct {
	Gate                 string
	FailureThreshold     int
	UnreachableThreshold int
	Members              []BatchMemberSpec
}

// BatchRequest is a requested batch: its stages in order, every member
// listed explicitly.
type BatchRequest struct {
	Stages []BatchStageSpec
}

// containerActions bind an existing container incarnation; their
// "container" parameter must be the full 64-hex container ID.
var containerActions = map[string]bool{
	"docker.inspect": true, "docker.restart": true, "docker.stop": true, "docker.start": true,
	"docker.logs": true, "docker.stats": true, "docker.check_updates": true,
}

// batchExcludedActions are never batch members: docker.logs returns host
// output that may hold secrets, and docker.compose_update recreates
// containers without an incarnation binding the batch contract can freeze.
var batchExcludedActions = map[string]string{
	"docker.logs":           "container logs are not available in a batch",
	"docker.compose_update": "Compose updates recreate containers and are not available in a batch",
}

var fullContainerIDRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

// plannedMember is one expanded member before the executor sees it.
type plannedMember struct {
	stage  int
	action actions.Action
	params []byte
	member canonical.BatchMember
	pin    *pb.HostKeyPin
}

// plan expands and validates req into a canonical batch-v1 document. It
// never drops, merges or reorders members.
func (b *Batches) plan(ctx context.Context, req BatchRequest) (canonical.Batch, []plannedMember, error) {
	if len(req.Stages) == 0 {
		return canonical.Batch{}, nil, batchInput("add at least one member")
	}
	if len(req.Stages) > MaxBatchStages {
		return canonical.Batch{}, nil, batchInput("at most %d stages per batch; split the work into separately reviewed batches", MaxBatchStages)
	}
	total := 0
	for _, st := range req.Stages {
		total += len(st.Members)
	}
	if total == 0 {
		return canonical.Batch{}, nil, batchInput("add at least one member")
	}
	if total > MaxBatchMembers {
		return canonical.Batch{}, nil, batchInput("%d members exceed the limit of %d; split the work into separately reviewed batches", total, MaxBatchMembers)
	}
	cctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	pins, err := b.exec.ListHostKeys(cctx, &pb.ListHostKeysRequest{})
	if err != nil {
		return canonical.Batch{}, nil, fmt.Errorf("list host keys: %w", err)
	}
	pinOf := map[string]*pb.HostKeyPin{}
	for _, p := range pins.GetHosts() {
		pinOf[p.GetHostId()] = p
	}
	batchID, err := newUUID()
	if err != nil {
		return canonical.Batch{}, nil, err
	}
	now := b.now()
	var members []plannedMember
	var stages []canonical.BatchStage
	versions := map[string]uint64{}
	tuples := map[string]int{}
	var planned time.Duration
	for si, st := range req.Stages {
		if len(st.Members) == 0 {
			return canonical.Batch{}, nil, batchInput("stage %d has no members", si+1)
		}
		if st.Gate != canonical.BatchGateManual && st.Gate != canonical.BatchGateAutomatic {
			return canonical.Batch{}, nil, batchInput("stage %d: the gate must be manual or automatic", si+1)
		}
		if st.FailureThreshold < 0 || st.FailureThreshold > len(st.Members) || st.UnreachableThreshold < 0 || st.UnreachableThreshold > len(st.Members) {
			return canonical.Batch{}, nil, batchInput("stage %d: thresholds must be 0 to %d", si+1, len(st.Members))
		}
		stage := canonical.BatchStage{
			StageID: fmt.Sprintf("s%d", si+1), Gate: st.Gate, MemberIDs: []string{},
			FailureThreshold: st.FailureThreshold, UnreachableThreshold: st.UnreachableThreshold, RequiredPostchecks: []string{},
		}
		var longest time.Duration
		for _, spec := range st.Members {
			n := len(members) + 1
			pm, err := b.planMember(ctx, spec, pinOf, versions, si+1, n)
			if err != nil {
				return canonical.Batch{}, nil, err
			}
			tuple := pm.member.Request.ActionID + "/" + spec.HostID + "/" + pm.member.Request.ParametersHash
			if first, dup := tuples[tuple]; dup {
				return canonical.Batch{}, nil, batchInput("member %d repeats member %d (%s on %s with the same parameters)", n, first, spec.ActionID, spec.HostID)
			}
			tuples[tuple] = n
			stage.MemberIDs = append(stage.MemberIDs, pm.member.MemberID)
			members = append(members, pm)
			longest = max(longest, pm.action.Timeout)
		}
		rounds := (len(st.Members) + parallelHosts - 1) / parallelHosts
		planned += time.Duration(rounds)*longest + stageMargin
		stages = append(stages, stage)
	}
	if planned+permitMargin > maxPermitLifetime {
		return canonical.Batch{}, nil, batchInput("the planned rollout takes longer than 24 hours; split the work into separately reviewed batches")
	}
	graph := canonical.BatchStagePlan{Stages: stages, Dependencies: []canonical.BatchDependency{}}
	gh, err := canonical.BatchStagePlanHash(graph)
	if err != nil {
		return canonical.Batch{}, nil, batchInput("invalid stage plan: %v", err)
	}
	expiry := now.Add(planned + permitMargin).Unix()
	doc := canonical.Batch{BatchVersion: canonical.BatchVersion, BatchID: batchID, ExpiryUnix: expiry, StagePlan: graph, StagePlanHash: gh.String()}
	for i := range members {
		members[i].member.Request.ExpiryUnix = expiry
		members[i].member.Request.StagePlanHash = gh.String()
		doc.Members = append(doc.Members, members[i].member)
	}
	if _, _, _, err := canonical.CanonicalizeBatch(doc, now); err != nil {
		return canonical.Batch{}, nil, batchInput("the plan is not a valid batch: %v", err)
	}
	return doc, members, nil
}

// planMember resolves one member against the inventory and the executor's
// pins. n is the member's 1-based plan position.
func (b *Batches) planMember(ctx context.Context, spec BatchMemberSpec, pinOf map[string]*pb.HostKeyPin, versions map[string]uint64, stage, n int) (plannedMember, error) {
	a, err := b.lookupAction(ctx, spec, n)
	if err != nil {
		return plannedMember{}, err
	}
	if why, excluded := batchExcludedActions[a.ID]; excluded {
		return plannedMember{}, batchInput("member %d: %s", n, why)
	}
	if len(a.Secrets) > 0 {
		return plannedMember{}, batchInput("member %d: actions with secrets are not available in a batch", n)
	}
	params := spec.Params
	if params == nil {
		params = map[string]string{}
	}
	if err := a.ValidParams(params); err != nil {
		return plannedMember{}, batchInput("member %d (%s): %v", n, a.ID, err)
	}
	paramsJSON, err := a.ParametersJSON(params, nil)
	if err != nil {
		return plannedMember{}, err
	}
	ph, err := canonical.HashParameters(paramsJSON)
	if err != nil {
		return plannedMember{}, err
	}
	if _, err := b.hosts.Get(ctx, spec.HostID); errors.Is(err, inventory.ErrHostNotFound) {
		return plannedMember{}, &HostError{Host: spec.HostID, Reason: "not in the inventory"}
	} else if err != nil {
		return plannedMember{}, err
	}
	p, ok := pinOf[spec.HostID]
	if !ok {
		return plannedMember{}, &HostError{Host: spec.HostID, Reason: "not enrolled (no pinned host key)"}
	}
	if p.GetBlocked() {
		return plannedMember{}, &HostError{Host: spec.HostID, Reason: "blocked after a host key mismatch"}
	}
	ref := p.GetCredentialRef()
	ver, ok := versions[ref]
	if !ok {
		if b.credVer == nil {
			return plannedMember{}, ErrBatchCredentials
		}
		v, err := b.credVer(ctx, ref)
		if err != nil || v == 0 {
			b.log.Warn("batch credential version", "credential", ref)
			return plannedMember{}, ErrBatchCredentials
		}
		versions[ref], ver = v, v
	}
	execID, err := newUUID()
	if err != nil {
		return plannedMember{}, err
	}
	m := canonical.BatchMember{
		MemberID: fmt.Sprintf("m-%03d", n),
		Request: canonical.Request{
			RequestVersion: canonical.RequestVersion, ExecutionID: execID, ActionID: a.ID, ModuleVersion: a.Version,
			ArtifactSHA256: a.SHA256(), ParametersHash: ph, CredentialRefs: []string{ref},
			RiskClass:       canonical.Risk(riskName(a.Risk)),
			ResolvedTargets: []canonical.Target{{HostID: spec.HostID, HostKeyFingerprint: p.GetFingerprint()}},
		},
		CredentialVersions: []canonical.CredentialVersion{{Reference: ref, Version: ver}},
		PreconditionHashes: []string{},
	}
	if containerActions[a.ID] {
		id := params["container"]
		if !fullContainerIDRe.MatchString(id) {
			return plannedMember{}, batchInput("member %d (%s on %s): name the container by its full 64-character ID", n, a.ID, spec.HostID)
		}
		c, err := b.containers.ContainerBinding(ctx, spec.HostID, id)
		if err != nil {
			return plannedMember{}, fmt.Errorf("member %d (%s on %s): %w", n, a.ID, spec.HostID, err)
		}
		m.Container = &c
	}
	return plannedMember{stage: stage, action: a, params: paramsJSON, member: m, pin: p}, nil
}

// lookupAction resolves a member's action: a built-in without a version,
// or a module or runbook action at exactly spec.Version.
func (b *Batches) lookupAction(ctx context.Context, spec BatchMemberSpec, n int) (actions.Action, error) {
	if a, ok := actions.Lookup(spec.ActionID); ok {
		if spec.Version != "" && spec.Version != a.Version {
			return actions.Action{}, batchInput("member %d: %q is a built-in action; it has no version %q", n, spec.ActionID, spec.Version)
		}
		return a, nil
	}
	if b.actions == nil {
		return actions.Action{}, batchInput("member %d: unknown action %q", n, spec.ActionID)
	}
	if spec.Version == "" {
		return actions.Action{}, batchInput("member %d: name the exact version of %q", n, spec.ActionID)
	}
	a, ok, err := b.actions.Action(ctx, spec.ActionID, spec.Version)
	if err != nil {
		return actions.Action{}, fmt.Errorf("member %d: resolve %s %s: %w", n, spec.ActionID, spec.Version, err)
	}
	if !ok || a.ID != spec.ActionID || a.Version != spec.Version {
		return actions.Action{}, batchInput("member %d: unknown action %q at version %q", n, spec.ActionID, spec.Version)
	}
	return a, nil
}

// BatchCreated is the result of ProposeBatch.
type BatchCreated struct {
	ID          string
	Digest      string
	State       string
	Risk        string
	Requirement string
	// Options is the WebAuthn request options JSON when the browser must
	// approve.
	Options []byte
}

// ProposeBatch plans req, proposes the complete plan to the executor and
// stores it. Every member is checked against the executor's answer; a
// differing answer is refused, never stored.
func (b *Batches) ProposeBatch(ctx context.Context, user string, req BatchRequest) (BatchCreated, error) {
	doc, members, err := b.plan(ctx, req)
	if err != nil {
		return BatchCreated{}, err
	}
	_, canon, _, err := canonical.CanonicalizeBatch(doc, b.now())
	if err != nil {
		return BatchCreated{}, batchInput("the plan is not a valid batch: %v", err)
	}
	in := &pb.ProposeBatchRequest{BatchJson: canon}
	for _, m := range members {
		in.Members = append(in.Members, &pb.BatchMemberInput{MemberId: m.member.MemberID, Artifact: m.action.Script, ParametersJson: m.params})
	}
	cctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	resp, err := b.exec.ProposeBatch(cctx, in)
	if err != nil {
		return BatchCreated{}, b.proposeError(err, members)
	}
	frozen, err := b.checkAnswer(resp, doc)
	if err != nil {
		b.log.Warn("batch answer rejected", "batch", doc.BatchID, "error", err.Error())
		return BatchCreated{}, err
	}
	risk := riskName(resp.GetRisk())
	if risk != "LOW" && risk != "MEDIUM" && risk != "HIGH" {
		return BatchCreated{}, ErrBatchAnswer
	}
	state := "pending"
	switch resp.GetState() {
	case pb.PermitState_PERMIT_STATE_APPROVED:
		state = "approved"
	case pb.PermitState_PERMIT_STATE_PENDING:
	default:
		return BatchCreated{}, ErrBatchAnswer
	}
	c := BatchCreated{ID: doc.BatchID, Digest: resp.GetBatchDigest(), State: state, Risk: risk,
		Requirement: requirementName(resp.GetApprovalRequirement()), Options: resp.GetRequestOptionsJson()}
	if err := b.store(ctx, user, c, resp, frozen, members); err != nil {
		return BatchCreated{}, err
	}
	b.log.Info("audit", "kind", "batch_proposed", "batch", c.ID, "digest", c.Digest, "risk", c.Risk,
		"members", len(members), "stages", len(doc.StagePlan.Stages), "user", user)
	return c, nil
}

// proposeError maps an executor refusal. A CRITICAL refusal names the
// members; only IDs of this plan are taken from the executor's text.
func (b *Batches) proposeError(err error, members []plannedMember) error {
	st, ok := status.FromError(err)
	if ok && st.Code() == codes.InvalidArgument && strings.Contains(st.Message(), ErrBatchCritical.Error()) {
		ce := &BatchCriticalError{}
		msg := st.Message()
		for _, m := range members {
			if regexp.MustCompile(`\b` + regexp.QuoteMeta(m.member.MemberID) + `\b`).MatchString(msg) {
				ce.Members = append(ce.Members, memberViewOf(m))
			}
		}
		return ce
	}
	return fmt.Errorf("propose batch: %w", err)
}

// checkAnswer verifies that the executor froze exactly the proposed plan:
// the digest is the SHA-256 of the canonical bytes, and every member,
// stage and binding equals the proposal except for the executor-derived
// risk, which may only be raised. It returns the frozen plan.
func (b *Batches) checkAnswer(resp *pb.ProposeBatchResponse, doc canonical.Batch) (canonical.Batch, error) {
	sum := sha256.Sum256(resp.GetCanonicalBatch())
	if hex.EncodeToString(sum[:]) != resp.GetBatchDigest() {
		return canonical.Batch{}, ErrBatchAnswer
	}
	frozen, _, _, err := canonical.ParseBatch(resp.GetCanonicalBatch(), b.now())
	if err != nil || frozen.BatchID != doc.BatchID || frozen.ExpiryUnix != doc.ExpiryUnix || frozen.StagePlanHash != doc.StagePlanHash ||
		len(frozen.Members) != len(doc.Members) || len(frozen.StagePlan.Stages) != len(doc.StagePlan.Stages) {
		return canonical.Batch{}, ErrBatchAnswer
	}
	for i, m := range frozen.Members {
		want := doc.Members[i]
		got := m
		if got.Request.RiskClass.Rank() < want.Request.RiskClass.Rank() || got.Request.RiskClass == canonical.RiskCritical {
			return canonical.Batch{}, ErrBatchAnswer
		}
		got.Request.RiskClass = want.Request.RiskClass
		if !sameMember(got, want) {
			return canonical.Batch{}, ErrBatchAnswer
		}
	}
	return frozen, nil
}

// sameMember compares every binding of two canonical members.
func sameMember(a, b canonical.BatchMember) bool {
	ra, rb := a.Request, b.Request
	if a.MemberID != b.MemberID || ra.RequestVersion != rb.RequestVersion || ra.ExecutionID != rb.ExecutionID || ra.ActionID != rb.ActionID ||
		ra.ModuleVersion != rb.ModuleVersion || ra.ArtifactSHA256 != rb.ArtifactSHA256 || ra.ParametersHash != rb.ParametersHash ||
		ra.RiskClass != rb.RiskClass || ra.StagePlanHash != rb.StagePlanHash || ra.ExpiryUnix != rb.ExpiryUnix ||
		strings.Join(ra.CredentialRefs, "\x00") != strings.Join(rb.CredentialRefs, "\x00") ||
		len(ra.ResolvedTargets) != len(rb.ResolvedTargets) || len(a.CredentialVersions) != len(b.CredentialVersions) ||
		strings.Join(a.PreconditionHashes, "\x00") != strings.Join(b.PreconditionHashes, "\x00") ||
		(a.Container == nil) != (b.Container == nil) || a.ProviderTarget != nil || b.ProviderTarget != nil {
		return false
	}
	for i := range ra.ResolvedTargets {
		if ra.ResolvedTargets[i] != rb.ResolvedTargets[i] {
			return false
		}
	}
	for i := range a.CredentialVersions {
		if a.CredentialVersions[i] != b.CredentialVersions[i] {
			return false
		}
	}
	return a.Container == nil || *a.Container == *b.Container
}

// store records the frozen plan in one transaction.
func (b *Batches) store(ctx context.Context, user string, c BatchCreated, resp *pb.ProposeBatchResponse, frozen canonical.Batch, members []plannedMember) error {
	tx, err := b.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	now := b.now().Unix()
	if _, err := tx.ExecContext(ctx, `INSERT INTO batches (id, digest, state, risk, requirement, member_count, stage_count, canonical, options,
			approval_expiry, expiry, approved_by, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		c.ID, c.Digest, c.State, c.Risk, c.Requirement, len(frozen.Members), len(frozen.StagePlan.Stages), resp.GetCanonicalBatch(),
		resp.GetRequestOptionsJson(), resp.GetChallengeExpiryUnix(), frozen.ExpiryUnix, approvedByOf(c.State), user, now); err != nil {
		return fmt.Errorf("store batch: %w", err)
	}
	for i, st := range frozen.StagePlan.Stages {
		if _, err := tx.ExecContext(ctx, `INSERT INTO batch_stages (batch_id, stage, stage_id, gate, failure_threshold, unreachable_threshold)
			VALUES (?, ?, ?, ?, ?, ?)`, c.ID, i+1, st.StageID, st.Gate, st.FailureThreshold, st.UnreachableThreshold); err != nil {
			return fmt.Errorf("store batch stage: %w", err)
		}
	}
	for i, m := range frozen.Members {
		pm := members[i]
		container := ""
		if m.Container != nil {
			container = m.Container.ContainerID
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO batch_members (batch_id, idx, member_id, execution_id, stage, action_id, module_version,
				artifact_sha256, parameters_hash, params, risk, host_id, fingerprint, credential_ref, container_id, updated_at)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			c.ID, i, m.MemberID, m.Request.ExecutionID, pm.stage, m.Request.ActionID, m.Request.ModuleVersion, m.Request.ArtifactSHA256,
			m.Request.ParametersHash, string(pm.params), string(m.Request.RiskClass), m.Request.ResolvedTargets[0].HostID,
			m.Request.ResolvedTargets[0].HostKeyFingerprint, m.Request.CredentialRefs[0], container, now); err != nil {
			return fmt.Errorf("store batch member: %w", err)
		}
	}
	return tx.Commit()
}

func approvedByOf(state string) string {
	if state == "approved" {
		return "privileged-session"
	}
	return ""
}

// ApproveBatch relays the browser's assertion for a pending batch. The
// executor verifies it; the server never approves.
func (b *Batches) ApproveBatch(ctx context.Context, user, id string, assertion []byte) error {
	v, err := b.Batch(ctx, id)
	if err != nil {
		return err
	}
	if v.State != "pending" {
		return ErrBatchNotPending
	}
	cctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	r, err := b.exec.CommitBatch(cctx, &pb.CommitBatchRequest{BatchDigest: v.Digest, AssertionJson: assertion})
	if err != nil {
		return fmt.Errorf("approve batch %s: %w", id, err)
	}
	if r.GetState() != pb.PermitState_PERMIT_STATE_APPROVED {
		return fmt.Errorf("approve batch %s: executor state %s", id, r.GetState())
	}
	if _, err := b.db.ExecContext(ctx, `UPDATE batches SET state = 'approved', approved_by = ?, options = NULL WHERE id = ? AND state = 'pending'`,
		batchTruncate(user, 64), id); err != nil {
		return fmt.Errorf("approve batch %s: %w", id, err)
	}
	b.log.Info("audit", "kind", "batch_approved", "batch", id, "digest", v.Digest, "user", user)
	return nil
}

// RefreshBatch asks the executor whether it still holds the approval
// (lock and restart revoke it). A pending batch the executor approved
// (hardened CLI) becomes approved; an approval the executor no longer
// holds ends the batch: pending becomes expired, and every member that
// was not dispatched becomes not executed. Nothing is redispatched.
func (b *Batches) RefreshBatch(ctx context.Context, id string) error {
	v, err := b.Batch(ctx, id)
	if err != nil {
		return err
	}
	if v.State != "pending" && v.State != "approved" {
		return nil
	}
	cctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	r, err := b.exec.GetBatchStatus(cctx, &pb.GetBatchStatusRequest{BatchDigest: v.Digest})
	switch status.Code(err) {
	case codes.OK:
	case codes.NotFound, codes.FailedPrecondition:
		return b.endBatch(ctx, v, "the executor no longer holds this batch approval (lock, restart, expiry or a changed risk); plan a fresh batch")
	default:
		return fmt.Errorf("batch status %s: %w", id, err)
	}
	if r.GetBatchId() != v.ID || r.GetBatchDigest() != v.Digest || len(r.GetMemberIds()) != len(v.Members) {
		return ErrBatchAnswer
	}
	for i, m := range v.Members {
		if r.GetMemberIds()[i] != m.MemberID || (len(r.GetMemberExecutionIds()) == len(v.Members) && r.GetMemberExecutionIds()[i] != m.ExecutionID) {
			return ErrBatchAnswer
		}
	}
	switch r.GetState() {
	case pb.PermitState_PERMIT_STATE_APPROVED:
		if v.State == "pending" {
			if _, err := b.db.ExecContext(ctx, `UPDATE batches SET state = 'approved', approved_by = ?, options = NULL WHERE id = ? AND state = 'pending'`,
				batchTruncate(r.GetApprovedBy(), 64), id); err != nil {
				return fmt.Errorf("batch status %s: %w", id, err)
			}
		}
	case pb.PermitState_PERMIT_STATE_PENDING:
	default:
		return b.endBatch(ctx, v, "the executor no longer holds this batch approval; plan a fresh batch")
	}
	return nil
}

// endBatch records that the executor's authority is gone.
func (b *Batches) endBatch(ctx context.Context, v BatchView, why string) error {
	tx, err := b.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	state := v.State
	if state == "pending" {
		state = "expired"
	}
	if _, err := tx.ExecContext(ctx, `UPDATE batches SET state = ?, detail = ?, options = NULL WHERE id = ?`, state, batchTruncate(why, maxBatchDetail), v.ID); err != nil {
		return fmt.Errorf("end batch %s: %w", v.ID, err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE batch_members SET outcome = 'not_executed', detail = ?, updated_at = ? WHERE batch_id = ? AND outcome = 'planned'`,
		batchTruncate(why, maxBatchDetail), b.now().Unix(), v.ID); err != nil {
		return fmt.Errorf("end batch %s: %w", v.ID, err)
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	b.log.Info("audit", "kind", "batch_ended", "batch", v.ID, "digest", v.Digest, "reason", why)
	return nil
}

// batchTruncate shortens s to at most n bytes on a UTF-8 boundary.
func batchTruncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

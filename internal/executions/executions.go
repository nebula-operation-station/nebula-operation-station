// SPDX-License-Identifier: AGPL-3.0-or-later

// Package executions plans and follows executions from the server side
// (spec 07): it builds the canonical request from the inventory and the
// executor's pins, proposes it, relays the browser approval, starts the
// host runs once the executor has approved, and keeps the outcomes for the
// UI. The server can only ask; the executor decides, holds the permit and
// talks SSH.
package executions

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/actions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/notify"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// Executor is the part of the executor client the service uses (server
// role).
type Executor interface {
	ListHostKeys(ctx context.Context, in *pb.ListHostKeysRequest, opts ...grpc.CallOption) (*pb.ListHostKeysResponse, error)
	ProposeExecution(ctx context.Context, in *pb.ProposeExecutionRequest, opts ...grpc.CallOption) (*pb.ProposeExecutionResponse, error)
	SubmitAssertion(ctx context.Context, in *pb.SubmitAssertionRequest, opts ...grpc.CallOption) (*pb.SubmitAssertionResponse, error)
	RunAttached(ctx context.Context, in *pb.RunAttachedRequest, opts ...grpc.CallOption) (*pb.RunAttachedResponse, error)
	StartDurable(ctx context.Context, in *pb.StartDurableRequest, opts ...grpc.CallOption) (*pb.StartDurableResponse, error)
	GetRun(ctx context.Context, in *pb.GetRunRequest, opts ...grpc.CallOption) (*pb.GetRunResponse, error)
}

// Hosts gives the inventory hosts (inventory.Store).
type Hosts interface {
	Get(ctx context.Context, id string) (inventory.Host, error)
}

// Errors shown to the user (they describe the request).
var (
	ErrUnknownAction = errors.New("unknown action")
	ErrNoHosts       = errors.New("select at least one host")
	ErrTooManyHosts  = fmt.Errorf("at most %d hosts per execution", MaxHosts)
	ErrNotFound      = errors.New("execution not found")
	ErrNotPending    = errors.New("the execution is not waiting for approval")
)

// HostError explains why a host cannot be part of an execution.
type HostError struct {
	Host   string
	Reason string
}

func (e *HostError) Error() string { return "host " + e.Host + ": " + e.Reason }

// Limits.
const (
	MaxHosts       = 100
	permitLifetime = time.Hour
	pollInterval   = 5 * time.Second
	callTimeout    = 30 * time.Second
	// parallelHosts bounds concurrent host runs of one execution.
	parallelHosts = 4
)

// retryDelays are the waits before retrying a safe action whose run never
// reached the host (spec 07 retry class safe); tests shorten them.
var retryDelays = []time.Duration{20 * time.Second, time.Minute}

// stagePlanHash identifies the only plan there is so far: one stage, all
// hosts (the stage engine is Milestone 6).
var stagePlanHash = func() string {
	s, _ := canonical.HashParameters([]byte(`{"plan":"single-stage-v1"}`))
	return s
}()

// ParamError is an invalid action parameter (it describes the input).
type ParamError struct{ Reason string }

func (e *ParamError) Error() string { return e.Reason }

// Service is safe for concurrent use.
type Service struct {
	exec  Executor
	db    *sql.DB
	hosts Hosts
	log   *slog.Logger
	now   func() time.Time

	notifier *notify.Notifier
	// opsMu serializes Ops State evaluations, so two runs finishing at
	// once on one host cannot both see the old state and notify twice.
	opsMu sync.Mutex

	mu      sync.Mutex
	running map[string]bool // executions with a dispatcher in this process
	wg      sync.WaitGroup
	ctx     context.Context
}

// New returns a service. ctx bounds the background dispatchers.
func New(ctx context.Context, exec Executor, db *sql.DB, hosts Hosts, log *slog.Logger) *Service {
	return &Service{exec: exec, db: db, hosts: hosts, log: log, now: time.Now, running: map[string]bool{}, ctx: ctx}
}

// Wait blocks until the background dispatchers have stopped (tests).
func (s *Service) Wait() { s.wg.Wait() }

func newUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := fmt.Sprintf("%x", b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32], nil
}

// Created is the result of Create.
type Created struct {
	ID          string
	State       string
	Risk        string
	Requirement string
	// Options is the WebAuthn request options JSON when the browser must
	// approve.
	Options []byte
}

type target struct {
	host      string
	fp        string
	cred      string
	endpoints []string
}

// Create plans an execution of a built-in action on hosts and proposes it.
func (s *Service) Create(ctx context.Context, user, actionID string, hostIDs []string, params map[string]string) (Created, error) {
	a, ok := actions.Lookup(actionID)
	if !ok {
		return Created{}, ErrUnknownAction
	}
	if params == nil {
		params = map[string]string{}
	}
	if err := a.ValidParams(params); err != nil {
		return Created{}, &ParamError{Reason: err.Error()}
	}
	paramsJSON, err := json.Marshal(params)
	if err != nil {
		return Created{}, err
	}
	if len(hostIDs) == 0 {
		return Created{}, ErrNoHosts
	}
	if len(hostIDs) > MaxHosts {
		return Created{}, ErrTooManyHosts
	}
	cctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	pins, err := s.exec.ListHostKeys(cctx, &pb.ListHostKeysRequest{})
	if err != nil {
		return Created{}, err
	}
	pinOf := map[string]*pb.HostKeyPin{}
	for _, p := range pins.GetHosts() {
		pinOf[p.GetHostId()] = p
	}
	seen := map[string]bool{}
	var targets []target
	creds := map[string]bool{}
	for _, id := range hostIDs {
		if seen[id] {
			continue
		}
		seen[id] = true
		h, err := s.hosts.Get(cctx, id)
		if errors.Is(err, inventory.ErrHostNotFound) {
			return Created{}, &HostError{Host: id, Reason: "not in the inventory"}
		}
		if err != nil {
			return Created{}, err
		}
		p, ok := pinOf[id]
		if !ok {
			return Created{}, &HostError{Host: id, Reason: "not enrolled (no pinned host key)"}
		}
		if p.GetBlocked() {
			return Created{}, &HostError{Host: id, Reason: "blocked after a host key mismatch"}
		}
		if len(h.Endpoints) == 0 {
			return Created{}, &HostError{Host: id, Reason: "has no endpoints"}
		}
		t := target{host: id, fp: p.GetFingerprint(), cred: p.GetCredentialRef()}
		for _, e := range h.Endpoints {
			port := e.Port
			if port == 0 {
				port = 22
			}
			t.endpoints = append(t.endpoints, net.JoinHostPort(e.Address, strconv.Itoa(port)))
		}
		targets = append(targets, t)
		creds[t.cred] = true
	}
	id, err := newUUID()
	if err != nil {
		return Created{}, err
	}
	ph, err := canonical.HashParameters(paramsJSON)
	if err != nil {
		return Created{}, err
	}
	req := &pb.ExecutionRequest{
		ExecutionId: id, ActionId: a.ID, ModuleVersion: a.Version, ArtifactSha256: a.SHA256(), ParametersHash: ph,
		RiskClass: a.Risk, StagePlanHash: stagePlanHash, ExpiryUnix: s.now().Add(permitLifetime).Unix(),
	}
	for c := range creds {
		req.CredentialRefs = append(req.CredentialRefs, c)
	}
	sort.Strings(req.CredentialRefs)
	for _, t := range targets {
		req.ResolvedTargets = append(req.ResolvedTargets, &pb.Target{HostId: t.host, HostKeyFingerprint: t.fp})
	}
	p, err := s.exec.ProposeExecution(cctx, &pb.ProposeExecutionRequest{Request: req, ParametersJson: paramsJSON, RaiseToMinimum: true})
	if err != nil {
		return Created{}, err
	}
	state := "pending"
	if p.GetState() == pb.PermitState_PERMIT_STATE_APPROVED {
		state = "approved"
	}
	c := Created{ID: id, State: state, Risk: riskName(p.GetRiskClass()), Requirement: requirementName(p.GetApprovalRequirement()), Options: p.GetRequestOptionsJson()}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Created{}, err
	}
	defer tx.Rollback() //nolint:errcheck
	if _, err := tx.ExecContext(ctx, `INSERT INTO executions (id, digest, action_id, module_version, artifact_sha256, risk, requirement, state,
			durable, timeout_s, options, approval_expiry, created_by, created_at, params) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, p.GetExecutionDigest(), a.ID, a.Version, a.SHA256(), c.Risk, c.Requirement, state, boolInt(a.Durable),
		int64(a.Timeout/time.Second), p.GetRequestOptionsJson(), p.GetChallengeExpiryUnix(), user, s.now().Unix(), string(paramsJSON)); err != nil {
		return Created{}, fmt.Errorf("store execution: %w", err)
	}
	for _, t := range targets {
		eps, _ := json.Marshal(t.endpoints)
		if _, err := tx.ExecContext(ctx, `INSERT INTO execution_hosts (execution_id, host_id, fingerprint, credential_ref, endpoints, state)
			VALUES (?, ?, ?, ?, ?, 'waiting')`, id, t.host, t.fp, t.cred, string(eps)); err != nil {
			return Created{}, fmt.Errorf("store execution host: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return Created{}, err
	}
	s.log.Info("audit", "kind", "execution_proposed", "execution", id, "digest", p.GetExecutionDigest(), "action", a.ID,
		"risk", c.Risk, "hosts", len(targets), "user", user)
	if state == "approved" {
		s.start(id)
	}
	return c, nil
}

// Approve relays the browser's assertion to the executor and starts the
// runs once the permit is approved.
func (s *Service) Approve(ctx context.Context, user, id string, assertion []byte, typedTargets uint32) error {
	e, err := s.Get(ctx, id)
	if err != nil {
		return err
	}
	if e.State != "pending" {
		return ErrNotPending
	}
	cctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	r, err := s.exec.SubmitAssertion(cctx, &pb.SubmitAssertionRequest{ExecutionDigest: e.Digest, AssertionJson: assertion, TypedTargetCount: typedTargets})
	if err != nil {
		return err
	}
	if r.GetState() != pb.PermitState_PERMIT_STATE_APPROVED {
		return status.Error(codes.FailedPrecondition, "not approved yet")
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE executions SET state = 'approved', options = NULL WHERE id = ? AND state = 'pending'`, id); err != nil {
		return err
	}
	s.log.Info("audit", "kind", "execution_approved_in_browser", "execution", id, "user", user)
	s.start(id)
	return nil
}

// Resume restarts the dispatchers of executions that were approved or
// running when the server stopped. Attached runs that were in flight have
// an unknown outcome on the server side; the executor never re-runs them.
func (s *Service) Resume(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `UPDATE execution_hosts SET state = 'finished', class = 'unknown',
			detail = 'the server restarted during an attached run; see the executor log', finished_at = ?
		WHERE state = 'running' AND execution_id IN (SELECT id FROM executions WHERE durable = 0)`, s.now().Unix()); err != nil {
		return err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id FROM executions WHERE state IN ('approved', 'running')`)
	if err != nil {
		return err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	rows.Close()
	for _, id := range ids {
		s.start(id)
	}
	return rows.Err()
}

func (s *Service) start(id string) {
	s.mu.Lock()
	if s.running[id] {
		s.mu.Unlock()
		return
	}
	s.running[id] = true
	s.mu.Unlock()
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer func() {
			s.mu.Lock()
			delete(s.running, id)
			s.mu.Unlock()
		}()
		s.dispatch(id)
	}()
}

func (s *Service) dispatch(id string) {
	ctx := s.ctx
	e, err := s.Get(ctx, id)
	if err != nil {
		s.log.Error("execution dispatch", "execution", id, "error", err.Error())
		return
	}
	a, ok := actions.Lookup(e.ActionID)
	if !ok || a.Version != e.ModuleVersion || a.SHA256() != e.ArtifactSHA256 {
		s.fail(id, "the action changed since the proposal; create a new execution")
		return
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE executions SET state = 'running' WHERE id = ? AND state = 'approved'`, id); err != nil {
		s.log.Error("execution dispatch", "execution", id, "error", err.Error())
		return
	}
	sem := make(chan struct{}, parallelHosts)
	var wg sync.WaitGroup
	for _, h := range e.Hosts {
		if h.State == "finished" {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(h Host) {
			defer wg.Done()
			defer func() { <-sem }()
			s.runHost(ctx, e, a, h)
		}(h)
	}
	wg.Wait()
	if ctx.Err() != nil {
		return
	}
	res, err := s.db.ExecContext(ctx, `UPDATE executions SET state = 'finished', finished_at = ? WHERE id = ? AND state != 'finished'
		AND NOT EXISTS (SELECT 1 FROM execution_hosts WHERE execution_id = ? AND state != 'finished')`, s.now().Unix(), id, id)
	if err != nil {
		s.log.Error("execution finish", "execution", id, "error", err.Error())
		return
	}
	s.log.Info("audit", "kind", "execution_finished", "execution", id)
	if n, _ := res.RowsAffected(); n == 1 {
		s.notifyFinished(ctx, id)
	}
}

func (s *Service) fail(id, detail string) {
	res, err := s.db.ExecContext(s.ctx, `UPDATE executions SET state = 'failed', detail = ?, finished_at = ? WHERE id = ? AND state != 'failed'`,
		detail, s.now().Unix(), id)
	if err != nil {
		return
	}
	if n, _ := res.RowsAffected(); n == 1 && s.notifier != nil {
		action := ""
		_ = s.db.QueryRowContext(s.ctx, `SELECT action_id FROM executions WHERE id = ?`, id).Scan(&action)
		s.notifier.Notify(s.ctx, notify.Event{Kind: notify.KindExecution, State: "FAILED", ExecutionID: id,
			Reason: action + ": " + detail, Time: s.now()})
	}
}

// maxNotifiedHosts bounds the host list in an execution notification.
const maxNotifiedHosts = 5

// notifyFinished sends one notification for an execution that finished
// with failed hosts (spec 13): FAILED if no host succeeded, WARNING if
// some did. Successful executions are not notified. The message carries
// hosts and result classes only, never host output.
func (s *Service) notifyFinished(ctx context.Context, id string) {
	if s.notifier == nil {
		return
	}
	e, err := s.Get(ctx, id)
	if err != nil {
		return
	}
	var failed []string
	for _, h := range e.Hosts {
		if h.Class != "success" {
			failed = append(failed, h.HostID+" ("+h.Class+")")
		}
	}
	if len(failed) == 0 {
		return
	}
	state := "WARNING"
	if len(failed) == len(e.Hosts) {
		state = "FAILED"
	}
	list := failed
	if len(list) > maxNotifiedHosts {
		list = append(list[:maxNotifiedHosts:maxNotifiedHosts], fmt.Sprintf("and %d more", len(failed)-maxNotifiedHosts))
	}
	host := ""
	if len(e.Hosts) == 1 {
		host = e.Hosts[0].HostID
	}
	s.notifier.Notify(ctx, notify.Event{Kind: notify.KindExecution, Host: host, State: state, ExecutionID: id, Time: s.now(),
		Reason: fmt.Sprintf("%s: %d of %d hosts failed: %s", e.ActionID, len(failed), len(e.Hosts), strings.Join(list, ", "))})
}

func (s *Service) runHost(ctx context.Context, e Execution, a actions.Action, h Host) {
	run := &pb.AuthorizeRunRequest{ExecutionDigest: e.Digest, HostId: h.HostID, HostKeyFingerprint: h.Fingerprint,
		ActionId: a.ID, ModuleVersion: a.Version, Artifact: a.Script, ParametersJson: []byte(e.Params), CredentialRef: h.CredentialRef}
	if h.State == "waiting" {
		if _, err := s.db.ExecContext(ctx, `UPDATE execution_hosts SET state = 'running', started_at = ? WHERE execution_id = ? AND host_id = ?`,
			s.now().Unix(), e.ID, h.HostID); err != nil {
			return
		}
		if !a.Durable {
			s.runAttached(ctx, e, a, h, run)
			return
		}
		cctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
		r, err := s.exec.StartDurable(cctx, &pb.StartDurableRequest{Run: run, Endpoints: h.Endpoints, TimeoutSeconds: uint32(a.Timeout / time.Second)})
		cancel()
		if err != nil {
			s.finishHost(e.ID, a.ID, h.HostID, "not_executed", refusal(err), -1, nil, nil, false)
			return
		}
		if st := r.GetRun(); st.GetState() == "finished" {
			s.finishHost(e.ID, a.ID, h.HostID, st.GetClass(), st.GetDetail(), int(st.GetExitCode()), st.GetResult(), st.GetLog(), st.GetLogTruncated())
			return
		}
	}
	// A durable run: follow it until the executor reports it finished. The
	// result is fetched without releasing it, stored, and only then released
	// in a second call, so a lost response never loses the result.
	t := time.NewTicker(pollInterval)
	defer t.Stop()
	for {
		cctx, cancel := context.WithTimeout(ctx, callTimeout)
		r, err := s.exec.GetRun(cctx, &pb.GetRunRequest{ExecutionId: e.ID, HostId: h.HostID})
		cancel()
		if err == nil && r.GetRun().GetState() == "finished" {
			st := r.GetRun()
			s.finishHost(e.ID, a.ID, h.HostID, st.GetClass(), st.GetDetail(), int(st.GetExitCode()), st.GetResult(), st.GetLog(), st.GetLogTruncated())
			cctx, cancel := context.WithTimeout(ctx, callTimeout)
			if _, err := s.exec.GetRun(cctx, &pb.GetRunRequest{ExecutionId: e.ID, HostId: h.HostID, Release: true}); err != nil {
				s.log.Warn("release run", "execution", e.ID, "host", h.HostID, "error", err.Error())
			}
			cancel()
			return
		}
		if status.Code(err) == codes.NotFound {
			s.finishHost(e.ID, a.ID, h.HostID, "unknown", "the executor has no record of this run", -1, nil, nil, false)
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// refusal turns an executor refusal into text for the user. The executor
// answers in fixed codes with descriptive messages; gRPC details are
// dropped.
func refusal(err error) string {
	st, ok := status.FromError(err)
	if !ok {
		return "executor unavailable"
	}
	msg := st.Message()
	if len(msg) > 300 {
		msg = msg[:300]
	}
	return "refused by the executor: " + msg
}

func (s *Service) finishHost(id, actionID, host, class, detail string, exit int, result, log []byte, truncated bool) {
	if len(detail) > 1000 {
		detail = detail[:1000]
	}
	if _, err := s.db.ExecContext(s.ctx, `UPDATE execution_hosts SET state = 'finished', class = ?, detail = ?, exit_code = ?, result = ?, log = ?,
			log_truncated = ?, finished_at = ? WHERE execution_id = ? AND host_id = ?`,
		class, detail, exit, result, log, boolInt(truncated), s.now().Unix(), id, host); err != nil {
		s.log.Error("execution host finish", "execution", id, "host", host, "error", err.Error())
		return
	}
	s.log.Info("audit", "kind", "execution_host_finished", "execution", id, "host", host, "class", class, "exit", exit)
	s.observe(id, actionID, host, class, result)
	s.refreshOpsState(s.ctx, host, lastRun{action: actionID, class: class, at: s.now(), ok: true})
}

// runAttached runs an attached action on one host. A safe action whose run
// never reached the host (the executor reports it retryable and has left
// the permit's host unused) is retried after retryDelays.
func (s *Service) runAttached(ctx context.Context, e Execution, a actions.Action, h Host, run *pb.AuthorizeRunRequest) {
	var last *pb.RunAttachedResponse
	for attempt := 0; ; attempt++ {
		cctx, cancel := context.WithTimeout(ctx, a.Timeout+2*time.Minute)
		r, err := s.exec.RunAttached(cctx, &pb.RunAttachedRequest{Run: run, Endpoints: h.Endpoints, TimeoutSeconds: uint32(a.Timeout / time.Second)})
		cancel()
		switch {
		case err != nil && last != nil:
			// The retry was refused (permit expired, executor locked):
			// report what the host did, which is nothing.
			s.finishHost(e.ID, a.ID, h.HostID, last.GetClass(), last.GetDetail()+"; retry refused: "+refusal(err), -1, nil, nil, false)
			return
		case err != nil:
			s.finishHost(e.ID, a.ID, h.HostID, "not_executed", refusal(err), -1, nil, nil, false)
			return
		}
		if !r.GetRetryable() || a.Retry != actions.RetrySafe || attempt >= len(retryDelays) {
			s.finishHost(e.ID, a.ID, h.HostID, r.GetClass(), r.GetDetail(), int(r.GetExitCode()), r.GetResult(), r.GetLog(), r.GetLogTruncated())
			return
		}
		last = r
		wait := retryDelays[attempt]
		note := fmt.Sprintf("%s; retry %d of %d in %s", r.GetClass(), attempt+1, len(retryDelays), wait)
		_, _ = s.db.ExecContext(ctx, `UPDATE execution_hosts SET detail = ? WHERE execution_id = ? AND host_id = ?`, note, e.ID, h.HostID)
		s.log.Info("audit", "kind", "execution_host_retry", "execution", e.ID, "host", h.HostID, "attempt", attempt+1)
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func riskName(r pb.RiskClass) string {
	return strings.TrimPrefix(r.String(), "RISK_CLASS_")
}

func requirementName(r pb.ApprovalRequirement) string {
	return strings.ToLower(strings.TrimPrefix(r.String(), "APPROVAL_REQUIREMENT_"))
}

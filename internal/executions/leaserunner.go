// SPDX-License-Identifier: AGPL-3.0-or-later

package executions

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/actions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/schedgrant"
)

// Scheduled runs of ordinary read leases (ADR 0007, "One standing
// read-grant mechanism"). The scheduler asks the executor, through
// RunReadGrant with the scheduled trigger, to run every action of every
// approved ordinary-profile lease on every frozen target once per
// min_interval_s, within the lease's per-target rolling-hour run budget.
// The selection here only picks work: the executor re-checks expiry,
// revocation, lock/pause, scope, credential version and its durable budget
// on every run, and its refusal always wins. Telemetry and provider
// profiles are run by their collectors; legacy read-schedule-v1 grants by
// RunDueSchedules. Results are stored like legacy scheduled runs:
// executions created by "schedule", with schedule_id set to the lease ID.

// leaseRunRequirement is the requirement recorded on a lease run.
const leaseRunRequirement = "read lease"

// leaseBudgetWindow is the rolling window of a lease's run budget.
const leaseBudgetWindow = time.Hour

// readGrantRunner is the executor API the lease runner needs. Like
// readGrantExecutor it is asserted, not part of Executor: an executor
// without it runs legacy schedules only.
type readGrantRunner interface {
	ListReadGrants(ctx context.Context, in *pb.ListReadGrantsRequest, opts ...grpc.CallOption) (*pb.ListReadGrantsResponse, error)
	RunReadGrant(ctx context.Context, in *pb.RunReadGrantRequest, opts ...grpc.CallOption) (*pb.RunReadGrantResponse, error)
}

// ordinaryLease is one approved ordinary lease selected for scheduled runs.
type ordinaryLease struct {
	id       string
	interval time.Duration
	budget   int
	actions  []leaseAction // docker.inspect before image.packages
	targets  []canonical.Target
	// credRef maps a frozen target to its approved credential reference.
	credRef map[string]string
}

// leaseAction is one action of an ordinary lease with the parameters it runs
// with: canonical JSON, "{}" for an action without parameters.
type leaseAction struct {
	action actions.Action
	params []byte
}

// boundParams is one stored parameter row of a read grant (read_grant_params):
// the action it belongs to and its parameters as stored.
type boundParams struct {
	action string
	params string
}

// maxBoundRowsPerGrant bounds the parameter rows read for one grant: one per
// image lease action.
const maxBoundRowsPerGrant = 2

// ordinaryLeases selects the executor's active, unexpired read-grant-v2
// leases with the ordinary profile and a scheduled trigger. Each document is
// re-verified against its registry entry (id and digest); an action is kept
// only when it is the local built-in at exactly the approved version and
// artifact, and either has no parameters (the server could not send any
// else) or is an image lease action whose stored parameters hash to the
// document's ParametersHash and pass the action's validation (see
// leaseActionParams). Every other grant is skipped.
func ordinaryLeases(grants []*pb.ReadGrant, now time.Time, stored map[string][]boundParams) []ordinaryLease {
	empty, err := canonical.HashParameters([]byte(`{}`))
	if err != nil {
		return nil
	}
	var out []ordinaryLease
	seen := map[string]bool{}
	for _, g := range grants {
		if g == nil || g.GetRevokedUnix() != 0 || !now.Before(time.Unix(g.GetExpiryUnix(), 0)) || seen[g.GetGrantId()] {
			continue
		}
		doc, _, digest, err := permit.ParseReadGrant(g.GetCanonicalGrant(), now)
		if err != nil || doc.ID != g.GetGrantId() || digest != g.GetGrantDigest() || doc.ExpiryUnix != g.GetExpiryUnix() ||
			doc.Grant != permit.ReadGrantFormat || doc.RateProfile != schedgrant.OrdinaryReadProfile ||
			(doc.Trigger != permit.TriggerScheduled && doc.Trigger != permit.TriggerBoth) {
			continue
		}
		l := ordinaryLease{id: doc.ID, interval: time.Duration(doc.MinIntervalS) * time.Second,
			budget: int(doc.RunBudget), targets: doc.Targets, credRef: map[string]string{}}
		if l.interval < schedgrant.MinInterval || l.budget < 1 || l.budget > permit.MaxRunBudget {
			continue // ParseReadGrant guarantees this; never run below the floor
		}
		for _, da := range doc.Actions {
			a, ok := actions.Lookup(da.ActionID)
			if !ok || a.Version != da.ModuleVersion || a.SHA256() != da.ArtifactSHA256 || !a.ReadOnly || a.Durable {
				continue
			}
			params, ok := leaseActionParams(a, da, empty, stored[l.id])
			if !ok || (da.ParametersHash != empty && slices.ContainsFunc(l.actions, func(x leaseAction) bool { return x.action.ID == a.ID })) {
				continue
			}
			l.actions = append(l.actions, leaseAction{action: a, params: params})
		}
		// The document may list the actions in any order; docker.inspect must
		// run before image.packages, so that the latter can wait for it.
		slices.SortStableFunc(l.actions, func(x, y leaseAction) int {
			return cmp.Compare(leaseActionRank(x.action.ID), leaseActionRank(y.action.ID))
		})
		for _, c := range doc.Credentials {
			l.credRef[c.HostID] = c.CredentialRef
		}
		if len(l.actions) == 0 {
			continue
		}
		seen[l.id] = true
		out = append(out, l)
	}
	return out
}

// leaseActionParams returns the canonical parameters an action of an ordinary
// lease runs with, and false when the action must be skipped. An action
// without a parameters hash runs with "{}" and must have no parameters. An
// image lease action runs with a stored row of its own action that hashes to
// the document's ParametersHash and passes the action's validation; without
// such a row, or with any other value, the action is skipped. No other action
// ever runs with parameters.
func leaseActionParams(a actions.Action, da permit.ReadGrantAction, empty string, stored []boundParams) ([]byte, bool) {
	if da.ParametersHash == empty {
		return []byte(`{}`), len(a.Params) == 0
	}
	if a.ID != imageLeaseInspectAction && a.ID != imageLeaseImageAction {
		return nil, false
	}
	for _, p := range stored {
		if p.action != a.ID {
			continue
		}
		canon, h, err := canonical.CanonicalParameters([]byte(p.params))
		if err != nil || h != da.ParametersHash {
			continue
		}
		var values map[string]string
		if json.Unmarshal(canon, &values) != nil || a.ValidParams(values) != nil {
			continue
		}
		return canon, true
	}
	return nil, false
}

// leaseActionRank orders the actions of one lease: docker.inspect first.
func leaseActionRank(id string) int {
	if id == imageLeaseInspectAction {
		return 0
	}
	return 1
}

// storedLeaseParams returns the stored parameter rows of each grant, at most
// maxBoundRowsPerGrant per grant. A grant whose rows cannot be read gets none:
// its parameterised actions are skipped, its other actions still run.
func (s *Service) storedLeaseParams(ctx context.Context, grants []*pb.ReadGrant) map[string][]boundParams {
	out := map[string][]boundParams{}
	if s.db == nil {
		return out
	}
	for _, g := range grants {
		id := g.GetGrantId()
		if _, done := out[id]; done {
			continue
		}
		params, err := s.grantParams(ctx, id)
		if err != nil {
			s.log.Error("read lease parameters", "grant", id, "error", err.Error())
		}
		out[id] = params
	}
	return out
}

// grantParams reads the stored parameter rows of one grant.
func (s *Service) grantParams(ctx context.Context, grant string) ([]boundParams, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT action_id, params FROM read_grant_params WHERE grant_id = ? LIMIT ?`,
		grant, maxBoundRowsPerGrant)
	if err != nil {
		return nil, fmt.Errorf("list lease parameters %s: %w", grant, err)
	}
	defer rows.Close()
	var out []boundParams
	for rows.Next() {
		var p boundParams
		if err := rows.Scan(&p.action, &p.params); err != nil {
			return nil, fmt.Errorf("list lease parameters %s: %w", grant, err)
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list lease parameters %s: %w", grant, err)
	}
	return out, nil
}

// errStopLeases ends a tick's lease runs: the executor cannot run any read
// now (locked, unavailable), so asking for the remaining ones only adds load.
var errStopLeases = errors.New("lease runs stopped for this tick")

// errStopLease ends one lease's runs for this tick (revoked, expired or
// paused on the executor).
var errStopLease = errors.New("lease stopped for this tick")

// executorLockedCode prefixes the executor's FailedPrecondition refusal
// when its vault is locked (internal/executor prepareRun). It is the only
// FailedPrecondition that stops every lease; the others name one host or
// credential.
const executorLockedCode = "vault_locked"

// leaseRefusalIsLock reports whether err is the executor's lock refusal.
func leaseRefusalIsLock(err error) bool {
	st := status.Convert(err)
	return st.Code() == codes.FailedPrecondition && strings.HasPrefix(st.Message(), executorLockedCode+":")
}

// errSkipTarget ends one target's runs of a lease for this tick (its budget
// is spent on the executor, the host is gone, not pinned or blocked, or its
// credential is unavailable).
var errSkipTarget = errors.New("target skipped for this tick")

// errSkipRun skips one refused run (not covered, artifact or risk changed);
// the executor claimed no budget for it.
var errSkipRun = errors.New("run skipped")

// RunDueReadGrants runs, one at a time, every due action of every approved
// ordinary read lease on every frozen target whose rolling-hour budget is not
// spent. It does nothing when the executor lacks the read-grant API.
func (s *Service) RunDueReadGrants(ctx context.Context) {
	exec, ok := s.exec.(readGrantRunner)
	if !ok {
		return
	}
	cctx, cancel := context.WithTimeout(ctx, callTimeout)
	r, err := exec.ListReadGrants(cctx, &pb.ListReadGrantsRequest{})
	cancel()
	if err != nil {
		s.log.Warn("read leases", "error", refusal(err))
		return
	}
	leases := ordinaryLeases(r.GetGrants(), s.now(), s.storedLeaseParams(ctx, r.GetGrants()))
	if len(leases) == 0 {
		return
	}
	cctx, cancel = context.WithTimeout(ctx, callTimeout)
	pins, err := s.exec.ListHostKeys(cctx, &pb.ListHostKeysRequest{})
	cancel()
	if err != nil {
		return
	}
	pinOf := map[string]*pb.HostKeyPin{}
	for _, p := range pins.GetHosts() {
		pinOf[p.GetHostId()] = p
	}
	for _, l := range leases {
		if err := s.runLease(ctx, exec, l, pinOf); errors.Is(err, errStopLeases) {
			return
		}
	}
}

// runLease runs the due actions of one lease.
func (s *Service) runLease(ctx context.Context, exec readGrantRunner, l ordinaryLease, pinOf map[string]*pb.HostKeyPin) error {
	last, used, err := s.leaseRuns(ctx, l.id)
	if err != nil {
		s.log.Error("read lease runs", "grant", l.id, "error", err.Error())
		return nil
	}
	for _, t := range l.targets {
		pin, ok := pinOf[t.HostID]
		ref := l.credRef[t.HostID]
		if !ok || pin.GetBlocked() || pin.GetFingerprint() != t.HostKeyFingerprint || ref == "" {
			continue // re-pinned, removed or blocked: needs a new lease
		}
		// inspected is set when this tick's docker.inspect of the target ended
		// with class success; image.packages runs only after it.
		inspected := false
		for _, la := range l.actions {
			a := la.action
			if ctx.Err() != nil {
				return errStopLeases
			}
			if used[t.HostID] >= l.budget {
				break
			}
			if a.ID == imageLeaseImageAction && !inspected {
				continue
			}
			// The action's own floor (ADR 0011 D3) can exceed the lease's
			// interval; asking sooner only gets a refusal that stops the
			// host's other actions for this tick.
			due := max(l.interval, permit.ReadActionMinInterval(a.ID))
			if at, ok := last[a.ID+"\x00"+t.HostID]; ok && s.now().Before(at.Add(due)) {
				continue
			}
			ok, err := s.runLeaseAction(ctx, exec, l, la, t, ref)
			if a.ID == imageLeaseInspectAction {
				inspected = ok
			}
			if errors.Is(err, errSkipTarget) {
				break
			}
			if errors.Is(err, errSkipRun) {
				continue
			}
			if err != nil {
				return err
			}
			used[t.HostID]++
		}
	}
	return nil
}

// leaseRuns returns, for one lease, the newest stored run per action and
// host and the number of runs per host in the current budget window.
func (s *Service) leaseRuns(ctx context.Context, id string) (map[string]time.Time, map[string]int, error) {
	last := map[string]time.Time{}
	used := map[string]int{}
	rows, err := s.db.QueryContext(ctx, `SELECT e.action_id, h.host_id, max(e.created_at),
			sum(CASE WHEN e.created_at > ? THEN 1 ELSE 0 END)
		FROM executions e JOIN execution_hosts h ON h.execution_id = e.id
		WHERE e.schedule_id = ? GROUP BY e.action_id, h.host_id`, s.now().Add(-leaseBudgetWindow).Unix(), id)
	if err != nil {
		return nil, nil, fmt.Errorf("list lease runs %s: %w", id, err)
	}
	defer rows.Close()
	for rows.Next() {
		var action, host string
		var at int64
		var n int
		if err := rows.Scan(&action, &host, &at, &n); err != nil {
			return nil, nil, fmt.Errorf("list lease runs %s: %w", id, err)
		}
		last[action+"\x00"+host] = time.Unix(at, 0)
		used[host] += n
	}
	return last, used, rows.Err()
}

// runLeaseAction asks the executor for one scheduled lease run and stores
// its result. ok reports that the run finished with class success. The error
// says how far the executor's refusal reaches. Logs name the grant, the
// action and the host, never the parameters.
func (s *Service) runLeaseAction(ctx context.Context, exec readGrantRunner, l ordinaryLease, la leaseAction, t canonical.Target, ref string) (ok bool, err error) {
	a := la.action
	h, err := s.hosts.Get(ctx, t.HostID)
	if err != nil {
		if !errors.Is(err, inventory.ErrHostNotFound) {
			s.log.Error("read lease run", "grant", l.id, "host", t.HostID, "error", err.Error())
		}
		return false, errSkipTarget
	}
	var eps []string
	for _, e := range h.Endpoints {
		port := e.Port
		if port == 0 {
			port = 22
		}
		eps = append(eps, net.JoinHostPort(e.Address, strconv.Itoa(port)))
	}
	run := &pb.AuthorizeRunRequest{HostId: t.HostID, HostKeyFingerprint: t.HostKeyFingerprint, ActionId: a.ID, ModuleVersion: a.Version,
		Artifact: a.Script, ParametersJson: la.params, CredentialRef: ref}
	rctx, cancel := context.WithTimeout(ctx, a.Timeout+2*time.Minute)
	r, err := exec.RunReadGrant(rctx, &pb.RunReadGrantRequest{GrantId: l.id, Trigger: pb.ReadGrantTrigger_READ_GRANT_TRIGGER_SCHEDULED,
		Run: run, Endpoints: eps, TimeoutSeconds: uint32(a.Timeout / time.Second)})
	cancel()
	code := status.Code(err)
	switch {
	case code == codes.OK:
		s.storeLeaseRun(ctx, l.id, a, t, ref, la.params, r.GetExecutionId(), r.GetResult())
		return r.GetResult().GetClass() == "success", nil
	case code == codes.ResourceExhausted:
		return false, errSkipTarget // the executor's interval or budget has not passed
	case code == codes.NotFound,
		code == codes.PermissionDenied && strings.HasPrefix(status.Convert(err).Message(), string(permit.CodeLeaseInactive)):
		s.log.Info("read lease inactive", "grant", l.id, "error", refusal(err))
		return false, errStopLease
	case leaseRefusalIsLock(err), code == codes.Unavailable, code == codes.Unimplemented,
		code == codes.DeadlineExceeded, code == codes.Canceled:
		s.log.Warn("read lease runs paused", "grant", l.id, "error", refusal(err))
		return false, errStopLeases
	case code == codes.FailedPrecondition:
		// Host not pinned or blocked, or its credential unavailable: only
		// this target is refused; other targets and leases go on.
		s.log.Warn("read lease target refused", "grant", l.id, "host", t.HostID, "error", refusal(err))
		return false, errSkipTarget
	default:
		s.log.Warn("read lease run refused", "grant", l.id, "action", a.ID, "host", t.HostID, "error", refusal(err))
		return false, errSkipRun
	}
}

// storeLeaseRun records a lease run like storeScheduled records a legacy one.
// params are the canonical parameters the run was sent with.
func (s *Service) storeLeaseRun(ctx context.Context, grantID string, a actions.Action, t canonical.Target, ref string, params []byte, id string, res *pb.RunAttachedResponse) {
	if _, err := s.db.ExecContext(ctx, `INSERT INTO executions (id, digest, action_id, module_version, artifact_sha256, risk, requirement, state,
			durable, timeout_s, created_by, created_at, finished_at, params, schedule_id) VALUES (?, '', ?, ?, ?, 'LOW', ?, 'finished', 0, ?, ?, ?, ?, ?, ?)`,
		id, a.ID, a.Version, a.SHA256(), leaseRunRequirement, int64(a.Timeout/time.Second), "schedule", s.now().Unix(), s.now().Unix(), string(params), grantID); err != nil {
		s.log.Error("store read lease run", "grant", grantID, "error", err.Error())
		return
	}
	if _, err := s.db.ExecContext(ctx, `INSERT INTO execution_hosts (execution_id, host_id, fingerprint, credential_ref, endpoints, state, started_at)
		VALUES (?, ?, ?, ?, '[]', 'running', ?)`, id, t.HostID, t.HostKeyFingerprint, ref, s.now().Unix()); err != nil {
		s.log.Error("store read lease run", "grant", grantID, "error", err.Error())
		return
	}
	s.finishHost(id, a.ID, t.HostID, res.GetClass(), res.GetDetail(), int(res.GetExitCode()), res.GetResult(), res.GetLog(), res.GetLogTruncated())
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package executions

import (
	"context"
	"errors"
	"fmt"
	"net"
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
	actions  []actions.Action
	targets  []canonical.Target
	// credRef maps a frozen target to its approved credential reference.
	credRef map[string]string
}

// ordinaryLeases selects the executor's active, unexpired read-grant-v2
// leases with the ordinary profile and a scheduled trigger. Each document is
// re-verified against its registry entry (id and digest); an action is kept
// only when it is the local built-in at exactly the approved version,
// artifact and empty parameters, since the server could not send anything
// else. Every other grant is skipped.
func ordinaryLeases(grants []*pb.ReadGrant, now time.Time) []ordinaryLease {
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
			if !ok || a.Version != da.ModuleVersion || a.SHA256() != da.ArtifactSHA256 || da.ParametersHash != empty ||
				!a.ReadOnly || a.Durable || len(a.Params) > 0 {
				continue
			}
			l.actions = append(l.actions, a)
		}
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
	leases := ordinaryLeases(r.GetGrants(), s.now())
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
		for _, a := range l.actions {
			if ctx.Err() != nil {
				return errStopLeases
			}
			if used[t.HostID] >= l.budget {
				break
			}
			if at, ok := last[a.ID+"\x00"+t.HostID]; ok && s.now().Before(at.Add(l.interval)) {
				continue
			}
			err := s.runLeaseAction(ctx, exec, l, a, t, ref)
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
// its result. The error says how far the executor's refusal reaches.
func (s *Service) runLeaseAction(ctx context.Context, exec readGrantRunner, l ordinaryLease, a actions.Action, t canonical.Target, ref string) error {
	h, err := s.hosts.Get(ctx, t.HostID)
	if err != nil {
		if !errors.Is(err, inventory.ErrHostNotFound) {
			s.log.Error("read lease run", "grant", l.id, "host", t.HostID, "error", err.Error())
		}
		return errSkipTarget
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
		Artifact: a.Script, ParametersJson: []byte(`{}`), CredentialRef: ref}
	rctx, cancel := context.WithTimeout(ctx, a.Timeout+2*time.Minute)
	r, err := exec.RunReadGrant(rctx, &pb.RunReadGrantRequest{GrantId: l.id, Trigger: pb.ReadGrantTrigger_READ_GRANT_TRIGGER_SCHEDULED,
		Run: run, Endpoints: eps, TimeoutSeconds: uint32(a.Timeout / time.Second)})
	cancel()
	code := status.Code(err)
	switch {
	case code == codes.OK:
		s.storeLeaseRun(ctx, l.id, a, t, ref, r.GetExecutionId(), r.GetResult())
		return nil
	case code == codes.ResourceExhausted:
		return errSkipTarget // the executor's interval or budget has not passed
	case code == codes.NotFound,
		code == codes.PermissionDenied && strings.HasPrefix(status.Convert(err).Message(), string(permit.CodeLeaseInactive)):
		s.log.Info("read lease inactive", "grant", l.id, "error", refusal(err))
		return errStopLease
	case leaseRefusalIsLock(err), code == codes.Unavailable, code == codes.Unimplemented,
		code == codes.DeadlineExceeded, code == codes.Canceled:
		s.log.Warn("read lease runs paused", "grant", l.id, "error", refusal(err))
		return errStopLeases
	case code == codes.FailedPrecondition:
		// Host not pinned or blocked, or its credential unavailable: only
		// this target is refused; other targets and leases go on.
		s.log.Warn("read lease target refused", "grant", l.id, "host", t.HostID, "error", refusal(err))
		return errSkipTarget
	default:
		s.log.Warn("read lease run refused", "grant", l.id, "action", a.ID, "host", t.HostID, "error", refusal(err))
		return errSkipRun
	}
}

// storeLeaseRun records a lease run like storeScheduled records a legacy one.
func (s *Service) storeLeaseRun(ctx context.Context, grantID string, a actions.Action, t canonical.Target, ref, id string, res *pb.RunAttachedResponse) {
	if _, err := s.db.ExecContext(ctx, `INSERT INTO executions (id, digest, action_id, module_version, artifact_sha256, risk, requirement, state,
			durable, timeout_s, created_by, created_at, finished_at, params, schedule_id) VALUES (?, '', ?, ?, ?, 'LOW', ?, 'finished', 0, ?, ?, ?, ?, '{}', ?)`,
		id, a.ID, a.Version, a.SHA256(), leaseRunRequirement, int64(a.Timeout/time.Second), "schedule", s.now().Unix(), s.now().Unix(), grantID); err != nil {
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

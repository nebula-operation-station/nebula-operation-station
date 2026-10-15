// SPDX-License-Identifier: AGPL-3.0-or-later

package executions

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/actions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/schedgrant"
)

// Scheduled read-only checks (docs/implementation/schedule-grants.md). The
// server proposes a schedule grant for read-only built-in actions on
// enrolled hosts; the executor checks that it rates each action LOW on
// each host, and the admin approves the grant with the security key. The
// scheduler then asks the executor to run each action on each host once
// per interval; the executor enforces the grant on every run. Runs are
// stored as executions created by "schedule".

// Schedule limits the server applies before the executor's own.
const (
	scheduleTick        = time.Minute
	DefaultScheduleDays = 30
	MaxScheduleDays     = 90
)

// Schedule is the server's record of a schedule grant.
type Schedule struct {
	ID, Digest, State string
	Actions           []string
	Hosts             []string
	Interval          time.Duration
	ExpiresAt         time.Time
	Options           []byte
	CreatedBy         string
	CreatedAt         time.Time
}

// Errors of schedules.
var (
	ErrScheduleNotFound = errors.New("schedule not found")
	ErrScheduleState    = errors.New("the schedule is not in a state that allows this")
)

// ScheduleError is an unusable schedule request (it describes the input).
type ScheduleError struct{ Reason string }

func (e *ScheduleError) Error() string { return e.Reason }

// ScheduleCreated is the result of CreateSchedule.
type ScheduleCreated struct {
	ID string
	// Options are the WebAuthn request options for the approval; empty if
	// the executor wants the CLI (hardened mode).
	Options []byte
	CLI     bool
	Digest  string
}

// CreateSchedule proposes a schedule grant: actionIDs (read-only built-ins
// without parameters) on hostIDs every interval, for days.
func (s *Service) CreateSchedule(ctx context.Context, user string, actionIDs, hostIDs []string, interval time.Duration, days int) (ScheduleCreated, error) {
	if days == 0 {
		days = DefaultScheduleDays
	}
	if days < 1 || days > MaxScheduleDays {
		return ScheduleCreated{}, &ScheduleError{fmt.Sprintf("a schedule lasts 1 to %d days", MaxScheduleDays)}
	}
	if interval < schedgrant.MinInterval || interval > schedgrant.MaxInterval {
		return ScheduleCreated{}, &ScheduleError{"the interval must be 15 minutes to 7 days"}
	}
	if len(actionIDs) == 0 || len(actionIDs) > schedgrant.MaxActions {
		return ScheduleCreated{}, &ScheduleError{fmt.Sprintf("choose 1 to %d actions", schedgrant.MaxActions)}
	}
	if len(hostIDs) == 0 || len(hostIDs) > schedgrant.MaxTargets {
		return ScheduleCreated{}, &ScheduleError{fmt.Sprintf("choose 1 to %d hosts", schedgrant.MaxTargets)}
	}
	empty, err := canonical.HashParameters([]byte(`{}`))
	if err != nil {
		return ScheduleCreated{}, err
	}
	id, err := newUUID()
	if err != nil {
		return ScheduleCreated{}, err
	}
	doc := schedgrant.Doc{Grant: schedgrant.Format, ID: id, MinIntervalS: int64(interval / time.Second),
		ExpiryUnix: s.now().Add(time.Duration(days) * 24 * time.Hour).Unix()}
	seen := map[string]bool{}
	for _, aid := range actionIDs {
		a, ok := actions.Lookup(aid)
		if !ok || seen[aid] {
			return ScheduleCreated{}, ErrUnknownAction
		}
		seen[aid] = true
		if !a.ReadOnly || a.Durable || len(a.Params) > 0 {
			return ScheduleCreated{}, &ScheduleError{a.ID + " cannot be scheduled: only read-only actions without parameters"}
		}
		doc.Actions = append(doc.Actions, schedgrant.Action{ActionID: a.ID, ModuleVersion: a.Version, ArtifactSHA256: a.SHA256(), ParametersHash: empty})
	}
	cctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	pins, err := s.exec.ListHostKeys(cctx, &pb.ListHostKeysRequest{})
	if err != nil {
		return ScheduleCreated{}, err
	}
	pinOf := map[string]*pb.HostKeyPin{}
	for _, p := range pins.GetHosts() {
		pinOf[p.GetHostId()] = p
	}
	for _, h := range hostIDs {
		if seen["h:"+h] {
			continue
		}
		seen["h:"+h] = true
		p, ok := pinOf[h]
		if !ok || p.GetBlocked() {
			return ScheduleCreated{}, &HostError{Host: h, Reason: "not enrolled, or blocked after a host key mismatch"}
		}
		doc.Targets = append(doc.Targets, canonical.Target{HostID: h, HostKeyFingerprint: p.GetFingerprint()})
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		return ScheduleCreated{}, err
	}
	p, err := s.exec.ProposeScheduleGrant(cctx, &pb.ProposeScheduleGrantRequest{GrantJson: raw})
	if err != nil {
		return ScheduleCreated{}, err
	}
	acts, _ := json.Marshal(actionIDs)
	hosts := make([]string, 0, len(doc.Targets))
	for _, t := range doc.Targets {
		hosts = append(hosts, t.HostID)
	}
	hj, _ := json.Marshal(hosts)
	if _, err := s.db.ExecContext(ctx, `INSERT INTO schedules (id, digest, state, actions, hosts, interval_s, expires_at, options, created_by, created_at)
		VALUES (?, ?, 'pending', ?, ?, ?, ?, ?, ?, ?)`, id, p.GetGrantDigest(), string(acts), string(hj), doc.MinIntervalS, doc.ExpiryUnix,
		p.GetRequestOptionsJson(), user, s.now().Unix()); err != nil {
		return ScheduleCreated{}, fmt.Errorf("store schedule: %w", err)
	}
	s.log.Info("audit", "kind", "schedule_proposed", "schedule", id, "digest", p.GetGrantDigest(), "user", user)
	return ScheduleCreated{ID: id, Options: p.GetRequestOptionsJson(), Digest: p.GetGrantDigest(),
		CLI: p.GetApprovalRequirement() == pb.ApprovalRequirement_APPROVAL_REQUIREMENT_CLI_ONLY}, nil
}

func scanSchedule(row interface{ Scan(...any) error }) (Schedule, error) {
	var x Schedule
	var acts, hosts string
	var interval, expires, created int64
	if err := row.Scan(&x.ID, &x.Digest, &x.State, &acts, &hosts, &interval, &expires, &x.Options, &x.CreatedBy, &created); err != nil {
		return Schedule{}, err
	}
	if json.Unmarshal([]byte(acts), &x.Actions) != nil || json.Unmarshal([]byte(hosts), &x.Hosts) != nil {
		return Schedule{}, errors.New("schedule: stored lists are corrupt")
	}
	x.Interval, x.ExpiresAt, x.CreatedAt = time.Duration(interval)*time.Second, time.Unix(expires, 0), time.Unix(created, 0)
	return x, nil
}

const scheduleColumns = `id, digest, state, actions, hosts, interval_s, expires_at, options, created_by, created_at`

// GetSchedule returns one schedule.
func (s *Service) GetSchedule(ctx context.Context, id string) (Schedule, error) {
	x, err := scanSchedule(s.db.QueryRowContext(ctx, `SELECT `+scheduleColumns+` FROM schedules WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Schedule{}, ErrScheduleNotFound
	}
	return x, err
}

// Schedules returns all schedules, newest first.
func (s *Service) Schedules(ctx context.Context) ([]Schedule, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+scheduleColumns+` FROM schedules ORDER BY created_at DESC, id`)
	if err != nil {
		return nil, fmt.Errorf("list schedules: %w", err)
	}
	defer rows.Close()
	var out []Schedule
	for rows.Next() {
		x, err := scanSchedule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, rows.Err()
}

// ApproveSchedule relays the browser's assertion for a pending schedule.
func (s *Service) ApproveSchedule(ctx context.Context, user, id string, assertion []byte) error {
	x, err := s.GetSchedule(ctx, id)
	if err != nil {
		return err
	}
	if x.State != "pending" {
		return ErrScheduleState
	}
	cctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	if _, err := s.exec.CommitScheduleGrant(cctx, &pb.CommitScheduleGrantRequest{GrantDigest: x.Digest, AssertionJson: assertion}); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE schedules SET state = 'active', options = NULL, approved_at = ? WHERE id = ? AND state = 'pending'`,
		s.now().Unix(), id); err != nil {
		return err
	}
	s.log.Info("audit", "kind", "schedule_approved", "schedule", id, "user", user)
	return nil
}

// RevokeSchedule revokes a schedule's grant on the executor.
func (s *Service) RevokeSchedule(ctx context.Context, user, id string) error {
	x, err := s.GetSchedule(ctx, id)
	if err != nil {
		return err
	}
	if x.State == "revoked" {
		return ErrScheduleState
	}
	if x.State == "active" {
		cctx, cancel := context.WithTimeout(ctx, callTimeout)
		defer cancel()
		if _, err := s.exec.RevokeScheduleGrant(cctx, &pb.RevokeScheduleGrantRequest{GrantId: id}); err != nil && status.Code(err) != codes.NotFound {
			return err
		}
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE schedules SET state = 'revoked', options = NULL WHERE id = ?`, id); err != nil {
		return err
	}
	s.log.Info("audit", "kind", "schedule_revoked", "schedule", id, "user", user)
	return nil
}

// RunSchedules runs due scheduled checks until ctx ends.
func (s *Service) RunSchedules(ctx context.Context) {
	t := time.NewTicker(scheduleTick)
	defer t.Stop()
	for {
		s.RunDueSchedules(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// RunDueSchedules runs every action of every active schedule on every host
// whose last scheduled run is at least the interval ago, one at a time.
func (s *Service) RunDueSchedules(ctx context.Context) {
	all, err := s.Schedules(ctx)
	if err != nil {
		s.log.Error("schedules", "error", err.Error())
		return
	}
	for _, x := range all {
		if x.State != "active" || !s.now().Before(x.ExpiresAt) {
			continue
		}
		for _, aid := range x.Actions {
			a, ok := actions.Lookup(aid)
			if !ok {
				continue
			}
			for _, host := range x.Hosts {
				if ctx.Err() != nil {
					return
				}
				if s.scheduleDue(ctx, x, aid, host) {
					s.runScheduled(ctx, x, a, host)
				}
			}
		}
	}
}

func (s *Service) scheduleDue(ctx context.Context, x Schedule, actionID, host string) bool {
	var last sql.NullInt64
	err := s.db.QueryRowContext(ctx, `SELECT max(e.created_at) FROM executions e JOIN execution_hosts h ON h.execution_id = e.id
		WHERE e.schedule_id = ? AND e.action_id = ? AND h.host_id = ?`, x.ID, actionID, host).Scan(&last)
	if err != nil {
		return false
	}
	return !last.Valid || !s.now().Before(time.Unix(last.Int64, 0).Add(x.Interval))
}

func (s *Service) runScheduled(ctx context.Context, x Schedule, a actions.Action, host string) {
	h, err := s.hosts.Get(ctx, host)
	if err != nil {
		if !errors.Is(err, inventory.ErrHostNotFound) {
			s.log.Error("scheduled run", "schedule", x.ID, "host", host, "error", err.Error())
		}
		return
	}
	cctx, cancel := context.WithTimeout(ctx, callTimeout)
	pins, err := s.exec.ListHostKeys(cctx, &pb.ListHostKeysRequest{})
	cancel()
	if err != nil {
		return
	}
	var pin *pb.HostKeyPin
	for _, p := range pins.GetHosts() {
		if p.GetHostId() == host {
			pin = p
		}
	}
	if pin == nil || pin.GetBlocked() {
		return
	}
	var eps []string
	for _, e := range h.Endpoints {
		port := e.Port
		if port == 0 {
			port = 22
		}
		eps = append(eps, net.JoinHostPort(e.Address, strconv.Itoa(port)))
	}
	run := &pb.AuthorizeRunRequest{HostId: host, HostKeyFingerprint: pin.GetFingerprint(), ActionId: a.ID, ModuleVersion: a.Version,
		Artifact: a.Script, ParametersJson: []byte(`{}`), CredentialRef: pin.GetCredentialRef()}
	rctx, cancel := context.WithTimeout(ctx, a.Timeout+2*time.Minute)
	r, err := s.exec.RunScheduled(rctx, &pb.RunScheduledRequest{GrantId: x.ID, Run: run, Endpoints: eps, TimeoutSeconds: uint32(a.Timeout / time.Second)})
	cancel()
	switch status.Code(err) {
	case codes.OK:
	case codes.ResourceExhausted:
		return // the executor's interval has not passed; try next tick
	default:
		s.log.Warn("scheduled run refused", "schedule", x.ID, "action", a.ID, "host", host, "error", refusal(err))
		return
	}
	s.storeScheduled(ctx, x, a, pin, r.GetExecutionId(), r.GetResult())
}

// storeScheduled records a scheduled run as a finished execution of one
// host and lets it update the host's state like any run.
func (s *Service) storeScheduled(ctx context.Context, x Schedule, a actions.Action, pin *pb.HostKeyPin, id string, res *pb.RunAttachedResponse) {
	if _, err := s.db.ExecContext(ctx, `INSERT INTO executions (id, digest, action_id, module_version, artifact_sha256, risk, requirement, state,
			durable, timeout_s, created_by, created_at, finished_at, params, schedule_id) VALUES (?, '', ?, ?, ?, 'LOW', 'schedule grant', 'finished', 0, ?, ?, ?, ?, '{}', ?)`,
		id, a.ID, a.Version, a.SHA256(), int64(a.Timeout/time.Second), "schedule", s.now().Unix(), s.now().Unix(), x.ID); err != nil {
		s.log.Error("store scheduled run", "schedule", x.ID, "error", err.Error())
		return
	}
	if _, err := s.db.ExecContext(ctx, `INSERT INTO execution_hosts (execution_id, host_id, fingerprint, credential_ref, endpoints, state, started_at)
		VALUES (?, ?, ?, ?, '[]', 'running', ?)`, id, pin.GetHostId(), pin.GetFingerprint(), pin.GetCredentialRef(), s.now().Unix()); err != nil {
		s.log.Error("store scheduled run", "schedule", x.ID, "error", err.Error())
		return
	}
	s.finishHost(id, a.ID, pin.GetHostId(), res.GetClass(), res.GetDetail(), int(res.GetExitCode()), res.GetResult(), res.GetLog(), res.GetLogTruncated())
}

// SortedActions lists the actions a schedule can run (read-only, without
// parameters), for the UI.
func SortedActions() []actions.Action {
	var out []actions.Action
	for _, a := range actions.Builtin {
		if a.ReadOnly && !a.Durable && len(a.Params) == 0 {
			out = append(out, a)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

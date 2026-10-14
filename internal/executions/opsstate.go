// SPDX-License-Identifier: AGPL-3.0-or-later

package executions

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/notify"
)

// Ops States (spec 12): instead of a health score, one of four states with
// observed_at, source and reason.
const (
	StateReady       = "READY"
	StateWarning     = "WARNING"
	StateUnreachable = "UNREACHABLE"
	StateUnknown     = "UNKNOWN"
)

// OpsState of one host.
type OpsState struct {
	State      string
	Reason     string
	Source     string
	ObservedAt time.Time
}

var stateRank = map[string]int{StateReady: 0, StateUnknown: 1, StateWarning: 2, StateUnreachable: 3}

// unreachableClasses are run outcomes that say the host could not be
// reached or did not come back.
var unreachableClasses = map[string]bool{"network_unreachable": true, "authentication_failed": true, "host_key_mismatch": true, "host_not_returned": true}

// SetNotifier makes Ops State transitions notify (spec 13). nil disables it.
func (s *Service) SetNotifier(n *notify.Notifier) { s.notifier = n }

// lastRun is the newest finished run of a host.
type lastRun struct {
	action, class string
	at            time.Time
	ok            bool
}

// evaluate derives a host's Ops State from its newest run and its update
// list.
func evaluate(run lastRun, upd *HostUpdates) OpsState {
	if run.ok && run.class != "success" && run.class != "" {
		st := StateWarning
		if unreachableClasses[run.class] {
			st = StateUnreachable
		}
		if run.class == "not_executed" {
			st = StateUnknown
		}
		return OpsState{State: st, Reason: run.action + ": " + run.class, Source: run.action, ObservedAt: run.at}
	}
	if upd != nil {
		o := OpsState{State: StateReady, Reason: "up to date", Source: "package.list_updates", ObservedAt: upd.ObservedAt}
		switch {
		case upd.Security > 0 && upd.RebootRequired:
			o.State, o.Reason = StateWarning, strconv.Itoa(upd.Security)+" security updates, reboot required"
		case upd.Security > 0:
			o.State, o.Reason = StateWarning, strconv.Itoa(upd.Security)+" security updates"
		case upd.RebootRequired:
			o.State, o.Reason = StateWarning, "reboot required"
		case upd.Total > 0:
			o.Reason = strconv.Itoa(upd.Total) + " other updates"
		}
		return o
	}
	if run.ok {
		return OpsState{State: StateReady, Reason: "reachable", Source: run.action, ObservedAt: run.at}
	}
	return OpsState{State: StateUnknown, Reason: "not checked yet", Source: "", ObservedAt: time.Time{}}
}

// refreshOpsState recomputes a host's state after the run that just
// finished and notifies a transition (worse or recovered), never a repeat.
func (s *Service) refreshOpsState(ctx context.Context, host string, run lastRun) {
	var upd *HostUpdates
	if u, err := s.Updates(ctx, host); err == nil {
		upd = &u
	}
	next := evaluate(run, upd)
	var prev string
	err := s.db.QueryRowContext(ctx, `SELECT state FROM host_ops_state WHERE host_id = ?`, host).Scan(&prev)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		s.log.Error("ops state", "host", host, "error", err.Error())
		return
	}
	now := s.now().Unix()
	observed := now
	if !next.ObservedAt.IsZero() {
		observed = next.ObservedAt.Unix()
	}
	if _, err := s.db.ExecContext(ctx, `INSERT INTO host_ops_state (host_id, state, reason, source, observed_at, changed_at) VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(host_id) DO UPDATE SET reason = excluded.reason, source = excluded.source, observed_at = excluded.observed_at,
			changed_at = CASE WHEN host_ops_state.state = excluded.state THEN host_ops_state.changed_at ELSE excluded.changed_at END,
			state = excluded.state`, host, next.State, truncate(next.Reason, 300), truncate(next.Source, 100), observed, now); err != nil {
		s.log.Error("ops state", "host", host, "error", err.Error())
		return
	}
	if prev == "" || prev == next.State || s.notifier == nil {
		return
	}
	verb := "is now"
	if stateRank[next.State] < stateRank[prev] {
		verb = "recovered:"
	}
	s.notifier.Notify(ctx, notify.Event{Kind: notify.KindOpsState, Host: host, State: next.State,
		Reason: fmt.Sprintf("%s %s (was %s): %s", host, verb+" "+next.State, prev, next.Reason), Time: s.now()})
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// AllOpsStates returns the stored Ops State of every host that has one.
func (s *Service) AllOpsStates(ctx context.Context) (map[string]OpsState, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT host_id, state, reason, source, observed_at FROM host_ops_state`)
	if err != nil {
		return nil, fmt.Errorf("ops states: %w", err)
	}
	defer rows.Close()
	out := map[string]OpsState{}
	for rows.Next() {
		var host string
		var o OpsState
		var at int64
		if err := rows.Scan(&host, &o.State, &o.Reason, &o.Source, &at); err != nil {
			return nil, err
		}
		o.ObservedAt = time.Unix(at, 0)
		out[host] = o
	}
	return out, rows.Err()
}

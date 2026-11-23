// SPDX-License-Identifier: AGPL-3.0-or-later

package executions

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/osdebian"
)

// maxStoredPackages bounds the package list kept per host for display.
const maxStoredPackages = 2000

// HostUpdates is the latest package.list_updates result of a host.
type HostUpdates struct {
	HostID         string
	ExecutionID    string
	ObservedAt     time.Time
	Total          int
	Security       int
	Kernel         int
	RebootRequired bool
	ListsUpdated   time.Time
	Packages       []osdebian.Package
}

// InstalledObserver receives every successful package.list_installed result
// of a host, once, when the run finishes (ADR 0011 D3). started is when the
// run began on the host (execution_hosts.started_at; the zero time when the
// row has none) and finished is the host's finish time, the same value the
// finish row stores. The result is the untrusted 1.1.0 JSON document the
// executor kept; the observer parses and stores it, and must not fail the
// run: it has no error to return.
//
// The call is synchronous on the finish path, on purpose: reads of one host
// are stored in finish order, which Latest relies on. The observer's
// database work is bounded by the observer itself, and a panic in it is
// recovered by the service, so the ops-state refresh always runs.
type InstalledObserver interface {
	ObserveInstalled(ctx context.Context, hostID, execID string, started, finished time.Time, result []byte)
}

// SetInstalledObserver installs the observer of package.list_installed
// results; nil turns it off. Call it before runs start.
func (s *Service) SetInstalledObserver(o InstalledObserver) { s.installed = o }

// osChangeAction is the action whose successful finish marks an OS change of
// a host: a full upgrade can move the host to a different release or
// kernel-visible OS state, so a core.facts result read before it no longer
// describes the host. No action in the catalog changes the release itself.
const osChangeAction = "package.install_all"

// notRanClasses are the classes of a host row whose run never reached the
// host's command, so nothing on the host changed. Every other class counts as
// a run that may have changed the OS: a full upgrade that ended failed,
// unknown or timed out may have applied in whole or in part.
const notRanClasses = `('precheck_failed', 'not_executed', 'skipped', 'not_run')`

// LastOSChange returns when the newest osChangeAction of host that ran (see
// notRanClasses) finished. ok is false when the host has none. A run that is
// still running has no finish yet; UpgradeOverlaps covers it.
func (s *Service) LastOSChange(ctx context.Context, host string) (at time.Time, ok bool, err error) {
	var fin sql.NullInt64
	err = s.db.QueryRowContext(ctx, `SELECT max(h.finished_at) FROM execution_hosts h JOIN executions e ON e.id = h.execution_id
		WHERE h.host_id = ? AND e.action_id = ? AND h.state = 'finished' AND h.class NOT IN `+notRanClasses,
		host, osChangeAction).Scan(&fin)
	if err != nil {
		return time.Time{}, false, fmt.Errorf("last os change of host %s: %w", host, err)
	}
	if !fin.Valid {
		return time.Time{}, false, nil
	}
	return time.Unix(fin.Int64, 0), true, nil
}

// UpgradeOverlaps reports whether an osChangeAction of host that ran (see
// LastOSChange) overlaps the interval [from, to]: it started no later than to,
// and it is still running or finished no earlier than from. A run whose end is
// unknown counts as open-ended. Both bounds are inclusive, so a tie overlaps.
func (s *Service) UpgradeOverlaps(ctx context.Context, host string, from, to time.Time) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM execution_hosts h JOIN executions e ON e.id = h.execution_id
		WHERE h.host_id = ? AND e.action_id = ?
		AND (h.state = 'running' OR (h.state = 'finished' AND h.class NOT IN `+notRanClasses+`))
		AND COALESCE(h.started_at, 0) <= ? AND (h.finished_at IS NULL OR h.finished_at >= ?))`,
		host, osChangeAction, to.Unix(), from.Unix()).Scan(&n)
	if err != nil {
		return false, fmt.Errorf("upgrade overlaps of host %s: %w", host, err)
	}
	return n == 1, nil
}

// observeInstalled hands a successful list to the observer. A panic in the
// observer is recovered and logged by class only: the panic value may carry
// host text, so it is not logged.
func (s *Service) observeInstalled(execID, host string, started, finished time.Time, result []byte) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("installed observer", "host", host, "execution", execID, "error_class", "panic")
		}
	}()
	s.installed.ObserveInstalled(s.ctx, host, execID, started, finished, result)
}

// observe keeps what successful read-only actions report about a host. at is
// the host's finish time (finishHost's finished_at); started is when the run
// began on the host.
func (s *Service) observe(execID, actionID, host, class string, started, at time.Time, result []byte) {
	switch actionID {
	case "package.list_installed":
		// Only a success carries the document; other classes keep none.
		if class == "success" && s.installed != nil {
			s.observeInstalled(execID, host, started, at, result)
		}
	case "package.install_security", "package.install_all", "system.reboot":
		// Packages may have changed: the stored update list is stale.
		if class != "precheck_failed" && class != "not_executed" {
			if _, err := s.db.ExecContext(s.ctx, `DELETE FROM host_updates WHERE host_id = ?`, host); err != nil {
				s.log.Error("forget update list", "host", host, "error", err.Error())
			}
		}
	case "package.list_updates":
		if class != "success" {
			return
		}
		u, err := osdebian.ParseUpdates(result)
		if err != nil {
			s.log.Warn("unreadable update list", "execution", execID, "host", host, "error", err.Error())
			return
		}
		pk := u.Packages
		if len(pk) > maxStoredPackages {
			pk = pk[:maxStoredPackages]
		}
		js, err := json.Marshal(pk)
		if err != nil {
			return
		}
		var lists int64
		if !u.ListsUpdated.IsZero() {
			lists = u.ListsUpdated.Unix()
		}
		if _, err := s.db.ExecContext(s.ctx, `INSERT INTO host_updates (host_id, observed_at, execution_id, total, security, kernel, reboot_required, lists_updated, packages)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(host_id) DO UPDATE SET observed_at = excluded.observed_at, execution_id = excluded.execution_id,
			total = excluded.total, security = excluded.security, kernel = excluded.kernel, reboot_required = excluded.reboot_required,
			lists_updated = excluded.lists_updated, packages = excluded.packages`,
			host, at.Unix(), execID, len(u.Packages), u.Security, u.Kernel, boolInt(u.RebootRequired), lists, string(js)); err != nil {
			s.log.Error("store update list", "host", host, "error", err.Error())
		}
	}
}

// AllUpdates returns the latest update summary of every host that has one
// (without the package lists).
func (s *Service) AllUpdates(ctx context.Context) (map[string]HostUpdates, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT host_id, execution_id, observed_at, total, security, kernel, reboot_required, lists_updated FROM host_updates`)
	if err != nil {
		return nil, fmt.Errorf("list host updates: %w", err)
	}
	defer rows.Close()
	out := map[string]HostUpdates{}
	for rows.Next() {
		u, err := scanUpdates(rows)
		if err != nil {
			return nil, err
		}
		out[u.HostID] = u
	}
	return out, rows.Err()
}

// ErrNoUpdates is returned when a host has no update list yet.
var ErrNoUpdates = errors.New("no update list for this host yet")

// Updates returns the latest update list of one host.
func (s *Service) Updates(ctx context.Context, host string) (HostUpdates, error) {
	var pk string
	row := s.db.QueryRowContext(ctx, `SELECT host_id, execution_id, observed_at, total, security, kernel, reboot_required, lists_updated, packages
		FROM host_updates WHERE host_id = ?`, host)
	u, err := scanUpdates(row, &pk)
	if errors.Is(err, sql.ErrNoRows) {
		return HostUpdates{}, ErrNoUpdates
	}
	if err != nil {
		return HostUpdates{}, err
	}
	if err := json.Unmarshal([]byte(pk), &u.Packages); err != nil {
		return HostUpdates{}, fmt.Errorf("host updates: %w", err)
	}
	return u, nil
}

func scanUpdates(sc interface{ Scan(...any) error }, extra ...any) (HostUpdates, error) {
	var u HostUpdates
	var observed, lists int64
	var reboot int
	dest := append([]any{&u.HostID, &u.ExecutionID, &observed, &u.Total, &u.Security, &u.Kernel, &reboot, &lists}, extra...)
	if err := sc.Scan(dest...); err != nil {
		return HostUpdates{}, err
	}
	u.ObservedAt, u.RebootRequired = time.Unix(observed, 0), reboot == 1
	if lists > 0 {
		u.ListsUpdated = time.Unix(lists, 0)
	}
	return u, nil
}

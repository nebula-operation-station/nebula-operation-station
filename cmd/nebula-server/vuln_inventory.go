// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/osdebian"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulninventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnver"
)

// inventoryFactsAction is the action whose latest result gives a host's
// release (os-release values, ADR 0011 D3).
const inventoryFactsAction = "core.facts"

// factsSource is the part of executions.Service the inventory reads from.
type factsSource interface {
	LastResult(ctx context.Context, actionID, host string) ([]byte, time.Time, bool, error)
}

// vulnInventoryService stores each successful package.list_installed result
// as a vulninventory read (ADR 0011 D3). It implements
// executions.InstalledObserver. It never fails a run: errors are logged by
// class only, never with package names or result text.
type vulnInventoryService struct {
	store *vulninventory.Store
	facts factsSource
	log   *slog.Logger
}

// newVulnInventoryService returns the service on db (server.db) that reads
// the release of each host from facts.
func newVulnInventoryService(db *sql.DB, facts factsSource, log *slog.Logger) (*vulnInventoryService, error) {
	st, err := vulninventory.New(db)
	if err != nil {
		return nil, fmt.Errorf("vulnerability inventory store: %w", err)
	}
	return &vulnInventoryService{store: st, facts: facts, log: log}, nil
}

// observeTimeout bounds the database work of one ObserveInstalled call (the
// release lookup and the store write). The parse is bounded by the input
// limits of osdebian.
const observeTimeout = 30 * time.Second

// markTimeout bounds the write of a partial marker. The marker is written
// on a context that is not cancelled by the observe deadline, so that a
// lookup or write that timed out can still leave a marker behind.
const markTimeout = 5 * time.Second

// ObserveInstalled parses result (untrusted host output) with
// osdebian.ParseInstalledResult and stores the read of host from execution
// execID at time at. The distribution comes only from the host's newest
// successful core.facts result, and only when that result is at least as
// recent as the list (finished at or after at); otherwise the read is stored
// partial with vulninventory.ReasonFactsOlder. Without a facts result the
// read is stored incomplete.
//
// Fail closed: when the release lookup fails, the facts are older than the
// list, or the store fails to write the read, a partial marker is stored
// instead. The host's older complete read then stops being its latest
// inventory. A refusal of the store (a field over its limit caused by host
// content) gives ReasonRefused; any other store failure gives
// ReasonStoreUnavailable. If the marker cannot be stored either, the failure
// is only logged.
//
// On shutdown (parent is cancelled) nothing is written, because the server
// is stopping and a cancelled write is not a refusal of the list.
func (v *vulnInventoryService) ObserveInstalled(parent context.Context, hostID, execID string, at time.Time, result []byte) {
	ctx, cancel := context.WithTimeout(parent, observeTimeout)
	defer cancel()
	facts, factsAt, ok, err := v.facts.LastResult(ctx, inventoryFactsAction, hostID)
	if err != nil {
		if v.shutdown(parent, hostID, execID) {
			return
		}
		v.log.Error("vulnerability inventory: release lookup", "host", hostID, "execution", execID, "error_class", "lookup")
		v.markFailed(parent, hostID, execID, at, vulninventory.ReasonLookupFailed)
		return
	}
	var eco string
	var distro vulnver.Distro
	if ok {
		if factsAt.Unix() < at.Unix() {
			v.markFailed(parent, hostID, execID, at, vulninventory.ReasonFactsOlder)
			return
		}
		if id, ver, code, readable := executions.OSRelease(facts); readable {
			eco, distro = vulninventory.Ecosystem(id, ver, code)
		}
	}
	inv := osdebian.ParseInstalledResult(result, osdebian.ReadStatus{ExitCode: 0}, distro)
	read := vulninventory.FromInstalled(hostID, execID, at, eco, inv)
	if _, err := v.store.Put(ctx, read); err != nil {
		if v.shutdown(parent, hostID, execID) {
			return
		}
		class := inventoryErrorClass(err)
		reason := vulninventory.ReasonStoreUnavailable
		if class == "limit" || class == "invalid_read" {
			reason = vulninventory.ReasonRefused
		}
		v.log.Error("vulnerability inventory: store read", "host", hostID, "execution", execID, "error_class", class)
		v.markFailed(parent, hostID, execID, at, reason)
		return
	}
	binaries := 0
	for _, c := range read.Components {
		binaries += len(c.Binaries)
	}
	v.log.Info("audit", "kind", "vuln_inventory_read_stored", "host", hostID, "execution", execID,
		"complete", read.Complete, "binaries", binaries, "sources", len(read.Components))
}

// shutdown reports whether parent is cancelled (the server is stopping). If
// so it logs the skip by class and the caller writes nothing.
func (v *vulnInventoryService) shutdown(parent context.Context, hostID, execID string) bool {
	if parent.Err() == nil {
		return false
	}
	v.log.Info("vulnerability inventory: skipped on shutdown", "host", hostID, "execution", execID, "error_class", "canceled")
	return true
}

// markFailed stores the partial marker of a list that could not be read or
// stored, so that the host's previous read is no longer its latest one. The
// marker is written on a fresh context bounded by markTimeout. A failure to
// store the marker is logged by class and does not fail the run.
func (v *vulnInventoryService) markFailed(parent context.Context, hostID, execID string, at time.Time, reason string) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), markTimeout)
	defer cancel()
	if _, err := v.store.Put(ctx, vulninventory.Failed(hostID, execID, at, reason)); err != nil {
		v.log.Error("vulnerability inventory: store failure marker", "host", hostID, "execution", execID, "error_class", inventoryErrorClass(err))
		return
	}
	v.log.Info("audit", "kind", "vuln_inventory_read_failed", "host", hostID, "execution", execID, "reason", reason)
}

// inventoryErrorClass names the class of an error without its text: a store
// refusal (limit or format), a context end (canceled or timeout), or any
// other store failure ("store", for example a busy or closed database).
func inventoryErrorClass(err error) string {
	switch {
	case errors.Is(err, vulninventory.ErrLimit):
		return "limit"
	case errors.Is(err, vulninventory.ErrInvalidRead):
		return "invalid_read"
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	default:
		return "store"
	}
}

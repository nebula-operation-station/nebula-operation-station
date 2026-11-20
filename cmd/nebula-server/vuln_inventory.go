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
// release lookup and the store writes). The parse is bounded by the input
// limits of osdebian.
const observeTimeout = 30 * time.Second

// ObserveInstalled parses result (untrusted host output) with
// osdebian.ParseInstalledResult and stores the read of host from execution
// execID at time at. The distribution comes only from the host's newest
// successful core.facts result; without one the read is stored incomplete.
//
// Fail closed: when the release lookup fails, or the store refuses the read
// (for example a field over its limit caused by host content), a partial
// marker (vulninventory.Failed) is stored instead. The host's older complete
// read then stops being its latest inventory. If the marker cannot be
// stored either, the failure is only logged.
func (v *vulnInventoryService) ObserveInstalled(parent context.Context, hostID, execID string, at time.Time, result []byte) {
	ctx, cancel := context.WithTimeout(parent, observeTimeout)
	defer cancel()
	facts, _, ok, err := v.facts.LastResult(ctx, inventoryFactsAction, hostID)
	if err != nil {
		v.log.Error("vulnerability inventory: release lookup", "host", hostID, "execution", execID, "error_class", "lookup")
		v.markFailed(ctx, hostID, execID, at, vulninventory.ReasonLookupFailed)
		return
	}
	var eco string
	var distro vulnver.Distro
	if ok {
		if id, ver, code, readable := executions.OSRelease(facts); readable {
			eco, distro = vulninventory.Ecosystem(id, ver, code)
		}
	}
	inv := osdebian.ParseInstalledResult(result, osdebian.ReadStatus{ExitCode: 0}, distro)
	read := vulninventory.FromInstalled(hostID, execID, at, eco, inv)
	if _, err := v.store.Put(ctx, read); err != nil {
		v.log.Error("vulnerability inventory: store read", "host", hostID, "execution", execID, "error_class", inventoryErrorClass(err))
		v.markFailed(ctx, hostID, execID, at, vulninventory.ReasonRefused)
		return
	}
	binaries := 0
	for _, c := range read.Components {
		binaries += len(c.Binaries)
	}
	v.log.Info("audit", "kind", "vuln_inventory_read_stored", "host", hostID, "execution", execID,
		"complete", read.Complete, "binaries", binaries, "sources", len(read.Components))
}

// markFailed stores the partial marker of a list that could not be read or
// stored, so that the host's previous read is no longer its latest one. A
// failure to store the marker is logged by class and does not fail the run.
func (v *vulnInventoryService) markFailed(ctx context.Context, hostID, execID string, at time.Time, reason string) {
	if _, err := v.store.Put(ctx, vulninventory.Failed(hostID, execID, at, reason)); err != nil {
		v.log.Error("vulnerability inventory: store failure marker", "host", hostID, "execution", execID, "error_class", inventoryErrorClass(err))
		return
	}
	v.log.Info("audit", "kind", "vuln_inventory_read_failed", "host", hostID, "execution", execID, "reason", reason)
}

// inventoryErrorClass names the class of a store error without its text.
func inventoryErrorClass(err error) string {
	switch {
	case errors.Is(err, vulninventory.ErrLimit):
		return "limit"
	case errors.Is(err, vulninventory.ErrInvalidRead):
		return "invalid_read"
	default:
		return "store"
	}
}

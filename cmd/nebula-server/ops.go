// SPDX-License-Identifier: AGPL-3.0-or-later

// Ops agent wiring (ADR 0016 D2, D7, D12): the notes store in its own file
// next to server.db, the ops API under /api/v1/ops/ for the one ops token,
// and the suggestion index the executions service reads (ADR 0016 D9).
//
// Source gap: the finding, listener and fix-decision sources of the
// projection are not connected in this build (ag11 defines the projector,
// not its inputs). Until they are, the projector sees no findings, so the
// work list carries only the fleet summary with zero counters and no
// group is ever due. Nothing here calls the executor for the ops agent.

package main

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/opsconfig"
	"github.com/nebula-operation-station/nebula-operation-station/internal/opsfacts"
	"github.com/nebula-operation-station/nebula-operation-station/internal/opsnotes"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverconfig"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/api"
)

// Ops agent wiring constants.
const (
	// opsNotesDir and opsNotesFile locate the notes database: a private
	// directory under the data dir, outside the server backup set (ADR 0016
	// D7). Deviation: the spec says "next to server.db"; the store refuses a
	// non-0700 directory and the data dir is not ours to re-mode.
	opsNotesDir  = "opsnotes"
	opsNotesFile = "notes.db"
	// opsPruneInterval is how often the notes retention runs.
	opsPruneInterval = time.Hour
	// opsSuggestionTimeout bounds one lookup of the suggestion index.
	opsSuggestionTimeout = 5 * time.Second
)

// opsAgentCorePrompt is the agent's fixed core prompt, covered by
// prompt_version. This build carries none: the agent ships its own.
const opsAgentCorePrompt = ""

// newOpsNotes opens the notes store in its own private directory under
// dataDir. The store requires a 0700 directory of its own, so the data
// directory's mode is not changed; the file is still apart from server.db.
func newOpsNotes(dataDir string) (*opsnotes.Store, error) {
	dir := filepath.Join(dataDir, opsNotesDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("ops notes: %w", err)
	}
	abs, err := filepath.Abs(filepath.Join(dir, opsNotesFile))
	if err != nil {
		return nil, fmt.Errorf("ops notes: %w", err)
	}
	st, err := opsnotes.Open(abs, time.Now)
	if err != nil {
		return nil, fmt.Errorf("ops notes: %w", err)
	}
	return st, nil
}

// runOpsNotes prunes the notes every opsPruneInterval until ctx ends, then
// closes the store. Retention uses the injected clock of the caller.
func runOpsNotes(ctx context.Context, notes *opsnotes.Store, log *slog.Logger) {
	defer func() {
		if err := notes.Close(); err != nil {
			log.Error("ops notes: close", "error", err)
		}
	}()
	prune := func(now time.Time) {
		n, err := notes.Prune(ctx, now)
		if err != nil {
			log.Error("ops notes: prune", "error", err)
			return
		}
		if n > 0 {
			log.Info("ops notes pruned", "count", n)
		}
	}
	prune(time.Now())
	t := time.NewTicker(opsPruneInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			prune(now)
		}
	}
}

// opsSuggestions implements executions.SuggestionIndex over the notes store.
type opsSuggestions struct {
	notes *opsnotes.Store
}

var _ executions.SuggestionIndex = opsSuggestions{}

// Step resolves "<note ID>.<step>" to the step's action, family and host.
func (s opsSuggestions) Step(ref string) (action, family, hostID string, ok bool) {
	id, idx, ok := parseSuggestionRef(ref)
	if !ok {
		return "", "", "", false
	}
	ctx, cancel := context.WithTimeout(context.Background(), opsSuggestionTimeout)
	defer cancel()
	st, found, err := s.notes.Step(ctx, id, idx)
	if err != nil || !found {
		return "", "", "", false
	}
	return st.ActionID, st.Family, st.HostID, true
}

// Match returns the ID of the newest stored note with a step of family on
// hostID.
func (s opsSuggestions) Match(family, hostID string) (string, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), opsSuggestionTimeout)
	defer cancel()
	st, found, err := s.notes.MatchStep(ctx, family, hostID)
	if err != nil || !found {
		return "", false
	}
	return strconv.FormatInt(st.NoteID, 10), true
}

// Family returns the family of an allowlisted action.
func (s opsSuggestions) Family(actionID string) (string, bool) {
	return opsfacts.Families(actionID)
}

// parseSuggestionRef splits "<note ID>.<step>"; both parts are positive.
func parseSuggestionRef(ref string) (int64, int, bool) {
	i := strings.LastIndexByte(ref, '.')
	if i <= 0 || i == len(ref)-1 {
		return 0, 0, false
	}
	id, err := strconv.ParseInt(ref[:i], 10, 64)
	if err != nil || id <= 0 {
		return 0, 0, false
	}
	idx, err := strconv.Atoi(ref[i+1:])
	if err != nil || idx <= 0 {
		return 0, 0, false
	}
	return id, idx, true
}

// opsHostsSource adapts the inventory to the projection.
type opsHostsSource struct {
	hosts func(ctx context.Context) ([]inventory.Host, error)
}

// Hosts returns the inventory hosts for the projection.
func (s opsHostsSource) Hosts(ctx context.Context) ([]opsfacts.Host, error) {
	hs, err := s.hosts(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]opsfacts.Host, 0, len(hs))
	for _, h := range hs {
		out = append(out, opsfacts.Host{ID: h.ID, Label: h.DisplayName,
			Environment: string(h.Environment), Criticality: opsfacts.Criticality(h.Criticality)})
	}
	return out, nil
}

// opsNoFindings is the finding, listener and decision source until the
// inputs are connected (see the file comment).
type opsNoFindings struct{}

func (opsNoFindings) Findings(context.Context) ([]opsfacts.Finding, error) { return nil, nil }
func (opsNoFindings) Listeners(context.Context, string) ([]opsfacts.Port, error) {
	return nil, nil
}

// opsCatalog accepts only actions on the suggestion allowlist.
type opsCatalog struct{}

func (opsCatalog) HasAction(action string) bool {
	_, ok := opsfacts.Families(action)
	return ok
}

// opsSkipLog records skipped inputs in the server log.
type opsSkipLog struct{ log *slog.Logger }

func (a opsSkipLog) Skipped(_ context.Context, s opsfacts.Skip) error {
	a.log.Warn("audit", "kind", "ops_projection_skip", "scope", string(s.Scope), "rule", s.Rule)
	return nil
}

// opsFactsSource is the server's OpsFacts over the projector.
type opsFactsSource struct {
	proj  *opsfacts.Projector
	hosts opsHostsSource
}

// EligibleGroups returns the projector's eligible groups.
func (f opsFactsSource) EligibleGroups(ctx context.Context) ([]opsfacts.Group, error) {
	return f.proj.EligibleGroups(ctx)
}

// External returns the projector's fleet counters.
func (f opsFactsSource) External(ctx context.Context) (opsfacts.ExternalProjection, error) {
	return f.proj.External(ctx)
}

// Hosts returns the IDs of the managed hosts.
func (f opsFactsSource) Hosts(ctx context.Context) ([]string, error) {
	hs, err := f.hosts.Hosts(ctx)
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(hs))
	for _, h := range hs {
		ids = append(ids, h.ID)
	}
	return ids, nil
}

// newOpsAPI returns the ops API handler, or nil when no ops token is
// configured. The settings row lives in db (server.db).
func newOpsAPI(cfg serverconfig.APIConfig, db *sql.DB, notes *opsnotes.Store,
	hosts func(ctx context.Context) ([]inventory.Host, error), log *slog.Logger) (http.Handler, error) {
	if _, ok := cfg.OpsToken(); !ok {
		return nil, nil
	}
	settings, err := opsconfig.NewStore(db, time.Now)
	if err != nil {
		return nil, fmt.Errorf("ops api: %w", err)
	}
	src := opsHostsSource{hosts: hosts}
	proj, err := opsfacts.New(opsfacts.Sources{Inventory: src, Listeners: opsNoFindings{}, Findings: opsNoFindings{},
		Catalog: opsCatalog{}, Audit: opsSkipLog{log: log}})
	if err != nil {
		return nil, fmt.Errorf("ops api: projection: %w", err)
	}
	h, err := api.NewOps(api.OpsOptions{Tokens: cfg.Tokens, Settings: settings,
		Facts: opsFactsSource{proj: proj, hosts: src}, Notes: notes, CorePrompt: opsAgentCorePrompt, Log: log})
	if err != nil {
		return nil, fmt.Errorf("ops api: %w", err)
	}
	return h, nil
}

// SPDX-License-Identifier: AGPL-3.0-or-later

// Ops agent wiring (ADR 0016 D2, D7, D12): the notes store in its own file
// next to server.db, the ops API under /api/v1/ops/ for the one ops token,
// and the suggestion index the executions service reads (ADR 0016 D9).
//
// The projection reads its findings, fix decisions and listening ports from
// the stored sources (ops_sources.go, ADR 0016 D3, D4). Nothing here calls the
// executor for the ops agent.

package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/helpdocs"
	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/opsconfig"
	"github.com/nebula-operation-station/nebula-operation-station/internal/opsfacts"
	"github.com/nebula-operation-station/nebula-operation-station/internal/opsnotes"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverconfig"
	"github.com/nebula-operation-station/nebula-operation-station/internal/trafficingest"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfix"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/api"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
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

// parseSuggestionRef splits "<note ID>.<step>" with the UI's parser, so the
// server and the operation form accept exactly the same references. Steps
// count from 1, as the notes store numbers them.
func parseSuggestionRef(ref string) (int64, int, bool) {
	return ui.ParseSuggestionRef(ref)
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

// opsSources are the stored inputs of the projection (ADR 0016 D3, D4). The
// server passes the vulnerability store, the operation results and container
// previews that the "fix with" pages read, and the net.facts source of the
// listening ports. Nil LastResults or Preview switch that read off, as on the
// pages (the fix decision then reads "off", the same as there).
type opsSources struct {
	// Findings is the vulnerability store (vuln.store). Required.
	Findings vulnFindingReader
	// LastResults reads the newest successful result of an action per host
	// (executions.Service.LastResults). Nil when operations are off.
	LastResults func(ctx context.Context, action string) (map[string]executions.LastResultRow, error)
	// Preview reads a host's newest container update preview
	// (executions.Batches.LatestContainerPreview). Nil when container updates
	// are off.
	Preview func(ctx context.Context, hostID string) (executions.ContainerPreview, error)
	// Traffic reads the stored net.facts results of the hosts (the listener
	// source). Required.
	Traffic trafficingest.Source
	// Tier is the host criticality of the finding scores: the tierer the
	// vulnerability pages use (newVulnServiceWithTier). Nil: every subject
	// is unset.
	Tier *vulnTierer
	// Now is the clock of the listener freshness rule; nil means time.Now.
	Now func() time.Time
}

// errOpsPreviewOff: the container preview source is off. The resolver is
// given no preview source then, so this error is never read.
var errOpsPreviewOff = errors.New("container previews are off")

// opsOffPreviews is the preview source of a server with container updates
// off. It only stands in for the required inner source of the finding
// source; the resolver is built without previews in that case.
type opsOffPreviews struct{}

// Preview always fails: the decision never reads it when previews are off.
func (opsOffPreviews) Preview(context.Context, string) (vulnfix.Preview, error) {
	return vulnfix.Preview{}, errOpsPreviewOff
}

// newOpsFindings builds the finding source over the stored sources. The fix
// decision comes from the same sources as the vulnerability pages
// (ui.NewVulnFixSources), one resolver per Findings call.
func newOpsFindings(srcs opsSources) (opsVulnFindings, error) {
	updates, previews := ui.NewVulnFixSources(srcs.LastResults, srcs.Preview)
	inner := previews
	if inner == nil {
		inner = opsOffPreviews{}
	}
	newFixes := func(g vulnfix.PreviewSource) fixDecider {
		if previews == nil {
			return vulnfix.NewResolver(updates, nil)
		}
		return vulnfix.NewResolver(updates, g)
	}
	return newOpsVulnFindingsWith(srcs.Findings, inner, newFixes, srcs.Tier)
}

// newOpsAPI returns the ops API handler, or nil when no ops token is
// configured. The settings row lives in db (server.db). srcs are the stored
// sources of the projection. accepted (may be nil) runs after each note is
// stored for the first time (see ops_suggestion.go).
func newOpsAPI(cfg serverconfig.APIConfig, db *sql.DB, notes *opsnotes.Store,
	hosts func(ctx context.Context) ([]inventory.Host, error), log *slog.Logger,
	accepted func(opsnotes.Note), srcs opsSources) (http.Handler, error) {
	return newOpsAPIWithChunk(cfg, db, notes, hosts, log, accepted, srcs, opsDocChunk(log))
}

// newOpsAPIWithChunk is newOpsAPI with the documentation citation check given
// by the caller (nil refuses every citation). newOpsAPI passes opsDocChunk.
func newOpsAPIWithChunk(cfg serverconfig.APIConfig, db *sql.DB, notes *opsnotes.Store,
	hosts func(ctx context.Context) ([]inventory.Host, error), log *slog.Logger,
	accepted func(opsnotes.Note), srcs opsSources, chunk func(chunkID string) bool) (http.Handler, error) {
	if _, ok := cfg.OpsToken(); !ok {
		return nil, nil
	}
	settings, err := opsconfig.NewStore(db, time.Now)
	if err != nil {
		return nil, fmt.Errorf("ops api: %w", err)
	}
	src := opsHostsSource{hosts: hosts}
	findings, err := newOpsFindings(srcs)
	if err != nil {
		return nil, fmt.Errorf("ops api: findings: %w", err)
	}
	now := srcs.Now
	if now == nil {
		now = time.Now
	}
	listeners := newOpsVulnListeners(srcs.Traffic, now)
	proj, err := opsfacts.New(opsfacts.Sources{Inventory: src, Listeners: listeners, Findings: findings,
		Catalog: opsCatalog{}, Audit: opsSkipLog{log: log}})
	if err != nil {
		return nil, fmt.Errorf("ops api: projection: %w", err)
	}
	h, err := api.NewOps(api.OpsOptions{Tokens: cfg.Tokens, Settings: settings,
		Facts: opsFactsSource{proj: proj, hosts: src}, Notes: notes, CorePrompt: opsAgentCorePrompt, Log: log,
		OnNoteAccepted: accepted, DocChunk: chunk})
	if err != nil {
		return nil, fmt.Errorf("ops api: %w", err)
	}
	return h, nil
}

// opsDocChunk returns the citation check of ADR 0016 D6: a note may cite only
// chunk IDs of the embedded documentation index, the same index the ops agent
// searches (helpdocs.FromDocsembed in cmd/nebula-ops-agent). When the index
// does not load, it logs a warning and returns nil, so no note may cite.
func opsDocChunk(log *slog.Logger) func(chunkID string) bool {
	return opsDocChunkFrom(log, helpdocs.FromDocsembed)
}

// opsDocChunkFrom is opsDocChunk over the given index loader. A failed load
// yields nil, which refuses every citation (fail closed).
func opsDocChunkFrom(log *slog.Logger, load func() (*helpdocs.Index, error)) func(chunkID string) bool {
	ix, err := load()
	if err != nil {
		log.Warn("ops api: documentation index not loaded, notes may not cite chunks", "error", err)
		return nil
	}
	ids := make(map[string]struct{}, len(ix.Chunks))
	for _, c := range ix.Chunks {
		ids[c.ID] = struct{}{}
	}
	return func(chunkID string) bool {
		_, ok := ids[chunkID]
		return ok
	}
}

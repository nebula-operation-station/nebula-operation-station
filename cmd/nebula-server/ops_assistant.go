// SPDX-License-Identifier: AGPL-3.0-or-later

// The Ops tab of the Assistant panel (ADR 0016 D11) on the server: its cards
// and questions come from the notes store, its admin rule is the server's
// (as for the operation suggestions), its catalog is checked against the same
// facts the ops API resolves, its status is the stored settings plus the last
// run the agent reported, and its trigger is the ops agent trigger, which
// carries no data. Without the ops token none of this is wired and the Ops
// routes answer 404 (ui.Options.AssistantOps stays nil).
package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/opsconfig"
	"github.com/nebula-operation-station/nebula-operation-station/internal/opsfacts"
	"github.com/nebula-operation-station/nebula-operation-station/internal/opsnotes"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverconfig"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/api"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
)

// opsAssistantCallTimeout bounds one read of the Ops tab's catalog or status.
const opsAssistantCallTimeout = 5 * time.Second

// errOpsAssistantNotTouched is the fixed text of a question whose agent
// trigger was not touched. It names no question and no host.
var errOpsAssistantNotTouched = errors.New("ops agent trigger not touched")

// opsRunReader is the part of the ops API handler the Ops tab reads: the last
// status report of the agent (api.OpsHandler.LastOpsStatus).
type opsRunReader interface {
	LastOpsStatus() (api.OpsRunStatus, bool)
}

// opsRunHolder gives the Ops tab the ops API handler. The handler is built
// after ui.New, so the tab reads it through this holder, which is set before
// the server listens. A nil or foreign handler leaves the holder empty.
type opsRunHolder struct {
	mu  sync.Mutex
	src opsRunReader
}

// set takes the ops API handler from newOpsAPI; nil (no ops token) is a no-op.
func (h *opsRunHolder) set(oh http.Handler) {
	r, ok := oh.(opsRunReader)
	if !ok {
		return
	}
	h.mu.Lock()
	h.src = r
	h.mu.Unlock()
}

// last returns the last run the agent reported, false when there is none.
func (h *opsRunHolder) last() (api.OpsRunStatus, bool) {
	h.mu.Lock()
	src := h.src
	h.mu.Unlock()
	if src == nil {
		return api.OpsRunStatus{}, false
	}
	return src.LastOpsStatus()
}

// opsAssistantSnapshotMaxAge is how long one read of the inventory and the
// projection serves all cards. A render of the Ops tab asks the catalog once
// per card; they all share one snapshot, so a render costs one projection and
// one inventory read, not one per card. The snapshot is at most this old.
const opsAssistantSnapshotMaxAge = 2 * time.Second

// opsAssistantSnapshot is one read of the catalog's facts. A failed read is
// kept as failed, so the cards deny until the next window.
type opsAssistantSnapshot struct {
	at       time.Time
	hosts    map[string]bool
	hostErr  bool
	digests  map[string]string
	groupErr bool
}

// opsAssistantCatalog checks the cards of the Ops tab against the server's
// current facts: the inventory hosts, and the eligible groups of the same
// projection the ops API resolves fix notes against (lab data class). Reads
// are shared through one snapshot (opsAssistantSnapshotMaxAge).
type opsAssistantCatalog struct {
	hosts  func(ctx context.Context) ([]inventory.Host, error)
	groups func(ctx context.Context) ([]opsfacts.Group, error)
	now    func() time.Time

	mu   sync.Mutex
	snap *opsAssistantSnapshot
}

var _ ui.AssistantOpsCatalog = (*opsAssistantCatalog)(nil)

// newOpsAssistantCatalog returns the catalog over the given reads; now is the
// clock of the snapshot window.
func newOpsAssistantCatalog(hosts func(ctx context.Context) ([]inventory.Host, error),
	groups func(ctx context.Context) ([]opsfacts.Group, error), now func() time.Time) *opsAssistantCatalog {
	return &opsAssistantCatalog{hosts: hosts, groups: groups, now: now}
}

// current returns the snapshot of the window, reading the sources when it has
// expired. The reads run under one timeout each and hold the lock, so
// concurrent renders wait for one read instead of each doing their own.
// The ui catalog interface has no request context, so the reads are not tied
// to the request; each is bounded by opsAssistantCallTimeout.
func (c *opsAssistantCatalog) current() *opsAssistantSnapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if c.snap != nil && now.Sub(c.snap.at) < opsAssistantSnapshotMaxAge {
		return c.snap
	}
	s := &opsAssistantSnapshot{at: now, hosts: map[string]bool{}, digests: map[string]string{}}
	hctx, hcancel := context.WithTimeout(context.Background(), opsAssistantCallTimeout)
	hs, err := c.hosts(hctx)
	hcancel()
	if err != nil {
		s.hostErr = true
	}
	for _, h := range hs {
		s.hosts[h.ID] = true
	}
	gctx, gcancel := context.WithTimeout(context.Background(), opsAssistantCallTimeout)
	gs, err := c.groups(gctx)
	gcancel()
	if err != nil {
		s.groupErr = true
	}
	for _, g := range gs {
		s.digests[g.Key] = g.Digest
	}
	c.snap = s
	return s
}

// HostExists reports whether the host is in the inventory. A failed read
// reports false, so no step button is shown.
func (c *opsAssistantCatalog) HostExists(hostID string) bool {
	s := c.current()
	return !s.hostErr && s.hosts[hostID]
}

// ActionFamily returns the family of an allowlisted action.
func (*opsAssistantCatalog) ActionFamily(actionID string) (string, bool) {
	return opsfacts.Families(actionID)
}

// CurrentDigest returns the digest of the eligible group ref. Only fix notes
// have groups; any other kind reports false, which marks the card outdated.
func (c *opsAssistantCatalog) CurrentDigest(kind opsnotes.Kind, ref string) (string, bool) {
	if kind != opsnotes.KindFix {
		return "", false
	}
	s := c.current()
	if s.groupErr {
		return "", false
	}
	d, ok := s.digests[ref]
	return d, ok
}

// newOpsAssistantGroups builds the projection the ops API serves, from the
// same sources (see newOpsAPIWithChunk in ops.go), and returns its eligible
// groups. It is a second projector over the same stores; ops.go is unchanged.
func newOpsAssistantGroups(srcs opsSources, hosts func(ctx context.Context) ([]inventory.Host, error), log *slog.Logger) (func(ctx context.Context) ([]opsfacts.Group, error), error) {
	findings, err := newOpsFindings(srcs)
	if err != nil {
		return nil, fmt.Errorf("ops assistant: findings: %w", err)
	}
	now := srcs.Now
	if now == nil {
		now = time.Now
	}
	listeners := newOpsVulnListeners(srcs.Traffic, now)
	proj, err := opsfacts.New(opsfacts.Sources{Inventory: opsHostsSource{hosts: hosts}, Listeners: listeners,
		Findings: findings, Catalog: opsCatalog{}, Audit: opsSkipLog{log: log}})
	if err != nil {
		return nil, fmt.Errorf("ops assistant: projection: %w", err)
	}
	return proj.EligibleGroups, nil
}

// opsAssistantWiring holds what the Ops tab needs. Tests build it with fakes.
type opsAssistantWiring struct {
	// store is the notes store of the Ops tab.
	store ui.AssistantOpsStore
	// isAdmin is the server's admin rule (vulnAdmin).
	isAdmin func(ctx context.Context) bool
	// catalog checks the cards.
	catalog ui.AssistantOpsCatalog
	// settings reads the stored ops agent settings (Enabled).
	settings opsSettingsReader
	// runs is the last run the agent reported.
	runs *opsRunHolder
	// touch wakes the agent; false when the trigger was not touched.
	touch func() bool
	// user overrides the session user (tests); nil uses the session.
	user func(r *http.Request) (string, bool)
}

// wireOpsAssistant returns the Ops tab wiring over the server's database and
// stores. Call it only when the ops token is configured.
func wireOpsAssistant(db *sql.DB, notes *opsnotes.Store, isAdmin func(ctx context.Context) bool,
	srcs opsSources, hosts func(ctx context.Context) ([]inventory.Host, error), runs *opsRunHolder,
	touch func() bool, log *slog.Logger) (opsAssistantWiring, error) {
	settings, err := opsconfig.NewStore(db, time.Now)
	if err != nil {
		return opsAssistantWiring{}, fmt.Errorf("ops assistant: %w", err)
	}
	groups, err := newOpsAssistantGroups(srcs, hosts, log)
	if err != nil {
		return opsAssistantWiring{}, err
	}
	return opsAssistantWiring{
		store:    notes,
		isAdmin:  isAdmin,
		catalog:  newOpsAssistantCatalog(hosts, groups, time.Now),
		settings: settings,
		runs:     runs,
		touch:    touch,
	}, nil
}

// status is the agent status line: the stored Enabled flag and the last
// reported run. Rejections are the agent's refusal reasons, already short
// identifiers from the ops API; the Ops tab shows them as escaped text.
func (w opsAssistantWiring) status(ctx context.Context) (ui.AssistantOpsStatus, error) {
	row, err := w.settings.Get(ctx)
	if err != nil {
		return ui.AssistantOpsStatus{}, fmt.Errorf("ops assistant: settings: %w", err)
	}
	st := ui.AssistantOpsStatus{Enabled: row.Enabled}
	if run, ok := w.runs.last(); ok {
		st.LastRun = run.ReceivedAt
		st.Rejections = run.Refusals
	}
	return st, nil
}

// touchTrigger wakes the agent after a question was stored. The trigger carries
// no data; a missed touch answers the fixed error text, and the agent then
// runs on its timer.
func (w opsAssistantWiring) touchTrigger() error {
	if w.touch == nil || !w.touch() {
		return errOpsAssistantNotTouched
	}
	return nil
}

// applyOpsAssistant is the ops token gate of the Ops tab: with the ops token
// configured it calls wire and sets the tab on the UI options; without it,
// wire is not called and the options stay as they are (the Ops routes then
// answer 404). A wiring error is returned, not swallowed.
func applyOpsAssistant(o ui.Options, cfg serverconfig.APIConfig, wire func() (opsAssistantWiring, error)) (ui.Options, error) {
	if _, ok := cfg.OpsToken(); !ok {
		return o, nil
	}
	w, err := wire()
	if err != nil {
		return o, err
	}
	return withOpsAssistant(o, w), nil
}

// withOpsAssistant sets the Ops tab on the UI options. The admin rule is the
// server's, as for the operation suggestions (withOperationSuggestions).
func withOpsAssistant(o ui.Options, w opsAssistantWiring) ui.Options {
	o.AssistantOps = &ui.AssistantOps{
		Store: w.store,
		IsAdmin: func(ctx context.Context, _ string) (bool, error) {
			return w.isAdmin(ctx), nil
		},
		Catalog: w.catalog,
		Status:  w.status,
		User:    w.user,
		Touch:   w.touchTrigger,
	}
	return o
}

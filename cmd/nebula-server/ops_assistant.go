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

// opsAssistantCatalog checks the cards of the Ops tab against the server's
// current facts: the inventory hosts, and the eligible groups of the same
// projection the ops API resolves fix notes against (lab data class).
type opsAssistantCatalog struct {
	hosts  func(ctx context.Context) ([]inventory.Host, error)
	groups func(ctx context.Context) ([]opsfacts.Group, error)
}

var _ ui.AssistantOpsCatalog = opsAssistantCatalog{}

// HostExists reports whether the host is in the inventory. A failed read
// reports false, so no step button is shown.
func (c opsAssistantCatalog) HostExists(hostID string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), opsAssistantCallTimeout)
	defer cancel()
	hs, err := c.hosts(ctx)
	if err != nil {
		return false
	}
	for _, h := range hs {
		if h.ID == hostID {
			return true
		}
	}
	return false
}

// ActionFamily returns the family of an allowlisted action.
func (opsAssistantCatalog) ActionFamily(actionID string) (string, bool) {
	return opsfacts.Families(actionID)
}

// CurrentDigest returns the digest of the eligible group ref. Only fix notes
// have groups; any other kind reports false, which marks the card outdated.
func (c opsAssistantCatalog) CurrentDigest(kind opsnotes.Kind, ref string) (string, bool) {
	if kind != opsnotes.KindFix {
		return "", false
	}
	ctx, cancel := context.WithTimeout(context.Background(), opsAssistantCallTimeout)
	defer cancel()
	gs, err := c.groups(ctx)
	if err != nil {
		return "", false
	}
	for _, g := range gs {
		if g.Key == ref {
			return g.Digest, true
		}
	}
	return "", false
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
		catalog:  opsAssistantCatalog{hosts: hosts, groups: groups},
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

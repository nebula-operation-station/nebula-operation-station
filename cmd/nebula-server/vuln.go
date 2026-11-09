// SPDX-License-Identifier: AGPL-3.0-or-later

// Vulnerability management wiring (ADR 0011; ticket vu14w): the findings
// store on server.db, the vulnerability agent API behind the vuln token
// (scopes and source-address allowlist from serverconfig), the store's
// sweeps, the D9 notifications through internal/notify, the findings pages
// and the admin-only, audited export.

package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/notify"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverconfig"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnnotify"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnprio"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnstore"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/api"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/auth"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
)

// Timing and limits of the vulnerability wiring.
const (
	// vulnSweepInterval is how often vulnstore.Prune runs (it finishes
	// runs left completing, aborts runs past vulnstore.MaxRunDuration and
	// applies the retention). vulnstore asks for an hour or less.
	vulnSweepInterval = 15 * time.Minute
	// vulnSweepTimeout bounds one sweep, and the startup
	// ResumeCompleting; a sweep that runs out of time leaves the run
	// completing for the next one.
	vulnSweepTimeout = 10 * time.Minute
	// vulnNotifyInterval is how often feed and Hermes staleness are
	// checked and vulnnotify.Flush sends the digest and retries.
	vulnNotifyInterval = 5 * time.Minute
	// vulnNotifyTimeout bounds one notification tick or event.
	vulnNotifyTimeout = 2 * time.Minute
	// vulnShutdownFlushTimeout bounds the last Flush on shutdown.
	vulnShutdownFlushTimeout = 10 * time.Second
	// vulnEventQueue bounds the run events waiting for the notifier; a
	// full queue drops the event (logged), the next batch or complete of
	// the run raises its findings again.
	vulnEventQueue = 64
	// maxVulnAlertScan bounds the findings one run event hands to the
	// notifier (the notifier itself sends at most vulnnotify.MaxPerHour).
	maxVulnAlertScan = 10_000
	// vulnInventoryBucket is the lifetime of one inventory snapshot ID.
	vulnInventoryBucket = time.Hour
	// vulnExportTimeout bounds reading the findings for one export.
	vulnExportTimeout = 30 * time.Second
	// vulnStatusTimeout bounds the executor status read of the admin check.
	vulnStatusTimeout = 5 * time.Second
)

// vulnSources is NOS's fixed feed source list (ADR 0011 D4, D5): it ships
// with NOS and never comes from the API or Hermes. Daily feeds may be 72 h
// old, vendor CSAF 30 days (Q5).
var vulnSources = []vulnstore.Source{
	{ID: "debian-tracker", MaxAge: 72 * time.Hour},
	{ID: "dsa", MaxAge: 72 * time.Hour},
	{ID: "dla", MaxAge: 72 * time.Hour},
	{ID: "osv", MaxAge: 72 * time.Hour},
	{ID: "nvd", MaxAge: 72 * time.Hour},
	{ID: "kev", MaxAge: 72 * time.Hour},
	{ID: "epss", MaxAge: 72 * time.Hour},
	{ID: "cisco-csaf", MaxAge: 30 * 24 * time.Hour},
	{ID: "paloalto-csaf", MaxAge: 30 * 24 * time.Hour},
}

func vulnSourceIDs() []string {
	ids := make([]string, len(vulnSources))
	for i, s := range vulnSources {
		ids[i] = s.ID
	}
	return ids
}

// vulnTier computes the D7 tier (vu-prio-v1) from the finding's scores.
// Exposure and host criticality are not wired yet, so the formula's
// defaults apply: exposure unknown (0.7, never "internal") and
// criticality unset (HIGH). Invalid scores give TierUnknown.
func vulnTier(_ vulnstore.Subject, r vulnfinding.Record) vulnstore.Tier {
	res, err := vulnprio.Compute(vulnprio.Input{Scores: r.Scores})
	if err != nil {
		return vulnstore.TierUnknown
	}
	switch res.Tier {
	case vulnprio.TierLow:
		return vulnstore.TierLow
	case vulnprio.TierMedium:
		return vulnstore.TierMedium
	case vulnprio.TierHigh:
		return vulnstore.TierHigh
	case vulnprio.TierCritical:
		return vulnstore.TierCritical
	}
	return vulnstore.TierUnknown
}

// errVulnNotCheckable: NOS keeps no package inventory the classifier
// could compare against yet.
var errVulnNotCheckable = errors.New("no NOS package inventory to classify against")

// vulnClassifier fails closed: until NOS stores the package inventory
// (package.list_installed, image.packages) every requested run closure is
// held for an admin (vulnstore.HoldClassifyFailed), never closed on
// Hermes' word alone.
type vulnClassifier struct{}

func (vulnClassifier) Classify(context.Context, vulnstore.Finding) (vulnstore.Class, error) {
	return 0, errVulnNotCheckable
}

// vulnInventory serves the D3 inventory export. NOS does not store the
// parsed package lists yet, so every snapshot is empty: Hermes can cover
// no subject, so no run requests a closure. The snapshot ID names its
// hour, so a snapshot is immutable for its ID, the generation only rises,
// and a run start within vulnstore.MaxInventoryAge finds it again.
type vulnInventory struct {
	now func() time.Time
}

const vulnSnapshotPrefix = "nos-empty-"

func (v vulnInventory) VulnSnapshot(_ context.Context, id string) (api.VulnSnapshot, error) {
	bucket := v.now().UTC().Truncate(vulnInventoryBucket)
	if id != "" {
		n, err := strconv.ParseInt(strings.TrimPrefix(id, vulnSnapshotPrefix), 10, 64)
		if err != nil || !strings.HasPrefix(id, vulnSnapshotPrefix) || n <= 0 {
			return api.VulnSnapshot{}, api.ErrVulnSnapshotGone
		}
		at := time.Unix(n, 0).UTC()
		if at.After(bucket) || bucket.Sub(at) > vulnstore.MaxInventoryAge || !at.Equal(at.Truncate(vulnInventoryBucket)) {
			return api.VulnSnapshot{}, api.ErrVulnSnapshotGone
		}
		bucket = at
	}
	return api.VulnSnapshot{ID: vulnSnapshotPrefix + strconv.FormatInt(bucket.Unix(), 10),
		Generation: bucket.Unix() / int64(vulnInventoryBucket/time.Second), TakenAt: bucket}, nil
}

// vulnService holds the findings store and the notifier and runs the
// background work: run events, sweeps and notification ticks.
type vulnService struct {
	store    *vulnstore.Store
	notifier *vulnnotify.Notifier
	log      *slog.Logger
	events   chan func(context.Context)
	// swept, when set (tests only), is called after every sweep.
	swept func(vulnstore.PruneResult, error)
}

// newVulnService opens the findings store on db (server.db) and the
// notifier on sink (the internal/notify providers).
func newVulnService(db *sql.DB, sink vulnnotify.Sink, log *slog.Logger, now func() time.Time) (*vulnService, error) {
	if now == nil {
		now = time.Now
	}
	st, err := vulnstore.New(db, vulnstore.Config{Sources: vulnSources, Tier: vulnTier, Classifier: vulnClassifier{}, Now: now})
	if err != nil {
		return nil, fmt.Errorf("vulnerability store: %w", err)
	}
	n, err := vulnnotify.New(vulnnotify.Config{Sink: sink, Sources: vulnSourceIDs(), Now: now})
	if err != nil {
		return nil, fmt.Errorf("vulnerability notifications: %w", err)
	}
	return &vulnService{store: st, notifier: n, log: log, events: make(chan func(context.Context), vulnEventQueue)}, nil
}

// enqueue hands a notification event to runEvents without blocking the
// API request that produced it.
func (v *vulnService) enqueue(kind string, f func(context.Context)) {
	select {
	case v.events <- f:
	default:
		v.log.Warn("vulnerability notification queue full, event dropped", "event", kind)
	}
}

// runEvents delivers queued events, one at a time, each bounded by
// vulnNotifyTimeout, until ctx is done.
func (v *vulnService) runEvents(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case f := <-v.events:
			ectx, cancel := context.WithTimeout(ctx, vulnNotifyTimeout)
			f(ectx)
			cancel()
		}
	}
}

// runAlerts raises vuln.kev_new and vuln.critical_new for the open KEV or
// critical findings the run wrote.
func (v *vulnService) runAlerts(ctx context.Context, runID string) {
	fs, err := v.store.RunAlertFindings(ctx, runID, maxVulnAlertScan)
	if err != nil {
		v.log.Error("vulnerability alerts: read run findings", "error", err)
		return
	}
	v.notifier.Findings(ctx, fs)
}

// checkHermes raises vuln.hermes_stale when no run completed within the
// D6 threshold (and ends the episode after a complete).
func (v *vulnService) checkHermes(ctx context.Context) {
	last, err := v.store.LastComplete(ctx)
	if err != nil {
		v.log.Error("vulnerability notifications: last complete", "error", err)
		return
	}
	v.notifier.Hermes(ctx, last)
}

// checkFeeds raises vuln.feed_stale for listed sources past their maximum
// age (and ends the episode of sources fresh again).
func (v *vulnService) checkFeeds(ctx context.Context) {
	st, err := v.store.FeedStatuses(ctx)
	if err != nil {
		v.log.Error("vulnerability notifications: feed status", "error", err)
		return
	}
	in := make([]vulnnotify.FeedStatus, len(st))
	for i, s := range st {
		in[i] = vulnnotify.FeedStatus{SourceID: s.SourceID, Stale: s.Stale, Since: s.StaleSince}
	}
	v.notifier.Feeds(ctx, in)
}

// notifyTick is one bounded notification round: feed and Hermes
// staleness, then Flush (digest and retries, at most MaxPerHour messages).
func (v *vulnService) notifyTick(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, vulnNotifyTimeout)
	defer cancel()
	v.checkFeeds(ctx)
	v.checkHermes(ctx)
	v.notifier.Flush(ctx)
}

// runNotify runs notifyTick every interval and a last Flush on shutdown,
// with its own short deadline, so the digest and queued retries are tried
// once more.
func (v *vulnService) runNotify(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), vulnShutdownFlushTimeout)
			v.notifier.Flush(fctx)
			cancel()
			return
		case <-t.C:
			v.notifyTick(ctx)
		}
	}
}

// runSweeps calls vulnstore.ResumeCompleting once at startup and then
// vulnstore.Prune every interval (which runs ResumeCompleting and
// AbortExpiredRuns before the retention), each bounded by
// vulnSweepTimeout. Errors are logged and retried at the next interval.
func (v *vulnService) runSweeps(ctx context.Context, interval time.Duration) {
	sctx, cancel := context.WithTimeout(ctx, vulnSweepTimeout)
	n, err := v.store.ResumeCompleting(sctx)
	cancel()
	if err != nil {
		v.log.Error("vulnerability store: resume completing runs", "error", err, "resumed", n)
	} else if n > 0 {
		v.log.Info("vulnerability store: resumed completing runs", "resumed", n)
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		sctx, cancel := context.WithTimeout(ctx, vulnSweepTimeout)
		res, err := v.store.Prune(sctx)
		cancel()
		attrs := []any{"resumed", res.ResumedRuns, "aborted", res.AbortedRuns, "deleted_findings", res.DeletedFindings,
			"cleared_assessment", res.ClearedAssessment, "deleted_runs", res.DeletedRuns, "deleted_history", res.DeletedHistory}
		if err != nil {
			v.log.Error("vulnerability store: sweep", append(attrs, "error", err)...)
		} else if res != (vulnstore.PruneResult{}) {
			v.log.Info("vulnerability store: sweep", attrs...)
		}
		if v.swept != nil {
			v.swept(res, err)
		}
	}
}

// vulnAPIStore is the store behind the agent API: it passes every call to
// vulnstore and queues the D9 events of the calls that succeeded.
type vulnAPIStore struct{ v *vulnService }

func (s vulnAPIStore) StartRun(ctx context.Context, req vulnstore.StartRequest) (vulnstore.Run, error) {
	r, err := s.v.store.StartRun(ctx, req)
	if err == nil {
		s.v.enqueue("run", func(ctx context.Context) { s.v.notifier.Run(ctx, r) })
	}
	return r, err
}

func (s vulnAPIStore) SubmitBatch(ctx context.Context, runID string, b vulnstore.Batch) (vulnstore.BatchResult, error) {
	res, err := s.v.store.SubmitBatch(ctx, runID, b)
	if err == nil && !res.Duplicate {
		s.v.enqueue("batch", func(ctx context.Context) { s.v.runAlerts(ctx, runID) })
	}
	return res, err
}

func (s vulnAPIStore) RejectBatch(ctx context.Context, runID string, seq int64, sum [32]byte) error {
	return s.v.store.RejectBatch(ctx, runID, seq, sum)
}

func (s vulnAPIStore) completed(runID string) {
	s.v.enqueue("complete", func(ctx context.Context) {
		s.v.runAlerts(ctx, runID)
		s.v.checkHermes(ctx)
	})
}

func (s vulnAPIStore) Complete(ctx context.Context, runID string) (vulnstore.Completion, error) {
	c, err := s.v.store.Complete(ctx, runID)
	if err == nil {
		s.completed(runID)
	}
	return c, err
}

func (s vulnAPIStore) CompletionOf(ctx context.Context, runID, tokenID string) (vulnstore.Completion, error) {
	return s.v.store.CompletionOf(ctx, runID, tokenID)
}

func (s vulnAPIStore) ResumeComplete(ctx context.Context, runID, tokenID string) (vulnstore.Completion, error) {
	c, err := s.v.store.ResumeComplete(ctx, runID, tokenID)
	if err == nil {
		s.completed(runID)
	}
	return c, err
}

// newVulnAPI returns the agent API handler when the configuration has a
// vuln token, nil otherwise. api.NewVuln takes the token, its scopes and
// its source-address allowlist from the configuration.
func newVulnAPI(cfg serverconfig.APIConfig, v *vulnService, inv api.VulnInventory, log *slog.Logger) (http.Handler, error) {
	if _, ok := cfg.VulnToken(); !ok {
		return nil, nil
	}
	h, err := api.NewVuln(api.VulnOptions{Tokens: cfg.Tokens, Inventory: inv,
		Store: vulnAPIStore{v: v}, Sources: vulnSources, Log: log})
	if err != nil {
		return nil, err
	}
	return h, nil
}

// vulnAdmin reports whether the request's session holds the executor's
// privileged session, the admin rule used for every admin-only page. Any
// error counts as no.
func vulnAdmin(status ui.StatusProvider) func(ctx context.Context) bool {
	return func(ctx context.Context) bool {
		if status == nil {
			return false
		}
		sctx, cancel := context.WithTimeout(ctx, vulnStatusTimeout)
		defer cancel()
		st, err := status.GetStatus(sctx, &pb.GetStatusRequest{})
		if err != nil {
			return false
		}
		return st.GetPrivilegedSessionActive() && auth.HoldsPrivilegedSession(ctx, st.GetPrivilegedSessionExpiryUnix())
	}
}

// errVulnDecisionsUnavailable: the executor has no RPC yet that binds a
// WebAuthn assertion to a vulnerability decision digest (Q4).
var errVulnDecisionsUnavailable = errors.New("vulnerability decisions need an executor-verified security key assertion, which this executor does not offer")

// vulnPages is the backend of the findings pages over the real store.
type vulnPages struct {
	v     *vulnService
	admin func(ctx context.Context) bool
}

func (p vulnPages) feeds(ctx context.Context) ([]ui.VulnFeedStatus, error) {
	st, err := p.v.store.FeedStatuses(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]ui.VulnFeedStatus, len(st))
	for i, s := range st {
		out[i] = ui.VulnFeedStatus{SourceID: s.SourceID, Listed: true, Stale: s.Stale, SnapshotDate: s.ContentDate,
			LastVerdict: s.LastVerdict, Probation: s.Probation, PreResetDate: s.PreResetDate, PreResetSeq: s.PreResetSeq}
	}
	return out, nil
}

func (p vulnPages) subject(ctx context.Context, s vulnstore.Subject) (ui.VulnSubjectStatus, error) {
	st, err := p.v.store.SubjectStatus(ctx, s)
	if err != nil {
		return ui.VulnSubjectStatus{}, err
	}
	return ui.VulnSubjectStatus{Subject: s, LastComplete: st.LastComplete}, nil
}

// VulnFindings reads the findings in scope with their current tier, the
// status of their subjects and the feeds.
func (p vulnPages) VulnFindings(ctx context.Context, q ui.VulnQuery) (ui.VulnPage, error) {
	limit := q.Limit
	if limit <= 0 || limit > ui.MaxVulnRows {
		limit = ui.MaxVulnRows
	}
	fs, trunc, err := p.v.store.List(ctx, vulnstore.ListQuery{VulnID: q.VulnID, Subject: q.Subject, Limit: limit})
	if err != nil {
		return ui.VulnPage{}, err
	}
	page := ui.VulnPage{Truncated: trunc, Rows: make([]ui.VulnRow, len(fs))}
	seen := map[vulnstore.Subject]bool{}
	if q.Subject != nil {
		seen[*q.Subject] = false
	}
	for i, f := range fs {
		page.Rows[i] = ui.VulnRow{Finding: f, Tier: vulnTier(f.Subject, f.Record)}
		if _, ok := seen[f.Subject]; !ok {
			seen[f.Subject] = false
		}
	}
	for s := range seen {
		st, err := p.subject(ctx, s)
		if err != nil {
			return ui.VulnPage{}, err
		}
		page.Subjects = append(page.Subjects, st)
	}
	if page.Feeds, err = p.feeds(ctx); err != nil {
		return ui.VulnPage{}, err
	}
	if page.LastComplete, err = p.v.store.LastComplete(ctx); err != nil {
		return ui.VulnPage{}, err
	}
	return page, nil
}

// VulnFinding reads one finding with its holds, subject and feeds.
func (p vulnPages) VulnFinding(ctx context.Context, key vulnfinding.Key) (ui.VulnFindingDetail, error) {
	f, err := p.v.store.Get(ctx, key)
	if err != nil {
		return ui.VulnFindingDetail{}, err
	}
	d := ui.VulnFindingDetail{Row: ui.VulnRow{Finding: f, Tier: vulnTier(f.Subject, f.Record)}}
	holds, err := p.v.store.Holds(ctx, key)
	if err != nil {
		return ui.VulnFindingDetail{}, err
	}
	for _, h := range holds {
		// NOS keeps no package inventory yet: no NOS version, never
		// shown as contradicted or confirmed by NOS.
		d.Holds = append(d.Holds, ui.VulnHold{Hold: h})
	}
	if d.Subject, err = p.subject(ctx, f.Subject); err != nil {
		return ui.VulnFindingDetail{}, err
	}
	if d.Feeds, err = p.feeds(ctx); err != nil {
		return ui.VulnFindingDetail{}, err
	}
	if d.LastComplete, err = p.v.store.LastComplete(ctx); err != nil {
		return ui.VulnFindingDetail{}, err
	}
	return d, nil
}

// VulnMarkResetCandidate returns the mark reset view of a listed source.
func (p vulnPages) VulnMarkResetCandidate(ctx context.Context, sourceID string) (vulnstore.MarkResetView, error) {
	return p.v.store.MarkResetCandidate(ctx, sourceID)
}

// VulnMaintainer reports whether the request holds the privileged session.
func (p vulnPages) VulnMaintainer(ctx context.Context, _ string) (bool, error) {
	return p.admin(ctx), nil
}

// BeginVulnDecision refuses: see errVulnDecisionsUnavailable.
func (p vulnPages) BeginVulnDecision(context.Context, string, ui.VulnDecision) (ui.VulnChallenge, error) {
	return ui.VulnChallenge{}, errVulnDecisionsUnavailable
}

// CommitVulnDecision refuses: see errVulnDecisionsUnavailable.
func (p vulnPages) CommitVulnDecision(context.Context, string, string, ui.VulnDecision, []byte) error {
	return errVulnDecisionsUnavailable
}

// vulnExportPath serves the admin export (ADR 0011 D9).
const vulnExportPath = "/vulnerabilities/export"

// vulnExport serves GET /vulnerabilities/export?format=csv|json: admin
// only, audited (vulnnotify.Export writes the audit entry before the
// first byte), streamed row by row, CSV cells formula-prefixed and no
// assessment text.
type vulnExport struct {
	v     *vulnService
	admin func(ctx context.Context) bool
	audit vulnnotify.Auditor
	log   *slog.Logger
}

// lazyHeaders sets the download headers on the first write, so a refused
// export (audit failure) still answers with an error status.
type lazyHeaders struct {
	w       http.ResponseWriter
	ctype   string
	name    string
	started bool
}

func (l *lazyHeaders) Write(b []byte) (int, error) {
	if !l.started {
		l.started = true
		h := l.w.Header()
		h.Set("Content-Type", l.ctype)
		h.Set("Content-Disposition", `attachment; filename="`+l.name+`"`)
		h.Set("Cache-Control", "no-store")
		h.Set("X-Content-Type-Options", "nosniff")
		l.w.WriteHeader(http.StatusOK)
	}
	return l.w.Write(b)
}

func (e vulnExport) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	user := webUserName(r)
	format := r.URL.Query().Get("format")
	if format == "" {
		format = vulnnotify.FormatCSV
	}
	if format != vulnnotify.FormatCSV && format != vulnnotify.FormatJSON {
		http.Error(w, "format must be csv or json", http.StatusBadRequest)
		return
	}
	if !e.admin(r.Context()) {
		e.log.Warn("audit", "kind", "vuln_export_refused", "user", user, "reason", "not_admin")
		http.Error(w, "only an admin with an open privileged session can export findings", http.StatusForbidden)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), vulnExportTimeout)
	fs, trunc, err := e.v.store.List(ctx, vulnstore.ListQuery{Limit: vulnnotify.MaxExportFindings})
	cancel()
	if err != nil {
		e.log.Error("vulnerability export: read findings", "error", err)
		http.Error(w, "findings unavailable", http.StatusServiceUnavailable)
		return
	}
	if trunc {
		e.log.Warn("audit", "kind", "vuln_export_refused", "user", user, "reason", "too_many_findings")
		http.Error(w, "more findings than one export may hold", http.StatusRequestEntityTooLarge)
		return
	}
	lw := &lazyHeaders{w: w, ctype: "text/csv; charset=utf-8", name: "nos-vuln-findings.csv"}
	if format == vulnnotify.FormatJSON {
		lw.ctype, lw.name = "application/json", "nos-vuln-findings.json"
	}
	err = vulnnotify.Export(r.Context(), e.audit, lw, vulnnotify.ExportRequest{Format: format, Actor: user, Findings: fs})
	if err != nil {
		e.log.Error("vulnerability export", "error", err)
		if !lw.started {
			http.Error(w, "export failed", http.StatusInternalServerError)
		}
	}
}

// webUserName is the session's user name; "unknown" outside the login
// chain.
func webUserName(r *http.Request) string {
	if s, ok := auth.SessionFrom(r.Context()); ok {
		return s.UserName
	}
	return "unknown"
}

// notifySink adapts *notify.Notifier to vulnnotify.Sink (it already is
// one; the assertion keeps it so).
var _ vulnnotify.Sink = (*notify.Notifier)(nil)

// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/auditlog"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/actions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executor"
	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/opsconfig"
	"github.com/nebula-operation-station/nebula-operation-station/internal/opsfacts"
	"github.com/nebula-operation-station/nebula-operation-station/internal/opsnotes"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
)

// The Ops tab of the Assistant panel, the suggestion form and the Ops-Agent
// settings for the browser test (test/browser/opsagent.spec.js, ADR 0016
// D8, D9, D11, D12; AG-25).
//
// The notes are a fixed in-memory store with hostile model text. Several
// values could never pass the notes store's validation (markup, URLs,
// Markdown links, bidi controls): the pages must stay safe even if a value
// got past it, as for the vulnerabilities pages (vuln.go). Step and match
// lookups follow *opsnotes.Store: dismissed notes still count (D9).

// Hostile model texts of note 1 (the spec compares them byte for byte).
const (
	opsSummary    = `<script>window.__pwned='summary'</script><img src=x onerror="window.__pwned='summary-img'">Upgrade openssl now`
	opsUrgency    = "high \xe2\x80\xaeevil\xe2\x80\xac [now](https://evil.example/urgent)" // U+202E, U+202C
	opsWhyRestart = `<a href="javascript:window.__pwned='why'">restart</a> **bold** [docs](https://evil.example/docs) https://evil.example/plain`
	opsWhyRefresh = `Refresh lists first <iframe srcdoc="<script>parent.__pwned='iframe'</script>"></iframe>`
	opsMitigation = "Block port 443: `iptables -I INPUT -p tcp --dport 443 -j DROP` <button onclick=\"window.__pwned='mit'\">run</button>"
	opsMitigForm  = `<form action="https://evil.example/f" method="post"><input type="submit" value="apply"></form>`
	opsCitation   = `<svg onload="window.__pwned='cite'">`
	opsCiteMD     = `[handbook](javascript:window.__pwned='cite-md')`
	opsPackage    = `openssl<img src=x onerror="window.__pwned='pkg'">`
	opsSummaryTxt = "<b>Fleet</b> summary <script>window.__pwned='fleet'</script>"
)

// opsHarnessFamilies extends the suggestion allowlist for the harness only:
// no allowlisted action is LOW, but D9 must be shown for a LOW action, so
// package.refresh (trusted as LOW here, see trustOpsLowAction) is a
// suggestable action in this harness and nowhere else.
var opsHarnessFamilies = map[string]string{"package.refresh": "harness-refresh"}

// opsFamily returns the suggestion family of action.
func opsFamily(action string) (string, bool) {
	if f, ok := opsfacts.Families(action); ok {
		return f, true
	}
	f, ok := opsHarnessFamilies[action]
	return f, ok
}

// opsAdmin is the harness's admin rule for the Ops tab, the suggestion form
// and the Ops-Agent settings. The test hook /__ops/admin sets it, so one
// browser session can be admin and non-admin.
var opsAdmin atomic.Bool

func init() { opsAdmin.Store(true) }

// opsAdminHook serves /__ops/admin?on=0|1.
func opsAdminHook(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Query().Get("on") {
	case "0":
		opsAdmin.Store(false)
	case "1":
		opsAdmin.Store(true)
	default:
		http.Error(w, "on=0 or on=1", http.StatusBadRequest)
		return
	}
	fmt.Fprint(w, opsAdmin.Load())
}

func opsIsAdmin(context.Context, string) (bool, error) { return opsAdmin.Load(), nil }

// harnessOps is the in-memory notes store.
type harnessOps struct {
	inv *inventory.Store

	mu        sync.Mutex
	notes     []opsnotes.Note
	digests   map[string]string
	questions []opsnotes.Question
}

// newHarnessOps seeds three notes: a fix card with hostile text (1), a
// plain fix card whose findings changed (2, the one the spec dismisses)
// and a summary (3).
func newHarnessOps(inv *inventory.Store, now time.Time) (*harnessOps, error) {
	snap, err := json.Marshal(map[string]any{"package": opsPackage, "version": "3.0.15-1~deb12u1", "tier": "critical",
		"score": 9.8, "kev": true, "exposure": "internet"})
	if err != nil {
		return nil, fmt.Errorf("ops harness snapshot: %w", err)
	}
	snap2, err := json.Marshal(map[string]any{"package": "curl", "version": "7.88.1", "tier": "medium", "score": 5.3})
	if err != nil {
		return nil, fmt.Errorf("ops harness snapshot: %w", err)
	}
	return &harnessOps{
		inv:     inv,
		digests: map[string]string{"group:e2e-host:openssl": "sha256:current", "group:e2e-two:curl": "sha256:changed"},
		notes: []opsnotes.Note{
			{ID: 1, Kind: opsnotes.KindFix, Ref: "group:e2e-host:openssl", Digest: "sha256:current", Snapshot: string(snap),
				CreatedAt: now.Add(-time.Hour), Body: opsnotes.Body{
					Summary: opsSummary, Urgency: opsUrgency,
					Steps: []opsnotes.StepInput{
						{ActionID: "service.restart", HostID: "e2e-host", Why: opsWhyRestart},
						{ActionID: "package.refresh", HostID: "e2e-host", Why: opsWhyRefresh},
						// The host left the inventory: no button.
						{ActionID: "system.reboot", HostID: "e2e-gone", Why: "reboot the gone host"},
						// Not a catalog action: no button.
						{ActionID: "rm.everything", HostID: "e2e-host", Why: "not an action"},
					},
					Mitigations: []string{opsMitigation, opsMitigForm},
					Citations:   []string{opsCitation, opsCiteMD},
				}},
			{ID: 2, Kind: opsnotes.KindFix, Ref: "group:e2e-two:curl", Digest: "sha256:old", Snapshot: string(snap2),
				CreatedAt: now.Add(-2 * time.Hour), Body: opsnotes.Body{
					Summary: "Second suggestion: update curl",
					Steps:   []opsnotes.StepInput{{ActionID: "service.restart", HostID: "e2e-two", Why: "restart after the update"}},
				}},
			{ID: 3, Kind: opsnotes.KindSummary, Ref: "fleet", Digest: "sha256:fleet", CreatedAt: now.Add(-3 * time.Hour),
				Body: opsnotes.Body{Text: opsSummaryTxt}},
		},
	}, nil
}

// List returns the notes, newest (highest ID) first.
func (o *harnessOps) List(context.Context) ([]opsnotes.Note, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	out := append([]opsnotes.Note(nil), o.notes...)
	sort.Slice(out, func(i, j int) bool { return out[i].ID > out[j].ID })
	return out, nil
}

// Get returns one note, dismissed or not.
func (o *harnessOps) Get(_ context.Context, id int64) (opsnotes.Note, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	for _, n := range o.notes {
		if n.ID == id {
			return n, nil
		}
	}
	return opsnotes.Note{}, fmt.Errorf("note %d: %w", id, opsnotes.ErrNotFound)
}

// Dismiss hides a note and changes nothing else.
func (o *harnessOps) Dismiss(_ context.Context, id int64) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	for i := range o.notes {
		if o.notes[i].ID == id {
			o.notes[i].Dismissed = true
			return nil
		}
	}
	return fmt.Errorf("note %d: %w", id, opsnotes.ErrNotFound)
}

// Step returns step index (from 1) of a fix note whose action is
// suggestable, like the steps table of *opsnotes.Store.
func (o *harnessOps) Step(_ context.Context, noteID int64, index int) (opsnotes.Step, bool, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	for _, n := range o.notes {
		if n.ID != noteID || n.Kind != opsnotes.KindFix || index < 1 || index > len(n.Body.Steps) {
			continue
		}
		in := n.Body.Steps[index-1]
		fam, ok := opsFamily(in.ActionID)
		if !ok {
			return opsnotes.Step{}, false, nil
		}
		return opsnotes.Step{NoteID: n.ID, Index: index, ActionID: in.ActionID, HostID: in.HostID, Family: fam, Why: in.Why}, true, nil
	}
	return opsnotes.Step{}, false, nil
}

// match returns the newest fix note with a step of family on hostID.
func (o *harnessOps) match(family, hostID string) (int64, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	var best int64
	for _, n := range o.notes {
		if n.Kind != opsnotes.KindFix {
			continue
		}
		for _, s := range n.Body.Steps {
			if f, ok := opsFamily(s.ActionID); ok && f == family && s.HostID == hostID && n.ID > best {
				best = n.ID
			}
		}
	}
	return best, best > 0
}

// AskQuestion stores a question; nothing answers it in the harness.
func (o *harnessOps) AskQuestion(_ context.Context, user, text string) (opsnotes.Question, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if len(o.questions) >= opsnotes.MaxOpenQuestions {
		return opsnotes.Question{}, opsnotes.ErrQuestionsFull
	}
	q := opsnotes.Question{ID: int64(len(o.questions) + 1), User: user, Text: text, Digest: opsnotes.QuestionDigest(text),
		State: opsnotes.QuestionOpen, CreatedAt: time.Now()}
	o.questions = append(o.questions, q)
	return q, nil
}

// ListQuestions returns the questions of user, newest first.
func (o *harnessOps) ListQuestions(_ context.Context, user string) ([]opsnotes.Question, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	var out []opsnotes.Question
	for i := len(o.questions) - 1; i >= 0; i-- {
		if o.questions[i].User == user {
			out = append(out, o.questions[i])
		}
	}
	return out, nil
}

// status is the agent status line: on, last run an hour ago.
func (o *harnessOps) status(context.Context) (ui.AssistantOpsStatus, error) {
	return ui.AssistantOpsStatus{Enabled: true, LastRun: time.Now().Add(-time.Hour)}, nil
}

// harnessOpsCatalog checks steps against the inventory and the catalog.
type harnessOpsCatalog struct{ o *harnessOps }

func (c harnessOpsCatalog) HostExists(hostID string) bool {
	_, err := c.o.inv.Get(context.Background(), hostID)
	return err == nil
}

func (harnessOpsCatalog) ActionFamily(actionID string) (string, bool) {
	if _, ok := actions.Lookup(actionID); !ok {
		return "", false
	}
	return opsFamily(actionID)
}

func (c harnessOpsCatalog) CurrentDigest(_ opsnotes.Kind, ref string) (string, bool) {
	d, ok := c.o.digests[ref]
	return d, ok
}

// harnessOpsIndex is the executions service's suggestion index over the
// harness notes (cmd/nebula-server's opsSuggestions over *opsnotes.Store).
type harnessOpsIndex struct{ o *harnessOps }

var _ executions.SuggestionIndex = harnessOpsIndex{}

func (x harnessOpsIndex) Step(ref string) (action, family, hostID string, ok bool) {
	id, idx, ok := ui.ParseSuggestionRef(ref)
	if !ok {
		return "", "", "", false
	}
	st, found, err := x.o.Step(context.Background(), id, idx)
	if err != nil || !found {
		return "", "", "", false
	}
	return st.ActionID, st.Family, st.HostID, true
}

func (x harnessOpsIndex) Match(family, hostID string) (string, bool) {
	id, ok := x.o.match(family, hostID)
	if !ok {
		return "", false
	}
	return strconv.FormatInt(id, 10), true
}

func (harnessOpsIndex) Family(actionID string) (string, bool) { return opsFamily(actionID) }

// trustOpsLowAction trusts package.refresh as LOW on the executor, so the
// spec can open a LOW action from a suggestion (e2e-host is recorded LOW).
func trustOpsLowAction(ctx context.Context, svc *executor.Service) error {
	a, ok := actions.Lookup("package.refresh")
	if !ok {
		return errors.New("ops harness: no action package.refresh")
	}
	_, err := svc.TrustArtifact(ctx, &pb.TrustArtifactRequest{ActionId: a.ID, ModuleVersion: a.Version,
		RiskClass: pb.RiskClass_RISK_CLASS_LOW, Artifact: a.Script, Label: "browser test (ops agent)", ExpectedSha256: a.SHA256()})
	if err != nil {
		return fmt.Errorf("ops harness: trust package.refresh: %w", err)
	}
	return nil
}

// harnessOpsAgent is the Ops-Agent settings backend: the real settings
// store and audit log, challenges from the executor's BeginLogin and the
// assertion checked by its FinishLogin, like cmd/nebula-server's
// opsAgentSettings (without the notifier).
type harnessOpsAgent struct {
	store *opsconfig.Store
	audit *auditlog.Store
	exec  direct

	mu      sync.Mutex
	pending map[string]opsAgentPending
}

type opsAgentPending struct {
	user   string
	digest [sha256.Size]byte
}

var _ ui.OpsAgentSettings = (*harnessOpsAgent)(nil)

func newHarnessOpsAgent(db *sql.DB, audit *auditlog.Store, exec direct) (*harnessOpsAgent, error) {
	st, err := opsconfig.NewStore(db, nil)
	if err != nil {
		return nil, fmt.Errorf("ops harness settings: %w", err)
	}
	return &harnessOpsAgent{store: st, audit: audit, exec: exec, pending: map[string]opsAgentPending{}}, nil
}

func (s *harnessOpsAgent) OpsAgentConfig(ctx context.Context) (opsconfig.Row, error) {
	return s.store.Get(ctx)
}

func (*harnessOpsAgent) OpsAgentCorePrompt() string { return "browser test core prompt" }

func (*harnessOpsAgent) OpsAgentMaintainer(ctx context.Context, user string) (bool, error) {
	return opsIsAdmin(ctx, user)
}

func (s *harnessOpsAgent) BeginOpsAgentChange(ctx context.Context, user string, c ui.OpsAgentChange) (ui.VulnChallenge, error) {
	if !opsAdmin.Load() {
		return ui.VulnChallenge{}, ui.ErrOpsAgentNotMaintainer
	}
	if err := c.Settings.Validate(); err != nil {
		return ui.VulnChallenge{}, fmt.Errorf("begin ops agent change: %w", err)
	}
	digest, err := c.Digest()
	if err != nil {
		return ui.VulnChallenge{}, fmt.Errorf("begin ops agent change: %w", err)
	}
	b, err := s.exec.BeginLogin(ctx, &pb.BeginLoginRequest{})
	if err != nil {
		return ui.VulnChallenge{}, fmt.Errorf("begin ops agent change: %w", err)
	}
	s.mu.Lock()
	s.pending[b.GetLoginId()] = opsAgentPending{user: user, digest: digest}
	s.mu.Unlock()
	return ui.VulnChallenge{ID: b.GetLoginId(), Options: b.GetRequestOptionsJson()}, nil
}

func (s *harnessOpsAgent) CommitOpsAgentChange(ctx context.Context, user, challengeID string, c ui.OpsAgentChange, assertion []byte) error {
	if !opsAdmin.Load() {
		return ui.ErrOpsAgentNotMaintainer
	}
	digest, err := c.Digest()
	if err != nil {
		return fmt.Errorf("commit ops agent change: %w", err)
	}
	s.mu.Lock()
	p, ok := s.pending[challengeID]
	delete(s.pending, challengeID)
	s.mu.Unlock()
	if !ok || p.user != user || p.digest != digest {
		return ui.ErrOpsAgentAssertionRefused
	}
	res, err := s.exec.FinishLogin(ctx, &pb.FinishLoginRequest{LoginId: challengeID, AssertionJson: assertion})
	if err != nil || res.GetUserName() != user {
		return ui.ErrOpsAgentAssertionRefused
	}
	if _, err := s.store.Save(ctx, user, c.Settings, c.BaseVersion, s.audit); err != nil {
		return fmt.Errorf("commit ops agent change: %w", err)
	}
	return nil
}

// wireOps adds the Ops tab, the suggestion form, the suggestion index and
// the Ops-Agent settings to the harness.
func wireOps(ctx context.Context, svc *executor.Service, ops *executions.Service, inv *inventory.Store, sdb *sql.DB,
	audit *auditlog.Store, opts *ui.Options) error {
	if err := trustOpsLowAction(ctx, svc); err != nil {
		return err
	}
	notes, err := newHarnessOps(inv, time.Now())
	if err != nil {
		return err
	}
	ops.SetSuggestionIndex(harnessOpsIndex{o: notes})
	opts.AssistantOps = &ui.AssistantOps{Store: notes, IsAdmin: opsIsAdmin, Catalog: harnessOpsCatalog{o: notes}, Status: notes.status}
	opts.OperationSuggestions = &ui.OperationSuggestions{Store: notes, IsAdmin: opsIsAdmin}
	settings, err := newHarnessOpsAgent(sdb, audit, direct{svc})
	if err != nil {
		return err
	}
	opts.OpsAgent = settings
	return nil
}

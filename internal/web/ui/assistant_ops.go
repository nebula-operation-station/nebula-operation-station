// SPDX-License-Identifier: AGPL-3.0-or-later

package ui

// The Ops tab of the Assistant panel (ADR 0016 D8, D11). Admins only: every
// route here answers 404 to anyone else, and the tab is absent from the
// markup for them. This file reads the notes store; the Help backend
// (assistant.go, help.go) must never import it.
//
// Rendering rules (ADR 0016 D8):
//   - "What" comes from the facts snapshot that NOS wrote, not from model text.
//   - Model text (summary, urgency, step reasons, mitigations, citations
//     labels) is rendered by html/template as escaped text, under the
//     LLM label. It never becomes a link.
//   - A step button is a plain GET link to the normal NOS form with
//     suggestion=<note>.<step>; the form is never submitted from here.
//   - The only state change on this tab is the dismiss POST.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/opsnotes"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/auth"
)

// assistantContainerFamily is the catalog family of container updates. A
// step of this family opens the container update page of its host; every
// other family opens the normal operation form.
const assistantContainerFamily = "container-update"

// AssistantOpsStore is the notes store the Ops tab reads and dismisses
// from; *opsnotes.Store implements it.
type AssistantOpsStore interface {
	// List returns all stored notes, newest first.
	List(ctx context.Context) ([]opsnotes.Note, error)
	// Get returns one stored note; opsnotes.ErrNotFound when missing.
	Get(ctx context.Context, id int64) (opsnotes.Note, error)
	// Dismiss hides a note from the cards and changes nothing else.
	Dismiss(ctx context.Context, id int64) error
	// Step returns step index of note noteID, validated at storage time.
	Step(ctx context.Context, noteID int64, index int) (opsnotes.Step, bool, error)
	// AskQuestion stores a question of user (ADR 0016 D11).
	AskQuestion(ctx context.Context, user, text string) (opsnotes.Question, error)
	// ListQuestions returns the questions of user, newest first.
	ListQuestions(ctx context.Context, user string) ([]opsnotes.Question, error)
}

// AssistantOpsCatalog is the server's current view a card is checked
// against. A nil catalog shows no step buttons and never marks a card
// outdated.
type AssistantOpsCatalog interface {
	// HostExists reports whether the managed host exists.
	HostExists(hostID string) bool
	// ActionFamily returns the family of a catalog action, false when the
	// action is not in the catalog.
	ActionFamily(actionID string) (string, bool)
	// CurrentDigest returns the current input digest of ref.
	CurrentDigest(kind opsnotes.Kind, ref string) (string, bool)
}

// AssistantOpsStatus is the agent's state as the Ops tab shows it.
type AssistantOpsStatus struct {
	// Enabled is false when the agent is switched off.
	Enabled bool
	// LastRun is the time of the last agent run; zero when none.
	LastRun time.Time
	// Rejections are the short reasons the last run refused output.
	Rejections []string
}

// AssistantOps configures the Ops tab. Nil in Options disables it: every
// Ops route then answers 404 and the tab is not rendered.
type AssistantOps struct {
	// Store is the notes store. Required.
	Store AssistantOpsStore
	// IsAdmin is the admin role check. Required; an error denies.
	IsAdmin func(ctx context.Context, user string) (bool, error)
	// Catalog checks steps and digests. Nil shows no step buttons.
	Catalog AssistantOpsCatalog
	// Status reads the agent status. Nil shows no agent status.
	Status func(ctx context.Context) (AssistantOpsStatus, error)
	// User returns the logged-in user of a request. Nil uses the session
	// of the auth middleware.
	User func(r *http.Request) (string, bool)
	// Touch wakes the ops agent after a question was stored (the trigger
	// path of ADR 0016 D3). Nil does nothing; the agent then runs on its
	// timer. A returned error is logged, never shown with question text.
	Touch func() error
}

// user returns the logged-in user of r.
func (o *AssistantOps) user(r *http.Request) (string, bool) {
	if o.User != nil {
		return o.User(r)
	}
	s, ok := auth.SessionFrom(r.Context())
	if !ok || s.UserName == "" {
		return "", false
	}
	return s.UserName, true
}

// assistantOpsView is the Ops tab body.
type assistantOpsView struct {
	// Status is the agent status line.
	Status assistantStatusView
	// Summary is the newest summary text, empty when there is none.
	Summary string
	// Cards are the open fix cards, most urgent first.
	Cards []assistantCard
	// Questions are the admin's own questions and the question form.
	Questions assistantQuestionsView
}

// assistantStatusView is what the status line shows.
type assistantStatusView struct {
	// Shown is false when no status is configured.
	Shown bool
	// Off: the agent is switched off.
	Off bool
	// LastRun is the formatted time of the last run; empty when none.
	LastRun    string
	Rejections []string
}

// assistantCard is one fix note as a card.
type assistantCard struct {
	ID        int64
	Created   string
	Facts     []assistantFact
	Summary   string
	Urgency   string
	Steps     []assistantStep
	Mitigate  []string
	Citations []assistantCitation
	// Outdated: the findings of the group changed after the note was made.
	Outdated bool
	// ReadOnly is "dismissed" or "superseded" for a note the admin hid or
	// that a newer note replaced: the card shows its content with no step
	// buttons and no dismiss form. Empty for a live card.
	ReadOnly  string
	DetailURL string
	tierRank  int
	score     float64
}

// assistantFact is one line of the "What" block.
type assistantFact struct {
	Label string
	Value string
}

// assistantStep is one ordered step. Button is false when the step has
// no catalog action or no host on this server: then it is shown as text.
type assistantStep struct {
	Index       int
	Action      string
	Host        string
	Why         string
	Button      bool
	ButtonLabel string
	Href        string
}

// assistantCitation is one citation; URL is empty when it does not map to
// a handbook section and is then shown as text.
type assistantCitation struct {
	Label string
	URL   string
}

// assistantSnapshot is the facts snapshot NOS stores with a fix note.
// Only these keys are read; the snapshot is NOS-written, never model text.
type assistantSnapshot struct {
	Package  string  `json:"package"`
	Version  string  `json:"version"`
	Tier     string  `json:"tier"`
	Score    float64 `json:"score"`
	KEV      bool    `json:"kev"`
	Exposure string  `json:"exposure"`
}

// tierRanks orders tiers, most urgent first.
var tierRanks = map[string]int{"critical": 4, "high": 3, "medium": 2, "low": 1}

// assistantOpsDenied answers 404 unless the request may use the Ops tab.
func (h *Handler) assistantOpsDenied(w http.ResponseWriter, r *http.Request) bool {
	if h.assistantOpsAllowed(r) {
		return false
	}
	http.NotFound(w, r)
	return true
}

// handleAssistantOps renders the Ops tab body for an admin.
func (h *Handler) handleAssistantOps(w http.ResponseWriter, r *http.Request) {
	if !helpMethodOK(w, r) || h.assistantOpsDenied(w, r) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), assistantCallTimeout)
	defer cancel()
	notes, err := h.assistantOps.Store.List(ctx)
	if err != nil {
		h.log.Error("assistant ops: list notes", "error", err)
		http.Error(w, "assistant unavailable", http.StatusInternalServerError)
		return
	}
	view := h.assistantOpsBody(ctx, r, notes)
	writeAssistantPanel(w, r, h.log, h.assistantPageData, &assistantPanelView{Tabs: assistantTabs(assistantTabOps, true), Ops: view})
}

// assistantOpsBody builds the Ops tab from the stored notes. It reads the
// status and the catalog of the request; no note is written.
func (h *Handler) assistantOpsBody(ctx context.Context, r *http.Request, notes []opsnotes.Note) *assistantOpsView {
	o := h.assistantOps
	view := &assistantOpsView{}
	if o.Status != nil {
		st, err := o.Status(ctx)
		if err != nil {
			h.log.Error("assistant ops: agent status", "error", err)
		} else {
			view.Status = assistantStatusView{Shown: true, Off: !st.Enabled, Rejections: st.Rejections}
			if !st.LastRun.IsZero() {
				view.Status.LastRun = st.LastRun.UTC().Format("2006-01-02 15:04 UTC")
			}
		}
	}
	if user, ok := o.user(r); ok {
		qv, err := h.assistantQuestionsFor(ctx, user, "")
		if err != nil {
			h.log.Error("assistant ops: list questions", "error", err)
		} else {
			view.Questions = qv
		}
	}
	for _, n := range notes {
		if n.Dismissed || n.Superseded {
			continue
		}
		switch n.Kind {
		case opsnotes.KindSummary:
			if view.Summary == "" {
				view.Summary = n.Body.Text
			}
		case opsnotes.KindFix:
			view.Cards = append(view.Cards, h.assistantCardFor(ctx, n))
		}
	}
	sort.SliceStable(view.Cards, func(i, j int) bool {
		a, b := view.Cards[i], view.Cards[j]
		if a.tierRank != b.tierRank {
			return a.tierRank > b.tierRank
		}
		if a.score != b.score {
			return a.score > b.score
		}
		return a.ID > b.ID
	})
	return view
}

// assistantCardFor builds the card of one fix note.
func (h *Handler) assistantCardFor(ctx context.Context, n opsnotes.Note) assistantCard {
	c := assistantCard{
		ID:        n.ID,
		Created:   n.CreatedAt.UTC().Format("2006-01-02 15:04 UTC"),
		Summary:   n.Body.Summary,
		Urgency:   n.Body.Urgency,
		Mitigate:  n.Body.Mitigations,
		DetailURL: fmt.Sprintf("/assistant/ops/notes/%d", n.ID),
	}
	var f assistantSnapshot
	if err := json.Unmarshal([]byte(n.Snapshot), &f); err != nil {
		h.log.Debug("assistant ops: snapshot", "note", n.ID, "error", err)
	}
	c.tierRank = tierRanks[f.Tier]
	c.score = f.Score
	c.Facts = []assistantFact{
		{"Package", f.Package},
		{"Version", f.Version},
		{"Tier", f.Tier},
		{"Score", strconv.FormatFloat(f.Score, 'f', -1, 64)},
		{"KEV", yesNo(f.KEV)},
		{"Exposure", f.Exposure},
	}
	switch {
	case n.Dismissed:
		c.ReadOnly = "dismissed"
	case n.Superseded:
		c.ReadOnly = "superseded"
	}
	if cat := h.assistantOps.Catalog; cat != nil {
		cur, ok := cat.CurrentDigest(opsnotes.KindFix, n.Ref)
		c.Outdated = !ok || cur != n.Digest
	}
	for i, in := range n.Body.Steps {
		idx := i + 1
		st := assistantStep{Index: idx, Action: in.ActionID, Host: in.HostID, Why: in.Why}
		if c.ReadOnly == "" {
			st.Href, st.ButtonLabel, st.Button = h.assistantStepLink(n.ID, idx, in)
		}
		c.Steps = append(c.Steps, st)
	}
	c.Citations = h.assistantCitations(n.Body.Citations)
	return c
}

// assistantStepLink decides whether a step gets a button and builds its
// link. The link is NOS-built: suggestion=<note>.<step>, to the container
// update page for container updates and to the operation form otherwise.
// A step without a catalog action or without a host gets no button.
func (h *Handler) assistantStepLink(noteID int64, idx int, in opsnotes.StepInput) (string, string, bool) {
	cat := h.assistantOps.Catalog
	if cat == nil || !cat.HostExists(in.HostID) {
		return "", "", false
	}
	family, ok := cat.ActionFamily(in.ActionID)
	if !ok {
		return "", "", false
	}
	ref := fmt.Sprintf("%d.%d", noteID, idx)
	if family == assistantContainerFamily {
		return "/inventory/containers?host=" + url.QueryEscape(in.HostID) + "&suggestion=" + url.QueryEscape(ref), "Open container update", true
	}
	return "/operations/new?suggestion=" + url.QueryEscape(ref), "Open form", true
}

// assistantCitations maps citation IDs to handbook links. An ID is a chunk
// ID of the embedded index, "slug#anchor" or "slug#anchor#pN" (see
// helpBook.chunkURL); only IDs that name a heading of their page get a link,
// everything else is text.
func (h *Handler) assistantCitations(ids []string) []assistantCitation {
	if len(ids) == 0 {
		return nil
	}
	book, err := loadHelpBook()
	if err != nil {
		h.log.Error("assistant ops: handbook", "error", err)
	}
	out := make([]assistantCitation, 0, len(ids))
	for _, id := range ids {
		c := assistantCitation{Label: id}
		if book != nil {
			if u, ok := book.chunkURL(id); ok {
				c.URL = u
			}
		}
		out = append(out, c)
	}
	return out
}

// handleAssistantOpsNote renders one fix card as its own page.
func (h *Handler) handleAssistantOpsNote(w http.ResponseWriter, r *http.Request) {
	if !helpMethodOK(w, r) || h.assistantOpsDenied(w, r) {
		return
	}
	id, ok := assistantNoteID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), assistantCallTimeout)
	defer cancel()
	n, err := h.assistantOps.Store.Get(ctx, id)
	switch {
	case errors.Is(err, opsnotes.ErrNotFound):
		http.NotFound(w, r)
		return
	case err != nil:
		h.log.Error("assistant ops: get note", "error", err)
		http.Error(w, "assistant unavailable", http.StatusInternalServerError)
		return
	}
	if n.Kind != opsnotes.KindFix {
		http.NotFound(w, r)
		return
	}
	page := assistantNotePage{pageData: h.assistantPageData(r, "Fix suggestion"), Card: h.assistantCardFor(ctx, n)}
	renderAssistantTemplate(w, h.log, assistantNotePageTemplate, "layout", page)
}

// assistantNotePage is the layout data of the detail page.
type assistantNotePage struct {
	pageData
	Card assistantCard
}

// handleAssistantOpsDismiss hides one card. It changes nothing else. A
// request from the panel (htmx) gets an empty answer so the card is removed
// in place; a plain form post goes back to /help.
func (h *Handler) handleAssistantOpsDismiss(w http.ResponseWriter, r *http.Request) {
	if h.assistantOpsDenied(w, r) {
		return
	}
	id, ok := assistantNoteID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), assistantCallTimeout)
	defer cancel()
	err := h.assistantOps.Store.Dismiss(ctx, id)
	switch {
	case errors.Is(err, opsnotes.ErrNotFound):
		http.NotFound(w, r)
		return
	case err != nil:
		h.log.Error("assistant ops: dismiss", "note", id, "error", err)
		http.Error(w, "assistant unavailable", http.StatusInternalServerError)
		return
	}
	h.log.Info("assistant ops: card dismissed", slog.Int64("note", id))
	if r.Header.Get("HX-Request") == "true" {
		w.WriteHeader(http.StatusOK)
		return
	}
	http.Redirect(w, r, "/help", http.StatusSeeOther)
}

// assistantNoteID parses the {id} path value; false when it is not a
// positive number.
func assistantNoteID(r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		return 0, false
	}
	return id, true
}

// yesNo is the text of a flag in the What block.
func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

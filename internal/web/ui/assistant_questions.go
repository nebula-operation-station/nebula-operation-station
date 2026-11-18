// SPDX-License-Identifier: AGPL-3.0-or-later

package ui

// Admin questions in the Ops tab (ADR 0016 D11). An admin asks a question
// (POST, Origin-checked by the middleware like every state change); NOS
// stores it and touches the agent's trigger, and the tab polls the list.
// No listener, no stream.
//
// Rules of this file:
//   - Admins only: every route answers 404 to anyone else (assistantOpsDenied).
//   - The question text is never logged, audited or notified. The audit line
//     carries the user, the length and a keyed digest of the text.
//   - An answer shows its text and its citations under the LLM label. It has
//     no steps and no buttons: the template has no place for them.
//   - Error answers carry fixed texts; the input is never echoed.

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"sync"

	"github.com/nebula-operation-station/nebula-operation-station/internal/opsnotes"
)

// maxAskRequestBytes bounds the form of one question before it is parsed:
// the text (MaxQuestionBytes) plus the form encoding and the field name.
const maxAskRequestBytes = 4 * opsnotes.MaxQuestionBytes

// assistantQuestionsView is the question part of the Ops tab: the form's error
// text and the admin's own questions, newest first. The list is polled by
// assistant-ops.js (ADR 0016 D11: the UI polls; there is no stream).
type assistantQuestionsView struct {
	// Error is the fixed text of a refused question; empty when none.
	Error string
	Items []assistantQuestionItem
}

// assistantQuestionItem is one question of the admin.
type assistantQuestionItem struct {
	ID      int64
	Created string
	Text    string
	// State is "open", "answered" or "expired".
	State  string
	Answer *assistantAnswerView
}

// assistantAnswerView is the answer to a question: text and citations only.
type assistantAnswerView struct {
	Text      string
	Citations []assistantCitation
}

// Fixed texts of refused questions (the form shows them; no input is echoed).
const (
	askErrMissing  = "Enter a question."
	askErrLimit    = "The question is longer than 2 KiB."
	askErrText     = "The question contains a web address or characters that are not allowed."
	askErrFull     = "Too many questions are open. Wait for an answer."
	askErrDaily    = "The daily question limit is reached."
	askErrRejected = "The question could not be read. Try again."
)

// askErrorText maps a store refusal to its fixed text; false for an error the
// store did not refuse on purpose.
func askErrorText(err error) (string, bool) {
	switch {
	case errors.Is(err, opsnotes.ErrMissing):
		return askErrMissing, true
	case errors.Is(err, opsnotes.ErrLimit):
		return askErrLimit, true
	case errors.Is(err, opsnotes.ErrInvalidText), errors.Is(err, opsnotes.ErrURL):
		return askErrText, true
	case errors.Is(err, opsnotes.ErrQuestionsFull):
		return askErrFull, true
	case errors.Is(err, opsnotes.ErrDailyLimit):
		return askErrDaily, true
	}
	return "", false
}

// assistantQuestionsFor builds the question view of user: the questions with
// their state and, for an answered one, its answer note.
func (h *Handler) assistantQuestionsFor(ctx context.Context, user, errText string) (assistantQuestionsView, error) {
	o := h.assistantOps
	qs, err := o.Store.ListQuestions(ctx, user)
	if err != nil {
		return assistantQuestionsView{}, err
	}
	notes, err := o.Store.List(ctx)
	if err != nil {
		return assistantQuestionsView{}, err
	}
	// A question names its answer note (AnswerNoteID). Notes are matched by
	// that ID only: an answer note pruned by the note cap leaves the question
	// answered without an answer, and no other note is shown in its place.
	answers := map[int64]opsnotes.Note{}
	for _, n := range notes {
		if n.Kind == opsnotes.KindAnswer {
			answers[n.ID] = n
		}
	}
	view := assistantQuestionsView{Error: errText, Items: make([]assistantQuestionItem, 0, len(qs))}
	for _, q := range qs {
		it := assistantQuestionItem{
			ID:      q.ID,
			Created: q.CreatedAt.UTC().Format("2006-01-02 15:04 UTC"),
			Text:    q.Text,
			State:   string(q.State),
		}
		if n, ok := answers[q.AnswerNoteID]; ok && q.State == opsnotes.QuestionAnswered {
			it.Answer = &assistantAnswerView{Text: n.Body.Text, Citations: h.assistantCitations(n.Body.Citations)}
		}
		view.Items = append(view.Items, it)
	}
	return view, nil
}

// handleAssistantOpsQuestions renders the question list for the polling
// script. It is read-only.
func (h *Handler) handleAssistantOpsQuestions(w http.ResponseWriter, r *http.Request) {
	if !helpMethodOK(w, r) || h.assistantOpsDenied(w, r) {
		return
	}
	user, ok := h.assistantOps.user(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), assistantCallTimeout)
	defer cancel()
	view, err := h.assistantQuestionsFor(ctx, user, "")
	if err != nil {
		h.log.Error("assistant ops: list questions", "error", err)
		http.Error(w, "assistant unavailable", http.StatusInternalServerError)
		return
	}
	renderAssistantTemplate(w, h.log, assistantFragmentTemplate, "assistant_questions_list", view)
}

// handleAssistantOpsAsk stores one admin question. Htmx gets the question
// block back (form and list); a plain form post goes back to /help.
func (h *Handler) handleAssistantOpsAsk(w http.ResponseWriter, r *http.Request) {
	if h.assistantOpsDenied(w, r) {
		return
	}
	user, ok := h.assistantOps.user(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), assistantCallTimeout)
	defer cancel()
	r.Body = http.MaxBytesReader(w, r.Body, maxAskRequestBytes)
	text, errText := askFormText(r)
	if errText == "" {
		q, err := h.assistantOps.Store.AskQuestion(ctx, user, text)
		switch {
		case err == nil:
			h.auditQuestion(user, text, q.ID)
			h.touchTrigger()
		default:
			msg, known := askErrorText(err)
			if !known {
				h.log.Error("assistant ops: store question", "error", err)
				http.Error(w, "assistant unavailable", http.StatusInternalServerError)
				return
			}
			errText = msg
		}
	}
	if errText != "" && r.Header.Get("HX-Request") != "true" {
		http.Error(w, errText, http.StatusBadRequest)
		return
	}
	if r.Header.Get("HX-Request") != "true" {
		http.Redirect(w, r, "/help", http.StatusSeeOther)
		return
	}
	view, err := h.assistantQuestionsFor(ctx, user, errText)
	if err != nil {
		h.log.Error("assistant ops: list questions", "error", err)
		http.Error(w, "assistant unavailable", http.StatusInternalServerError)
		return
	}
	renderAssistantTemplate(w, h.log, assistantFragmentTemplate, "assistant_ask", view)
}

// askFormText reads the question field. The second result is the fixed error
// text when the form is malformed or the text is empty; the store checks the
// rest.
func askFormText(r *http.Request) (string, string) {
	if err := r.ParseForm(); err != nil {
		return "", askErrRejected
	}
	vals := r.PostForm["question"]
	if len(vals) != 1 {
		return "", askErrRejected
	}
	return vals[0], ""
}

// questionAuditKey keys the digest of the audit line. It is random per process
// and never logged, so a reader of the log cannot test a guessed question
// against the digest; the digests compare only within one run.
var questionAuditKey = sync.OnceValue(func() []byte {
	k := make([]byte, 32)
	_, _ = rand.Read(k) // crypto/rand.Read does not fail since Go 1.24
	return k
})

// questionAuditDigest is the HMAC-SHA256 of a question text under the audit
// key, with a domain prefix.
func questionAuditDigest(text string) string {
	m := hmac.New(sha256.New, questionAuditKey())
	m.Write([]byte("nebula-ops-question-audit-v1\x00" + text))
	return hex.EncodeToString(m.Sum(nil))
}

// auditQuestion writes the audit line of a stored question: user, length and
// the keyed digest of the text. The text itself is never logged.
func (h *Handler) auditQuestion(user, text string, id int64) {
	h.log.Info("audit", "kind", "ops_question", "user", user, "question", id,
		"length", len(text), "digest", questionAuditDigest(text))
}

// touchTrigger wakes the agent through the injected trigger, if configured.
// A failure is logged without any question text; the agent then runs on its
// timer.
func (h *Handler) touchTrigger() {
	if h.assistantOps.Touch == nil {
		return
	}
	if err := h.assistantOps.Touch(); err != nil {
		h.log.Warn("assistant ops: trigger not touched", "error", err)
	}
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package ui_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/opsnotes"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
)

// questionMarker must never reach a log line, an audit line or a notification.
const questionMarker = "MARKER-QUESTION-TEXT-7f3a"

// postQuestion posts a question form as htmx (htmx=true) or as a plain form.
func postQuestion(t *testing.T, h http.Handler, text string, htmx bool) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/assistant/ops/questions",
		strings.NewReader(url.Values{"question": {text}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", assistantOrigin)
	if htmx {
		req.Header.Set("HX-Request", "true")
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// questionServer builds the UI for user with a log buffer and a trigger
// counter. The trigger error, when set, is returned by Touch.
func questionServer(t *testing.T, store *fakeOpsStore, user string, touchErr error) (http.Handler, *bytes.Buffer, *int) {
	t.Helper()
	var logBuf bytes.Buffer
	touched := 0
	o := &ui.AssistantOps{
		Store:   store,
		IsAdmin: isAdminName,
		Catalog: newCatalog(),
		User:    assistantUser{user}.user,
		Touch: func() error {
			touched++
			return touchErr
		},
	}
	srv, err := newTestHandler(t, ui.Options{PublicOrigin: assistantOrigin, AssistantOps: o,
		Log: slog.New(slog.NewJSONHandler(&logBuf, nil))}).Server()
	if err != nil {
		t.Fatalf("Server: %v", err)
	}
	return srv.Handler, &logBuf, &touched
}

// Non-admins get 404 on both question routes and nothing is stored.
func TestAssistantQuestionsNonAdminIs404(t *testing.T) {
	store := &fakeOpsStore{}
	h, _, touched := questionServer(t, store, "alice", nil)
	if rec := postQuestion(t, h, "Ist alles ok?", true); rec.Code != http.StatusNotFound {
		t.Errorf("POST by non-admin: %d, want 404", rec.Code)
	}
	if rec := doAssistant(t, h, http.MethodGet, "/assistant/ops/questions", map[string]string{"HX-Request": "true"}); rec.Code != http.StatusNotFound {
		t.Errorf("GET list by non-admin: %d, want 404", rec.Code)
	}
	if len(store.questions) != 0 || *touched != 0 {
		t.Errorf("non-admin stored %d questions, touched %d", len(store.questions), *touched)
	}
}

// Questions need the same origin (CSRF, middleware).
func TestAssistantQuestionNeedsSameOrigin(t *testing.T) {
	store := &fakeOpsStore{}
	h, _, _ := questionServer(t, store, "root", nil)
	req := httptest.NewRequest(http.MethodPost, "/assistant/ops/questions",
		strings.NewReader(url.Values{"question": {"Frage?"}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://evil.example")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code == http.StatusOK || rec.Code == http.StatusSeeOther || len(store.questions) != 0 {
		t.Errorf("cross-origin question accepted: %d, stored %d", rec.Code, len(store.questions))
	}
}

// An admin's question is stored for that admin, the agent is touched once,
// and the htmx answer is the question block with the new question.
func TestAssistantQuestionStoresAndTouchesTrigger(t *testing.T) {
	store := &fakeOpsStore{}
	h, _, touched := questionServer(t, store, "root", nil)
	rec := postQuestion(t, h, "Ist die Box erreichbar?", true)
	if rec.Code != http.StatusOK {
		t.Fatalf("htmx POST: %d %s", rec.Code, rec.Body.String())
	}
	if len(store.questions) != 1 || store.questions[0].User != "root" || store.questions[0].State != opsnotes.QuestionOpen {
		t.Fatalf("stored = %+v", store.questions)
	}
	if *touched != 1 {
		t.Errorf("trigger touched %d times, want 1", *touched)
	}
	if !strings.Contains(rec.Body.String(), `id="assistant-ask"`) || !strings.Contains(rec.Body.String(), "Question 1") {
		t.Errorf("answer is not the question block:\n%s", rec.Body.String())
	}
}

// A plain form post goes back to /help.
func TestAssistantQuestionPlainPostRedirects(t *testing.T) {
	store := &fakeOpsStore{}
	h, _, _ := questionServer(t, store, "root", nil)
	rec := postQuestion(t, h, "Frage?", false)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/help" {
		t.Errorf("plain post: %d %q, want 303 /help", rec.Code, rec.Header().Get("Location"))
	}
	if len(store.questions) != 1 {
		t.Errorf("stored %d questions, want 1", len(store.questions))
	}
}

// A trigger failure does not lose the question; it is logged without text.
func TestAssistantQuestionSurvivesTriggerFailure(t *testing.T) {
	store := &fakeOpsStore{}
	h, logBuf, _ := questionServer(t, store, "root", errors.New("unit not found"))
	if rec := postQuestion(t, h, "Frage?", true); rec.Code != http.StatusOK {
		t.Fatalf("POST: %d", rec.Code)
	}
	if len(store.questions) != 1 {
		t.Errorf("question lost after trigger failure")
	}
	if !strings.Contains(logBuf.String(), "trigger not touched") {
		t.Errorf("trigger failure not logged")
	}
}

// The store's refusals show as fixed texts; nothing is touched.
func TestAssistantQuestionRefusalsShowFixedText(t *testing.T) {
	tests := []struct {
		err  error
		want string
	}{
		{opsnotes.ErrQuestionsFull, "Too many questions are open"},
		{opsnotes.ErrDailyLimit, "daily question limit"},
		{fmt.Errorf("x: %w", opsnotes.ErrLimit), "longer than 2 KiB"},
		{fmt.Errorf("x: %w", opsnotes.ErrURL), "web address"},
		{fmt.Errorf("x: %w", opsnotes.ErrInvalidText), "not allowed"},
	}
	for _, tc := range tests {
		t.Run(tc.want, func(t *testing.T) {
			store := &fakeOpsStore{askErr: tc.err}
			h, _, touched := questionServer(t, store, "root", nil)
			rec := postQuestion(t, h, "Frage?", true)
			if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), tc.want) {
				t.Errorf("refusal answer %d: %s", rec.Code, rec.Body.String())
			}
			if *touched != 0 {
				t.Errorf("refused question touched the trigger")
			}
		})
	}
}

// The question text never reaches a log line, the audit line carries only the
// user, the length and the SHA-256, and the pages and lists do not log it.
func TestAssistantQuestionTextNeverReachesLogsOrAudit(t *testing.T) {
	store := &fakeOpsStore{}
	text := questionMarker + " ist die Box erreichbar?"
	h, logBuf, _ := questionServer(t, store, "root", nil)
	if rec := postQuestion(t, h, text, true); rec.Code != http.StatusOK {
		t.Fatalf("POST: %d", rec.Code)
	}
	doAssistant(t, h, http.MethodGet, "/assistant/ops/questions", map[string]string{"HX-Request": "true"})
	doAssistant(t, h, http.MethodGet, "/assistant/ops", map[string]string{"HX-Request": "true"})
	if strings.Contains(logBuf.String(), questionMarker) {
		t.Fatalf("question text reached the log:\n%s", logBuf.String())
	}
	sum := sha256.Sum256([]byte(text))
	audit := auditLineOf(t, logBuf.String(), "ops_question")
	if !strings.Contains(audit, `"user":"root"`) || !strings.Contains(audit, hex.EncodeToString(sum[:])) ||
		!strings.Contains(audit, fmt.Sprintf(`"length":%d`, len(text))) {
		t.Errorf("audit line = %s", audit)
	}
}

// auditLineOf returns the JSON log line whose kind is kind.
func auditLineOf(t *testing.T, log, kind string) string {
	t.Helper()
	for _, line := range strings.Split(log, "\n") {
		if strings.Contains(line, `"kind":"`+kind+`"`) {
			return line
		}
	}
	t.Fatalf("no %s audit line in:\n%s", kind, log)
	return ""
}

// The list shows only the admin's own questions, and an answer shows its text
// and sources under the LLM label, with no steps and no buttons.
func TestAssistantQuestionListOwnAndAnswers(t *testing.T) {
	store := &fakeOpsStore{
		questions: []opsnotes.Question{
			{ID: 1, User: "root", Text: "Frage eins", State: opsnotes.QuestionAnswered, CreatedAt: time.Unix(1_800_000_000, 0).UTC()},
			{ID: 2, User: "other", Text: "fremde Frage", State: opsnotes.QuestionOpen, CreatedAt: time.Unix(1_800_000_000, 0).UTC()},
		},
		notes: []opsnotes.Note{{
			ID: 9, Kind: opsnotes.KindAnswer, Ref: "1", Digest: "x",
			Body:      opsnotes.Body{Text: "Ja, sie antwortet.", Citations: []string{"doc-unknown"}},
			CreatedAt: time.Unix(1_800_000_100, 0).UTC(),
		}},
		nextQuestion: 2,
	}
	h, _, _ := questionServer(t, store, "root", nil)
	body := doAssistant(t, h, http.MethodGet, "/assistant/ops/questions", map[string]string{"HX-Request": "true"}).Body.String()
	if strings.Contains(body, "fremde Frage") {
		t.Errorf("another admin's question is shown")
	}
	if !strings.Contains(body, "Frage eins") || !strings.Contains(body, "Ja, sie antwortet.") {
		t.Fatalf("own question or answer missing:\n%s", body)
	}
	if !strings.Contains(body, "Generated by an LLM") {
		t.Errorf("answer has no LLM label")
	}
	answer := body[strings.Index(body, `aria-label="Answer"`):]
	answer = answer[:strings.Index(answer, "</section>")]
	for _, bad := range []string{"<button", "<form", "<a class=\"button", "/operations/new", "suggestion="} {
		if strings.Contains(answer, bad) {
			t.Errorf("answer carries %q:\n%s", bad, answer)
		}
	}
}

// The Ops tab carries the question form and the poll target.
func TestAssistantOpsTabHasQuestionFormAndPollTarget(t *testing.T) {
	store := &fakeOpsStore{}
	h, _, _ := questionServer(t, store, "root", nil)
	body := doAssistant(t, h, http.MethodGet, "/assistant/ops", nil).Body.String()
	for _, want := range []string{`action="/assistant/ops/questions"`, `name="question"`, `maxlength="2048"`,
		`id="assistant-questions"`, `data-url="/assistant/ops/questions"`, `/static/assistant-ops.js`} {
		if !strings.Contains(body, want) {
			t.Errorf("Ops tab lacks %s", want)
		}
	}
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package opsnotes

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"
)

// zeroWidthSpace is U+200B, built from its code point so the source holds no
// invisible format character.
const zeroWidthSpace = string(rune(0x200b))

// askQuestion stores a question and fails the test on error.
func askQuestion(t *testing.T, s *Store, user, text string) Question {
	t.Helper()
	q, err := s.AskQuestion(context.Background(), user, text)
	if err != nil {
		t.Fatalf("AskQuestion: %v", err)
	}
	return q
}

// answerDraft is an answer to question q carrying the question's digest.
func answerDraft(q Question, text string) Draft {
	return Draft{Kind: KindAnswer, Ref: strconv.FormatInt(q.ID, 10), Digest: q.Digest, Body: Body{Text: text}}
}

func TestAskQuestionStoresOpenQuestionWithDigest(t *testing.T) {
	s := openTestStore(t, &fakeClock{t: baseTime})
	q := askQuestion(t, s, "admin", "Ist host1 erreichbar?")
	if q.ID == 0 || q.State != QuestionOpen || q.User != "admin" || q.Text != "Ist host1 erreichbar?" {
		t.Fatalf("AskQuestion = %+v", q)
	}
	if q.Digest != QuestionDigest(q.Text) || q.Digest == QuestionDigest("anderer Text") {
		t.Errorf("digest does not bind the text: %s", q.Digest)
	}
	if !q.CreatedAt.Equal(baseTime) {
		t.Errorf("CreatedAt = %v, want the injected clock", q.CreatedAt)
	}
	list, err := s.ListQuestions(context.Background(), "admin")
	if err != nil || len(list) != 1 || list[0].ID != q.ID {
		t.Fatalf("ListQuestions = %+v, %v", list, err)
	}
	other, err := s.ListQuestions(context.Background(), "someone-else")
	if err != nil || len(other) != 0 {
		t.Errorf("ListQuestions of another user = %+v, %v; want none", other, err)
	}
}

func TestAskQuestionRefusesBadTextAndStoresNothing(t *testing.T) {
	s := openTestStore(t, &fakeClock{t: baseTime})
	ctx := context.Background()
	tests := []struct {
		name string
		text string
		want error
	}{
		{"empty", "   ", ErrMissing},
		{"over 2 KiB", strings.Repeat("a", MaxTextBytes+1), ErrLimit},
		{"control rune", "hallo\x07", ErrInvalidText},
		{"zero width", "ha" + zeroWidthSpace + "llo", ErrInvalidText},
		{"invalid UTF-8", "ha\xffllo", ErrInvalidText},
		{"URL", "siehe https://example.org", ErrURL},
		{"www", "siehe www.example.org", ErrURL},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := s.AskQuestion(ctx, "admin", tc.text)
			if !errors.Is(err, tc.want) {
				t.Fatalf("AskQuestion error = %v, want %v", err, tc.want)
			}
		})
	}
	if list, _ := s.ListQuestions(ctx, "admin"); len(list) != 0 {
		t.Errorf("refused questions were stored: %d", len(list))
	}
}

func TestAskQuestionAcceptsExactlyTheByteLimit(t *testing.T) {
	s := openTestStore(t, &fakeClock{t: baseTime})
	q := askQuestion(t, s, "admin", strings.Repeat("a", MaxTextBytes))
	if len(q.Text) != MaxTextBytes {
		t.Errorf("stored %d bytes, want %d", len(q.Text), MaxTextBytes)
	}
}

func TestAskQuestionOpenLimitIsMaxOpenQuestions(t *testing.T) {
	s := openTestStore(t, &fakeClock{t: baseTime})
	ctx := context.Background()
	for i := range MaxOpenQuestions {
		askQuestion(t, s, "admin", "Frage "+strconv.Itoa(i))
	}
	_, err := s.AskQuestion(ctx, "admin", "eine zu viel")
	if !errors.Is(err, ErrQuestionsFull) {
		t.Fatalf("question %d error = %v, want ErrQuestionsFull", MaxOpenQuestions+1, err)
	}
}

func TestAskQuestionDailyLimitCountsUTCDay(t *testing.T) {
	clock := &fakeClock{t: baseTime}
	s := openTestStore(t, clock)
	ctx := context.Background()
	// Close the questions after asking so only the daily limit applies.
	for i := range MaxQuestionsPerDay {
		q := askQuestion(t, s, "admin", "Frage "+strconv.Itoa(i))
		closeQuestionForTest(t, s, q.ID)
	}
	if _, err := s.AskQuestion(ctx, "admin", "zu viele heute"); !errors.Is(err, ErrDailyLimit) {
		t.Fatalf("question %d today error = %v, want ErrDailyLimit", MaxQuestionsPerDay+1, err)
	}
	clock.t = baseTime.Add(24 * time.Hour)
	askQuestion(t, s, "admin", "morgen wieder erlaubt")
}

func TestAnswerRequiresOpenQuestionWithCurrentDigest(t *testing.T) {
	s := openTestStore(t, &fakeClock{t: baseTime})
	ctx := context.Background()
	r := newFakeResolver()
	q := askQuestion(t, s, "admin", "Frage?")

	tests := []struct {
		name  string
		draft Draft
		want  error
	}{
		{"unknown question", Draft{Kind: KindAnswer, Ref: "999", Digest: q.Digest, Body: Body{Text: "x"}}, ErrUnknownRef},
		{"non-numeric ref", Draft{Kind: KindAnswer, Ref: "vu:host1:openssl", Digest: q.Digest, Body: Body{Text: "x"}}, ErrUnknownRef},
		{"stale digest", Draft{Kind: KindAnswer, Ref: strconv.FormatInt(q.ID, 10), Digest: "0000", Body: Body{Text: "x"}}, ErrStaleDigest},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := s.Put(ctx, r, tc.draft, testSnapshot)
			if !errors.Is(err, tc.want) {
				t.Fatalf("Put error = %v, want %v", err, tc.want)
			}
		})
	}
	if got := questionState(t, s, q.ID); got != QuestionOpen {
		t.Errorf("refused answers changed the question to %s", got)
	}
}

func TestAnswerWithStepsIsRefused(t *testing.T) {
	s := openTestStore(t, &fakeClock{t: baseTime})
	ctx := context.Background()
	r := newFakeResolver()
	q := askQuestion(t, s, "admin", "Was tun?")
	d := answerDraft(q, "Antwort.")
	d.Steps = []StepInput{{ActionID: "service.restart", HostID: "host1"}}
	_, _, err := s.Put(ctx, r, d, testSnapshot)
	if !errors.Is(err, ErrFieldNotAllowed) {
		t.Fatalf("answer with steps error = %v, want ErrFieldNotAllowed", err)
	}
	d = answerDraft(q, "Antwort.")
	d.Mitigations = []string{"Dienst stoppen"}
	if _, _, err := s.Put(ctx, r, d, testSnapshot); !errors.Is(err, ErrFieldNotAllowed) {
		t.Fatalf("answer with mitigations error = %v, want ErrFieldNotAllowed", err)
	}
	if got := questionState(t, s, q.ID); got != QuestionOpen {
		t.Errorf("refused answer changed the question to %s", got)
	}
}

func TestAnswerClosesQuestionAndStoresNote(t *testing.T) {
	s := openTestStore(t, &fakeClock{t: baseTime})
	ctx := context.Background()
	r := newFakeResolver()
	q := askQuestion(t, s, "admin", "Frage?")
	n, created, err := s.Put(ctx, r, answerDraft(q, "Antwort."), testSnapshot)
	if err != nil || !created {
		t.Fatalf("Put answer created=%v err=%v", created, err)
	}
	if got := questionState(t, s, q.ID); got != QuestionAnswered {
		t.Errorf("state = %s, want answered", got)
	}
	got, err := s.GetQuestion(ctx, q.ID)
	if err != nil || got.AnswerNoteID != n.ID {
		t.Errorf("GetQuestion AnswerNoteID = %d, %v; want %d", got.AnswerNoteID, err, n.ID)
	}
	// A second answer to the same question is refused.
	if _, _, err := s.Put(ctx, r, answerDraft(q, "Noch eine."), testSnapshot); !errors.Is(err, ErrNotOpen) {
		t.Errorf("second answer error = %v, want ErrNotOpen", err)
	}
	open, err := s.OpenQuestions(ctx)
	if err != nil || len(open) != 0 {
		t.Errorf("OpenQuestions = %+v, %v; want none", open, err)
	}
}

func TestOpenQuestionsOldestFirst(t *testing.T) {
	clock := &fakeClock{t: baseTime}
	s := openTestStore(t, clock)
	first := askQuestion(t, s, "admin", "erste")
	clock.t = clock.t.Add(time.Minute)
	second := askQuestion(t, s, "admin", "zweite")
	open, err := s.OpenQuestions(context.Background())
	if err != nil || len(open) != 2 || open[0].ID != first.ID || open[1].ID != second.ID {
		t.Fatalf("OpenQuestions = %+v, %v; want oldest first", open, err)
	}
}

func TestOpenQuestionExpiresAfterRetention(t *testing.T) {
	clock := &fakeClock{t: baseTime}
	s := openTestStore(t, clock)
	ctx := context.Background()
	q := askQuestion(t, s, "admin", "alt")
	clock.t = baseTime.Add(QuestionOpenTTL + time.Hour)
	if _, err := s.Prune(ctx, clock.t); err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if got := questionState(t, s, q.ID); got != QuestionExpired {
		t.Fatalf("state after the open TTL = %s, want expired", got)
	}
	if _, _, err := s.Put(ctx, newFakeResolver(), answerDraft(q, "zu spät"), testSnapshot); !errors.Is(err, ErrNotOpen) {
		t.Errorf("answer to expired question error = %v, want ErrNotOpen", err)
	}
}

func TestPruneDeletesQuestionsOlderThanRetention(t *testing.T) {
	clock := &fakeClock{t: baseTime}
	s := openTestStore(t, clock)
	ctx := context.Background()
	old := askQuestion(t, s, "admin", "alt")
	clock.t = baseTime.Add(Retention + time.Hour)
	fresh := askQuestion(t, s, "admin", "neu")
	if _, err := s.Prune(ctx, clock.t); err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if _, err := s.GetQuestion(ctx, old.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("old question still stored: %v", err)
	}
	if _, err := s.GetQuestion(ctx, fresh.ID); err != nil {
		t.Errorf("fresh question pruned: %v", err)
	}
}

// questionState reads the state of a question straight from the store.
func questionState(t *testing.T, s *Store, id int64) QuestionState {
	t.Helper()
	q, err := s.GetQuestion(context.Background(), id)
	if err != nil {
		t.Fatalf("GetQuestion: %v", err)
	}
	return q.State
}

// closeQuestionForTest marks a question answered without a note, so the
// daily limit can be tested without hitting the open limit.
func closeQuestionForTest(t *testing.T, s *Store, id int64) {
	t.Helper()
	if _, err := s.db.Exec(`UPDATE questions SET state = 'answered' WHERE id = ?`, id); err != nil {
		t.Fatalf("close question: %v", err)
	}
}

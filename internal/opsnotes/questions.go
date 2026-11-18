// SPDX-License-Identifier: AGPL-3.0-or-later

package opsnotes

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

// QuestionState is the state of an admin question (ADR 0016 D11).
type QuestionState string

// The question states. An open question is answered once; an open question
// older than QuestionOpenTTL becomes expired and can no longer be answered.
const (
	QuestionOpen     QuestionState = "open"
	QuestionAnswered QuestionState = "answered"
	QuestionExpired  QuestionState = "expired"
)

// Question is a stored admin question. Text is the admin's text; it is never
// written to a log or an audit entry.
type Question struct {
	ID           int64
	User         string
	Text         string
	Digest       string
	State        QuestionState
	CreatedAt    time.Time
	AnsweredAt   time.Time
	AnswerNoteID int64
}

// QuestionDigest is the input digest of a question: SHA-256 over its text,
// domain-separated. An answer carries it, so an answer binds to the text it
// answers.
func QuestionDigest(text string) string {
	sum := sha256.Sum256([]byte("nebula-ops-question-v1\x00" + text))
	return hex.EncodeToString(sum[:])
}

// maxQuestionUserBytes bounds the user name stored with a question.
const maxQuestionUserBytes = 128

// AskQuestion stores a question of user. The text is checked like a note's
// free text (at most MaxQuestionBytes, printable, no URL). Before storing it
// prunes, then refuses at MaxOpenQuestions open questions or at
// MaxQuestionsPerDay questions of the UTC day.
func (s *Store) AskQuestion(ctx context.Context, user, text string) (Question, error) {
	if strings.TrimSpace(user) == "" {
		return Question{}, fmt.Errorf("user: %w", ErrMissing)
	}
	if err := checkText("user", user, maxQuestionUserBytes, false); err != nil {
		return Question{}, err
	}
	if strings.TrimSpace(text) == "" {
		return Question{}, fmt.Errorf("question: %w", ErrMissing)
	}
	if err := checkFreeText("question", text, MaxQuestionBytes); err != nil {
		return Question{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Question{}, fmt.Errorf("opsnotes: begin question: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	now := s.now().UTC()
	if _, err := expireQuestionsTx(ctx, tx, now); err != nil {
		return Question{}, err
	}
	var open int
	if err := tx.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM questions WHERE state = 'open'`).Scan(&open); err != nil {
		return Question{}, fmt.Errorf("opsnotes: count open questions: %w", err)
	}
	if open >= MaxOpenQuestions {
		return Question{}, fmt.Errorf("%d open: %w", open, ErrQuestionsFull)
	}
	dayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	var today int
	if err := tx.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM questions WHERE created_at >= ?`, dayStart.UnixNano()).Scan(&today); err != nil {
		return Question{}, fmt.Errorf("opsnotes: count questions today: %w", err)
	}
	if today >= MaxQuestionsPerDay {
		return Question{}, fmt.Errorf("day %s: %w", dayStart.Format(time.DateOnly), ErrDailyLimit)
	}
	res, err := tx.ExecContext(ctx,
		`INSERT INTO questions (user_name, text, digest, state, created_at) VALUES (?, ?, ?, 'open', ?)`,
		user, text, QuestionDigest(text), now.UnixNano())
	if err != nil {
		return Question{}, fmt.Errorf("opsnotes: insert question: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return Question{}, fmt.Errorf("opsnotes: question ID: %w", err)
	}
	q, err := getQuestion(ctx, tx, id)
	if err != nil {
		return Question{}, err
	}
	if err := tx.Commit(); err != nil {
		return Question{}, fmt.Errorf("opsnotes: commit question: %w", err)
	}
	return q, nil
}

// GetQuestion returns a stored question in any state.
func (s *Store) GetQuestion(ctx context.Context, id int64) (Question, error) {
	return getQuestion(ctx, s.db, id)
}

// ListQuestions returns the questions of user, newest first, in any state.
func (s *Store) ListQuestions(ctx context.Context, user string) ([]Question, error) {
	return s.queryQuestions(ctx, questionColumns+` WHERE user_name = ? ORDER BY id DESC`, user)
}

// OpenQuestions returns the open questions, oldest first (the order the agent
// answers them in). A question older than QuestionOpenTTL is not returned even
// before the prune has marked it expired.
func (s *Store) OpenQuestions(ctx context.Context) ([]Question, error) {
	return s.queryQuestions(ctx,
		questionColumns+` WHERE state = 'open' AND created_at >= ? ORDER BY created_at ASC, id ASC`,
		s.openCutoff().UnixNano())
}

// openCutoff is the oldest creation time an open question may have and still
// be open: the same bound expireQuestionsTx applies.
func (s *Store) openCutoff() time.Time {
	return s.now().UTC().Add(-QuestionOpenTTL)
}

func (s *Store) queryQuestions(ctx context.Context, query string, args ...any) ([]Question, error) {
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("opsnotes: list questions: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []Question
	for rows.Next() {
		q, err := scanQuestion(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, q)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("opsnotes: list questions: %w", err)
	}
	return out, nil
}

// openQuestionForAnswer returns the question an answer refers to. The ref must
// be a question ID: a missing or non-decimal one is ErrUnknownRef, a question
// that is no longer open is ErrNotOpen.
func (s *Store) openQuestionForAnswer(ctx context.Context, ref string) (Question, error) {
	id, err := parseQuestionRef(ref)
	if err != nil {
		return Question{}, err
	}
	q, err := getQuestion(ctx, s.db, id)
	if errors.Is(err, ErrNotFound) {
		return Question{}, fmt.Errorf("question %s: %w", ref, ErrUnknownRef)
	}
	if err != nil {
		return Question{}, err
	}
	if q.State != QuestionOpen {
		return Question{}, fmt.Errorf("question %s is %s: %w", ref, q.State, ErrNotOpen)
	}
	// The prune marks expired questions only hourly; an open question past
	// its TTL is refused here already, as expireQuestionsTx would.
	if q.CreatedAt.Before(s.openCutoff()) {
		return Question{}, fmt.Errorf("question %s is past its open TTL: %w", ref, ErrNotOpen)
	}
	return q, nil
}

// parseQuestionRef reads the decimal question ID an answer carries as its ref.
// Only the canonical form is accepted, so one question has one ref.
func parseQuestionRef(ref string) (int64, error) {
	var id int64
	if _, err := fmt.Sscan(ref, &id); err != nil || id <= 0 || fmt.Sprint(id) != ref {
		return 0, fmt.Errorf("ref %q is not a question ID: %w", ref, ErrUnknownRef)
	}
	return id, nil
}

// closeQuestionTx marks question id answered by note noteID, inside the
// transaction of the answer note. A question that is no longer open fails.
func closeQuestionTx(ctx context.Context, tx *sql.Tx, id, noteID int64, at time.Time) error {
	res, err := tx.ExecContext(ctx,
		`UPDATE questions SET state = 'answered', answered_at = ?, answer_note = ? WHERE id = ? AND state = 'open'`,
		at.UnixNano(), noteID, id)
	if err != nil {
		return fmt.Errorf("opsnotes: close question %d: %w", id, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("opsnotes: close question %d: %w", id, err)
	}
	if n != 1 {
		return fmt.Errorf("question %d: %w", id, ErrNotOpen)
	}
	return nil
}

// expireQuestionsTx marks open questions older than QuestionOpenTTL as
// expired, and deletes the questions older than Retention. Reads apply the
// same open bound (Store.openCutoff) without waiting for this.
func expireQuestionsTx(ctx context.Context, q queryer, now time.Time) (int64, error) {
	if _, err := q.ExecContext(ctx,
		`UPDATE questions SET state = 'expired' WHERE state = 'open' AND created_at < ?`,
		now.Add(-QuestionOpenTTL).UnixNano()); err != nil {
		return 0, fmt.Errorf("opsnotes: expire questions: %w", err)
	}
	res, err := q.ExecContext(ctx, `DELETE FROM questions WHERE created_at < ?`, now.Add(-Retention).UnixNano())
	if err != nil {
		return 0, fmt.Errorf("opsnotes: prune questions: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("opsnotes: prune questions: %w", err)
	}
	return n, nil
}

const questionColumns = `SELECT id, user_name, text, digest, state, created_at, answered_at, answer_note FROM questions`

func getQuestion(ctx context.Context, q queryer, id int64) (Question, error) {
	row := q.QueryRowContext(ctx, questionColumns+` WHERE id = ?`, id)
	out, err := scanQuestion(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Question{}, fmt.Errorf("question %d: %w", id, ErrNotFound)
	}
	return out, err
}

func scanQuestion(sc scanner) (Question, error) {
	var (
		q                     Question
		state                 string
		createdNS, answeredNS int64
	)
	if err := sc.Scan(&q.ID, &q.User, &q.Text, &q.Digest, &state, &createdNS, &answeredNS, &q.AnswerNoteID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Question{}, err
		}
		return Question{}, fmt.Errorf("opsnotes: scan question: %w", err)
	}
	q.State = QuestionState(state)
	q.CreatedAt = time.Unix(0, createdNS).UTC()
	if answeredNS != 0 {
		q.AnsweredAt = time.Unix(0, answeredNS).UTC()
	}
	return q, nil
}

// answerResolver checks an answer against its question: the current digest of
// an answer ref is the question's digest. Every other check is the wrapped
// resolver's.
type answerResolver struct {
	Resolver
	digest string
}

// CurrentDigest returns the question's digest for an answer.
func (a answerResolver) CurrentDigest(kind Kind, ref string) (string, bool) {
	if kind == KindAnswer {
		return a.digest, true
	}
	return a.Resolver.CurrentDigest(kind, ref)
}

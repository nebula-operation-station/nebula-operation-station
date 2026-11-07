// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// Session lifetimes. A web session only allows reading; privileged work
// needs its own assertions at the executor (spec 05).
const (
	IdleTimeout     = 24 * time.Hour
	AbsoluteTimeout = 14 * 24 * time.Hour
	// touchInterval limits last_seen writes to one per interval.
	touchInterval = 5 * time.Minute
	tokenBytes    = 32
)

// ErrNoSession is returned for a missing, unknown or expired session.
var ErrNoSession = errors.New("auth: no valid session")

// Session is an authenticated web session.
type Session struct {
	CredentialID string // base64url, as the executor reported it
	UserName     string
	CreatedAt    time.Time
	LastSeenAt   time.Time
	ExpiresAt    time.Time
}

// Store keeps web sessions in server.db (migration 0003). Only the SHA-256
// of a token is stored.
type Store struct {
	db  *sql.DB
	now func() time.Time
}

// NewStore returns a session store on db. now may be nil (time.Now).
func NewStore(db *sql.DB, now func() time.Time) *Store {
	if now == nil {
		now = time.Now
	}
	return &Store{db: db, now: now}
}

func hashToken(token string) ([]byte, bool) {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(raw) != tokenBytes {
		return nil, false
	}
	sum := sha256.Sum256(raw)
	return sum[:], true
}

// Create opens a session for a verified login and returns its token.
func (s *Store) Create(ctx context.Context, credentialID, userName string) (string, Session, error) {
	raw := make([]byte, tokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", Session{}, fmt.Errorf("auth: random token: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256(raw)
	now := s.now().Truncate(time.Second)
	sess := Session{CredentialID: credentialID, UserName: userName, CreatedAt: now, LastSeenAt: now, ExpiresAt: now.Add(AbsoluteTimeout)}
	if _, err := s.db.ExecContext(ctx, `INSERT INTO web_sessions (token_hash, credential_id, user_name, created_at, last_seen_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?)`, sum[:], credentialID, userName, now.Unix(), now.Unix(), sess.ExpiresAt.Unix()); err != nil {
		return "", Session{}, fmt.Errorf("auth: create session: %w", err)
	}
	return token, sess, nil
}

// Lookup returns the session for token if it is neither idle-expired nor
// past its absolute expiry, and records the activity.
func (s *Store) Lookup(ctx context.Context, token string) (Session, error) {
	return s.lookup(ctx, token, true)
}

// Peek is Lookup without recording activity: it validates the session the
// same way but never moves last_seen, so it cannot keep an idle session
// alive. It serves passive status requests (see PassiveHeader).
func (s *Store) Peek(ctx context.Context, token string) (Session, error) {
	return s.lookup(ctx, token, false)
}

// LiveTargetsPath is the live chart's visible-box endpoint. An open chart
// tab POSTs to it every 10 s on its own (lease renewal), so that POST is
// background traffic, not user activity.
const LiveTargetsPath = "/chart/live/targets"

// recordsActivity reports whether an authenticated request moves the
// session's last_seen. Marked passive status polls (PassiveHeader) and the
// live target renewal do not: an unattended open tab cannot keep a web
// session alive past IdleTimeout. Such requests are authenticated with
// Peek, which validates exactly like Lookup; they gain nothing.
func recordsActivity(r *http.Request) bool {
	if r.Method == http.MethodPost && r.URL.Path == LiveTargetsPath {
		return false
	}
	return !passiveRequest(r)
}

// PeekRegistered is Peek plus the credential check the login wrapper runs
// on every request: once the executor reports the session's credential
// removed, the session is deleted and ErrNoSession returned. It never
// records activity. It re-validates long-lived requests that do not pass
// the wrapper again (the live chart's SSE stream); the executor is asked
// at most once per CredentialCheckInterval per session.
func (h *Handler) PeekRegistered(ctx context.Context, token string) (Session, error) {
	sess, err := h.sessions.Peek(ctx, token)
	if err != nil {
		return Session{}, err
	}
	if !h.credentialStillRegistered(ctx, token, sess) {
		h.clearHolderOf(token)
		if err := h.sessions.Delete(ctx, token); err != nil {
			h.log.Error("delete revoked session", "error", err)
		}
		h.log.Info("audit", "kind", "web_session_revoked", "user", sess.UserName, "credential", sess.CredentialID,
			"reason", "credential no longer registered")
		return Session{}, ErrNoSession
	}
	return sess, nil
}

func (s *Store) lookup(ctx context.Context, token string, touch bool) (Session, error) {
	h, ok := hashToken(token)
	if !ok {
		return Session{}, ErrNoSession
	}
	var sess Session
	var created, seen, exp int64
	err := s.db.QueryRowContext(ctx, `SELECT credential_id, user_name, created_at, last_seen_at, expires_at
		FROM web_sessions WHERE token_hash = ?`, h).Scan(&sess.CredentialID, &sess.UserName, &created, &seen, &exp)
	if errors.Is(err, sql.ErrNoRows) {
		return Session{}, ErrNoSession
	}
	if err != nil {
		return Session{}, fmt.Errorf("auth: lookup session: %w", err)
	}
	sess.CreatedAt, sess.LastSeenAt, sess.ExpiresAt = time.Unix(created, 0), time.Unix(seen, 0), time.Unix(exp, 0)
	now := s.now()
	if !now.Before(sess.ExpiresAt) || !now.Before(sess.LastSeenAt.Add(IdleTimeout)) {
		_, _ = s.db.ExecContext(ctx, `DELETE FROM web_sessions WHERE token_hash = ?`, h)
		return Session{}, ErrNoSession
	}
	if touch && now.Sub(sess.LastSeenAt) >= touchInterval {
		if _, err := s.db.ExecContext(ctx, `UPDATE web_sessions SET last_seen_at = ? WHERE token_hash = ?`, now.Unix(), h); err == nil {
			sess.LastSeenAt = now.Truncate(time.Second)
		}
	}
	return sess, nil
}

// Delete ends the session of token (logout). Unknown tokens are ignored.
func (s *Store) Delete(ctx context.Context, token string) error {
	h, ok := hashToken(token)
	if !ok {
		return nil
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM web_sessions WHERE token_hash = ?`, h); err != nil {
		return fmt.Errorf("auth: delete session: %w", err)
	}
	return nil
}

// DeleteAll ends every session and reports how many there were.
func (s *Store) DeleteAll(ctx context.Context) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM web_sessions`)
	if err != nil {
		return 0, fmt.Errorf("auth: delete sessions: %w", err)
	}
	return res.RowsAffected()
}

// Prune removes expired sessions.
func (s *Store) Prune(ctx context.Context) (int64, error) {
	now := s.now()
	res, err := s.db.ExecContext(ctx, `DELETE FROM web_sessions WHERE expires_at <= ? OR last_seen_at <= ?`,
		now.Unix(), now.Add(-IdleTimeout).Unix())
	if err != nil {
		return 0, fmt.Errorf("auth: prune sessions: %w", err)
	}
	return res.RowsAffected()
}

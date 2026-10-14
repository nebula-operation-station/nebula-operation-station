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
	if now.Sub(sess.LastSeenAt) >= touchInterval {
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

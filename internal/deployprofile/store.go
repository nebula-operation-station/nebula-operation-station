// SPDX-License-Identifier: AGPL-3.0-or-later

package deployprofile

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"
)

// ErrNotFound reports a profile or version that does not exist.
var ErrNotFound = errors.New("deployprofile: not found")

var userRe = regexp.MustCompile(`^[\x21-\x7e]{1,64}$`)

// Version is one stored, immutable version of a deploy profile.
type Version struct {
	Profile   Profile
	Version   int
	CreatedBy string
	CreatedAt time.Time
	DocSHA256 string
}

// Store keeps deploy profiles in the server database.
type Store struct {
	db  *sql.DB
	now func() time.Time
}

// New returns a store over the server database.
func New(db *sql.DB) *Store { return &Store{db: db, now: time.Now} }

// Save validates a profile and stores it as the profile's next version.
// Editing an existing profile therefore creates a new version; stored
// versions are never changed or removed.
func (s *Store) Save(ctx context.Context, user string, p Profile) (Version, error) {
	if !userRe.MatchString(user) {
		return Version{}, errors.New("deployprofile: invalid user")
	}
	if err := Validate(p); err != nil {
		return Version{}, err
	}
	doc, err := p.Doc()
	if err != nil {
		return Version{}, err
	}
	sum := sha256.Sum256(doc)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Version{}, err
	}
	defer func() { _ = tx.Rollback() }()
	now := s.now()
	if _, err := tx.ExecContext(ctx, `INSERT INTO deploy_profiles (slug, created_by, created_at) VALUES (?, ?, ?) ON CONFLICT (slug) DO NOTHING`,
		p.Slug, user, now.Unix()); err != nil {
		return Version{}, err
	}
	var last sql.NullInt64
	if err := tx.QueryRowContext(ctx, `SELECT max(version) FROM deploy_profile_versions WHERE slug = ?`, p.Slug).Scan(&last); err != nil {
		return Version{}, err
	}
	v := Version{Profile: p, Version: int(last.Int64) + 1, CreatedBy: user, CreatedAt: now, DocSHA256: hex.EncodeToString(sum[:])}
	if _, err := tx.ExecContext(ctx, `INSERT INTO deploy_profile_versions (slug, version, title, description, doc, doc_sha256, created_by, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		p.Slug, v.Version, p.Title, p.Description, string(doc), v.DocSHA256, user, now.Unix()); err != nil {
		return Version{}, err
	}
	return v, tx.Commit()
}

const versionCols = `slug, version, title, description, doc, doc_sha256, created_by, created_at`

func scanVersion(row interface{ Scan(...any) error }) (Version, error) {
	var v Version
	var doc string
	var created int64
	if err := row.Scan(&v.Profile.Slug, &v.Version, &v.Profile.Title, &v.Profile.Description, &doc, &v.DocSHA256, &v.CreatedBy, &created); err != nil {
		return Version{}, err
	}
	if err := json.Unmarshal([]byte(doc), &v.Profile); err != nil {
		return Version{}, fmt.Errorf("deployprofile: stored document: %w", err)
	}
	// The stored document must still be this version's canonical,
	// valid document: a changed database is caught here.
	if Validate(v.Profile) != nil {
		return Version{}, fmt.Errorf("deployprofile: stored version %s %d does not verify", v.Profile.Slug, v.Version)
	}
	canonical, err := v.Profile.Doc()
	if err != nil {
		return Version{}, fmt.Errorf("deployprofile: stored version %s %d does not verify: %w", v.Profile.Slug, v.Version, err)
	}
	sum := sha256.Sum256(canonical)
	if hex.EncodeToString(sum[:]) != v.DocSHA256 || string(canonical) != doc {
		return Version{}, fmt.Errorf("deployprofile: stored version %s %d does not verify", v.Profile.Slug, v.Version)
	}
	v.CreatedAt = time.Unix(created, 0)
	return v, nil
}

// Get returns one version of a profile; version 0 is the latest.
func (s *Store) Get(ctx context.Context, slug string, version int) (Version, error) {
	q := `SELECT ` + versionCols + ` FROM deploy_profile_versions WHERE slug = ? AND version = ?`
	args := []any{slug, version}
	if version == 0 {
		q = `SELECT ` + versionCols + ` FROM deploy_profile_versions WHERE slug = ? ORDER BY version DESC LIMIT 1`
		args = args[:1]
	}
	v, err := scanVersion(s.db.QueryRowContext(ctx, q, args...))
	if errors.Is(err, sql.ErrNoRows) {
		return Version{}, ErrNotFound
	}
	return v, err
}

// Latest returns the latest version of every profile, by slug.
func (s *Store) Latest(ctx context.Context) ([]Version, error) {
	return s.list(ctx, `SELECT `+versionCols+` FROM deploy_profile_versions v WHERE version = (SELECT max(version) FROM deploy_profile_versions w WHERE w.slug = v.slug) ORDER BY slug`)
}

// Versions returns every version of a profile, newest first.
func (s *Store) Versions(ctx context.Context, slug string) ([]Version, error) {
	return s.list(ctx, `SELECT `+versionCols+` FROM deploy_profile_versions WHERE slug = ? ORDER BY version DESC`, slug)
}

func (s *Store) list(ctx context.Context, q string, args ...any) ([]Version, error) {
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Version
	for rows.Next() {
		v, err := scanVersion(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

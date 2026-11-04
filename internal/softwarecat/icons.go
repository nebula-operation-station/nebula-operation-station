// SPDX-License-Identifier: AGPL-3.0-or-later

package softwarecat

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"time"
)

// maxSourceURLLen bounds a stored icon source URL.
const maxSourceURLLen = 2048

// IconSourceKind is where an icon came from.
type IconSourceKind string

// Icon source kinds (ADR 0009 D6).
const (
	// IconUpload is an admin upload.
	IconUpload IconSourceKind = "upload"
	// IconURL is a fetch from an allowlisted HTTPS host.
	IconURL IconSourceKind = "url"
)

// Icon is a reference to a sanitized icon in the content-addressed icon
// store (internal/iconstore): its SHA-256 and where it came from.
// SourceURL is kept for audit only and must never be rendered as a link
// or image source.
type Icon struct {
	SHA       string
	Kind      IconSourceKind
	SourceURL string
	AddedBy   string
	AddedAt   time.Time
}

// SubjectKind is what an icon is set on.
type SubjectKind string

// Icon subject kinds.
const (
	// SubjectCatalog is a software catalog key.
	SubjectCatalog SubjectKind = "catalog"
	// SubjectAsset is an IPAM asset (per-asset override for devices).
	SubjectAsset SubjectKind = "asset"
)

// maxAssetIDLen bounds an asset ID (as in the assets table).
const maxAssetIDLen = 63

// IconSubject names a catalog key or an asset.
type IconSubject struct {
	Kind SubjectKind
	ID   string
}

func (s IconSubject) validate() error {
	switch s.Kind {
	case SubjectCatalog:
		if _, err := NewKey(s.ID); err != nil {
			return err
		}
	case SubjectAsset:
		if !validID(s.ID, maxAssetIDLen) {
			return fmt.Errorf("asset ID: %w", ErrInvalidInput)
		}
	default:
		return fmt.Errorf("icon subject kind %q: %w", s.Kind, ErrInvalidInput)
	}
	return nil
}

// IconChange is one row of an icon history: the subject's icon changed
// from PrevSHA to SHA ("" is the generic symbol). RollbackOf is the ID
// of the change this one rolled back, 0 for an ordinary change.
// AssetDeleted marks the change that removed an asset's override
// because the asset was deleted (recorded by the database, ChangedBy
// "system"); that change and every older one belong to the deleted
// asset and cannot be rolled back.
type IconChange struct {
	ID           int64
	Subject      IconSubject
	SHA          string
	PrevSHA      string
	RollbackOf   int64
	AssetDeleted bool
	ChangedBy    string
	ChangedAt    time.Time
}

// assetDeletedMark is the rollback_of value of the history row that
// migration 0033's trigger writes when an asset with an override is
// deleted.
const assetDeletedMark = -1

// validSourceURL checks an icon source URL for storage: printable
// ASCII, bounded, absolute https with a host, without user info and
// without query string or fragment (signed or tokenized URLs carry
// their secret there, and the URL ends up in the audit detail). The URL
// is stored for audit only; the fetch policy itself is
// internal/iconfetch's.
func validSourceURL(raw string) error {
	if raw == "" || len(raw) > maxSourceURLLen {
		return fmt.Errorf("icon source URL length %d: %w", len(raw), ErrInvalidInput)
	}
	for i := 0; i < len(raw); i++ {
		if c := raw[i]; c <= ' ' || c >= 0x7f {
			return fmt.Errorf("icon source URL byte %d: %w", i, ErrInvalidInput)
		}
		if c := raw[i]; c == '?' || c == '#' {
			return fmt.Errorf("icon source URL with query string or fragment: %w", ErrInvalidInput)
		}
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("icon source URL: %w", ErrInvalidInput)
	}
	if u.Scheme != "https" || u.Host == "" || u.User != nil || u.Opaque != "" {
		return fmt.Errorf("icon source URL must be https with a host and no user info: %w", ErrInvalidInput)
	}
	return nil
}

func nullSHA(sha string) any {
	if sha == "" {
		return nil
	}
	return sha
}

// RegisterIcon records a sanitized icon (already written to the icon
// store) with its source. Registering a hash that is already known
// keeps the first record and reports false.
func (s *Store) RegisterIcon(ctx context.Context, actor string, sha string, kind IconSourceKind, sourceURL string) (bool, error) {
	if err := validActor(actor); err != nil {
		return false, err
	}
	if !validHex64(sha) {
		return false, fmt.Errorf("icon hash: %w", ErrInvalidInput)
	}
	switch kind {
	case IconUpload:
		if sourceURL != "" {
			return false, fmt.Errorf("uploaded icon with a source URL: %w", ErrInvalidInput)
		}
	case IconURL:
		if err := validSourceURL(sourceURL); err != nil {
			return false, err
		}
	default:
		return false, fmt.Errorf("icon source kind %q: %w", kind, ErrInvalidInput)
	}
	created := false
	err := s.adminChange(ctx, func(tx *sql.Tx, now time.Time) error {
		res, err := tx.ExecContext(ctx,
			`INSERT INTO software_icons (sha, source_kind, source_url, added_by, added_at) VALUES (?, ?, ?, ?, ?)
			 ON CONFLICT (sha) DO NOTHING`,
			sha, string(kind), sourceURL, actor, now.UnixNano())
		if err != nil {
			return fmt.Errorf("register icon %s: %w", sha, err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return fmt.Errorf("register icon %s: %w", sha, err)
		}
		if n == 0 {
			return nil
		}
		created = true
		detail := string(kind)
		if sourceURL != "" {
			detail += " " + sourceURL
		}
		return audit(ctx, tx, now, actor, "icon_register", sha, detail)
	})
	if err != nil {
		return false, err
	}
	return created, nil
}

// Icon returns the registered icon with hash sha.
func (s *Store) Icon(ctx context.Context, sha string) (Icon, error) {
	if !validHex64(sha) {
		return Icon{}, fmt.Errorf("icon hash: %w", ErrInvalidInput)
	}
	var ic Icon
	var kind string
	var at int64
	err := s.db.QueryRowContext(ctx,
		`SELECT sha, source_kind, source_url, added_by, added_at FROM software_icons WHERE sha = ?`, sha).
		Scan(&ic.SHA, &kind, &ic.SourceURL, &ic.AddedBy, &at)
	if errors.Is(err, sql.ErrNoRows) {
		return Icon{}, fmt.Errorf("icon %s: %w", sha, ErrNotFound)
	}
	if err != nil {
		return Icon{}, fmt.Errorf("read icon %s: %w", sha, err)
	}
	ic.Kind, ic.AddedAt = IconSourceKind(kind), time.Unix(0, at)
	return ic, nil
}

// SetIcon sets the icon of a catalog key or the override of an asset to
// the registered icon sha; "" returns the subject to the generic symbol
// (catalog) or removes the override (asset). Every effective change is
// audited and appended to the subject's icon history; setting the
// current icon again changes nothing.
func (s *Store) SetIcon(ctx context.Context, actor string, subject IconSubject, sha string) error {
	if err := validActor(actor); err != nil {
		return err
	}
	if err := subject.validate(); err != nil {
		return err
	}
	if sha != "" && !validHex64(sha) {
		return fmt.Errorf("icon hash: %w", ErrInvalidInput)
	}
	return s.adminChange(ctx, func(tx *sql.Tx, now time.Time) error {
		_, err := s.applyIcon(ctx, tx, now, actor, subject, sha, 0)
		return err
	})
}

// RollbackIcon undoes the icon change changeID of subject: the subject
// gets the icon it had before that change (one-click rollback is
// RollbackIcon with the newest change). The rollback is itself audited
// (as icon_rollback, for catalog keys and asset overrides alike) and
// appended to the history, so it can be rolled back too. This holds
// also when the subject already has the icon the rollback restores.
// For an asset, the asset must exist, and changes of an earlier asset
// with the same ID (up to and including the change that recorded its
// deletion) are not found.
func (s *Store) RollbackIcon(ctx context.Context, actor string, subject IconSubject, changeID int64) error {
	if err := validActor(actor); err != nil {
		return err
	}
	if err := subject.validate(); err != nil {
		return err
	}
	if changeID <= 0 {
		return fmt.Errorf("icon change ID: %w", ErrInvalidInput)
	}
	return s.adminChange(ctx, func(tx *sql.Tx, now time.Time) error {
		var prev sql.NullString
		var mark int64
		err := tx.QueryRowContext(ctx,
			`SELECT prev_sha, rollback_of FROM software_icon_history WHERE id = ? AND subject_kind = ? AND subject_id = ?`,
			changeID, string(subject.Kind), subject.ID).Scan(&prev, &mark)
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("icon change %d of %s %s: %w", changeID, subject.Kind, subject.ID, ErrNotFound)
		}
		if err != nil {
			return fmt.Errorf("read icon change %d: %w", changeID, err)
		}
		if subject.Kind == SubjectAsset {
			// A change at or before an asset deletion belongs to the
			// deleted asset, not to a later one with the same ID.
			var later int
			err := tx.QueryRowContext(ctx,
				`SELECT COUNT(*) FROM software_icon_history
				 WHERE subject_kind = 'asset' AND subject_id = ? AND id >= ? AND rollback_of = ?`,
				subject.ID, changeID, assetDeletedMark).Scan(&later)
			if err != nil {
				return fmt.Errorf("read icon history of asset %s: %w", subject.ID, err)
			}
			if mark == assetDeletedMark || later > 0 {
				return fmt.Errorf("icon change %d of asset %s (asset deleted since): %w", changeID, subject.ID, ErrNotFound)
			}
		}
		_, err = s.applyIcon(ctx, tx, now, actor, subject, prev.String, changeID)
		return err
	})
}

// applyIcon sets subject's icon to sha inside tx, appends the history
// row and the audit row. Setting the current icon again (rollbackOf 0)
// writes nothing; a rollback (rollbackOf > 0) is always recorded and
// audited as icon_rollback, also when it lands on the current icon. It
// reports whether a history row was written.
func (s *Store) applyIcon(ctx context.Context, tx *sql.Tx, now time.Time, actor string, subject IconSubject, sha string, rollbackOf int64) (bool, error) {
	if sha != "" {
		var one int
		err := tx.QueryRowContext(ctx, `SELECT 1 FROM software_icons WHERE sha = ?`, sha).Scan(&one)
		if errors.Is(err, sql.ErrNoRows) {
			return false, fmt.Errorf("icon %s is not registered: %w", sha, ErrNotFound)
		}
		if err != nil {
			return false, fmt.Errorf("read icon %s: %w", sha, err)
		}
	}
	ts := now.UnixNano()
	var cur string
	var action string
	switch subject.Kind {
	case SubjectCatalog:
		e, err := getEntry(ctx, tx, Key(subject.ID))
		if err != nil {
			return false, err
		}
		if e.MergedInto != "" {
			return false, fmt.Errorf("icon of %s (merged into %s): %w", subject.ID, e.MergedInto, ErrMerged)
		}
		cur = e.IconSHA
		action = "icon_set"
		if cur == sha {
			break
		}
		if _, err := tx.ExecContext(ctx,
			`UPDATE software_catalog SET icon_sha = ?, updated_by = ?, updated_at = ? WHERE key = ?`,
			nullSHA(sha), actor, ts, subject.ID); err != nil {
			return false, fmt.Errorf("set icon of %s: %w", subject.ID, err)
		}
	case SubjectAsset:
		// Setting an override and any rollback need the asset; only
		// clearing an override (a no-op for a missing asset, whose
		// override the foreign key already removed) does not.
		if sha != "" || rollbackOf > 0 {
			var one int
			err := tx.QueryRowContext(ctx, `SELECT 1 FROM assets WHERE id = ?`, subject.ID).Scan(&one)
			if errors.Is(err, sql.ErrNoRows) {
				return false, fmt.Errorf("asset %s: %w", subject.ID, ErrNotFound)
			}
			if err != nil {
				return false, fmt.Errorf("read asset %s: %w", subject.ID, err)
			}
		}
		err := tx.QueryRowContext(ctx, `SELECT icon_sha FROM asset_icon_overrides WHERE asset_id = ?`, subject.ID).Scan(&cur)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return false, fmt.Errorf("read icon override of asset %s: %w", subject.ID, err)
		}
		if cur == sha {
			break
		}
		if sha == "" {
			if _, err := tx.ExecContext(ctx, `DELETE FROM asset_icon_overrides WHERE asset_id = ?`, subject.ID); err != nil {
				return false, fmt.Errorf("clear icon override of asset %s: %w", subject.ID, err)
			}
			action = "asset_icon_clear"
		} else {
			if _, err := tx.ExecContext(ctx,
				`INSERT INTO asset_icon_overrides (asset_id, icon_sha, updated_by, updated_at) VALUES (?, ?, ?, ?)
				 ON CONFLICT (asset_id) DO UPDATE SET icon_sha = excluded.icon_sha, updated_by = excluded.updated_by, updated_at = excluded.updated_at`,
				subject.ID, sha, actor, ts); err != nil {
				return false, fmt.Errorf("set icon override of asset %s: %w", subject.ID, err)
			}
			action = "asset_icon_set"
		}
	}
	unchanged := cur == sha
	if unchanged && rollbackOf == 0 {
		// Setting the current icon again is not a change. A rollback
		// is an admin decision and is recorded even when it lands on
		// the current icon.
		return false, nil
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO software_icon_history (subject_kind, subject_id, icon_sha, prev_sha, rollback_of, changed_by, changed_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		string(subject.Kind), subject.ID, nullSHA(sha), nullSHA(cur), rollbackOf, actor, ts); err != nil {
		return false, fmt.Errorf("record icon history of %s %s: %w", subject.Kind, subject.ID, err)
	}
	detail := fmt.Sprintf("%s -> %s", orNone(cur), orNone(sha))
	if rollbackOf > 0 {
		// Rollbacks of catalog icons and of asset overrides share one
		// action; the detail names the subject kind.
		action = "icon_rollback"
		detail = fmt.Sprintf("%s: %s (rollback of change %d", subject.Kind, detail, rollbackOf)
		if unchanged {
			detail += ", no change"
		}
		detail += ")"
	}
	if err := audit(ctx, tx, now, actor, action, subject.ID, detail); err != nil {
		return false, err
	}
	return true, nil
}

func orNone(sha string) string {
	if sha == "" {
		return "none"
	}
	return sha
}

// IconHistory returns up to limit (at most MaxQueuePage) icon changes of
// subject, newest first.
func (s *Store) IconHistory(ctx context.Context, subject IconSubject, limit int) ([]IconChange, error) {
	if err := subject.validate(); err != nil {
		return nil, err
	}
	if limit <= 0 || limit > MaxQueuePage {
		limit = MaxQueuePage
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, COALESCE(icon_sha, ''), COALESCE(prev_sha, ''), rollback_of, changed_by, changed_at
		FROM software_icon_history WHERE subject_kind = ? AND subject_id = ?
		ORDER BY id DESC LIMIT ?`, string(subject.Kind), subject.ID, limit)
	if err != nil {
		return nil, fmt.Errorf("read icon history of %s %s: %w", subject.Kind, subject.ID, err)
	}
	defer func() { _ = rows.Close() }()
	var out []IconChange
	for rows.Next() {
		c := IconChange{Subject: subject}
		var at int64
		if err := rows.Scan(&c.ID, &c.SHA, &c.PrevSHA, &c.RollbackOf, &c.ChangedBy, &at); err != nil {
			return nil, fmt.Errorf("read icon history of %s %s: %w", subject.Kind, subject.ID, err)
		}
		if c.RollbackOf == assetDeletedMark {
			c.RollbackOf, c.AssetDeleted = 0, true
		}
		c.ChangedAt = time.Unix(0, at)
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read icon history of %s %s: %w", subject.Kind, subject.ID, err)
	}
	return out, nil
}

// AssetIcon returns the icon override of an asset, "" when it has none.
func (s *Store) AssetIcon(ctx context.Context, assetID string) (string, error) {
	if !validID(assetID, maxAssetIDLen) {
		return "", fmt.Errorf("asset ID: %w", ErrInvalidInput)
	}
	var sha string
	err := s.db.QueryRowContext(ctx, `SELECT icon_sha FROM asset_icon_overrides WHERE asset_id = ?`, assetID).Scan(&sha)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("read icon override of asset %s: %w", assetID, err)
	}
	return sha, nil
}

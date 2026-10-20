// SPDX-License-Identifier: AGPL-3.0-or-later

package executordb

import (
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
)

// ErrInvalid wraps every validation failure of admin-supplied data, so the
// RPC layer can report it as invalid input rather than a storage failure.
var ErrInvalid = errors.New("invalid")

// Limits on admin-supplied text.
const (
	maxLabelLen    = 200
	maxActorLen    = 64
	maxActionIDLen = 129 // CHECK in 0002_risk_floor.sql
)

// TrustedArtifact is an artifact the admin trusted for one action at a
// declared risk (H01). The executor hashed the bytes itself.
type TrustedArtifact struct {
	SHA256        string // lowercase hex
	ActionID      string
	ModuleVersion string
	Risk          canonical.Risk
	Label         string
	TrustedAt     time.Time
	TrustedBy     string
}

// HostCriticality is the criticality the executor holds for one host.
// The record is bound to the host's pinned key: it applies only to a target
// whose host_id and fingerprint both match.
type HostCriticality struct {
	HostID             string
	HostKeyFingerprint string
	Criticality        canonical.Risk
	UpdatedAt          time.Time
	UpdatedBy          string
}

// TrustArtifact records a, replacing an earlier entry for the same
// artifact, action and version. TrustedAt is set by the database.
func (db *DB) TrustArtifact(a TrustedArtifact) error {
	sum, err := parseSHA256(a.SHA256)
	if err != nil {
		return err
	}
	if !canonical.ValidActionID(a.ActionID) || len(a.ActionID) > maxActionIDLen {
		return fmt.Errorf("executordb: %w: action_id %q is malformed", ErrInvalid, a.ActionID)
	}
	if !canonical.ValidModuleVersion(a.ModuleVersion) {
		return fmt.Errorf("executordb: %w: module_version %q is malformed", ErrInvalid, a.ModuleVersion)
	}
	if a.Risk.Rank() == 0 {
		return fmt.Errorf("executordb: %w: risk %q is unknown", ErrInvalid, a.Risk)
	}
	if err := checkText("label", a.Label, maxLabelLen, true); err != nil {
		return err
	}
	if err := checkText("actor", a.TrustedBy, maxActorLen, false); err != nil {
		return err
	}
	_, err = db.sql.Exec(`INSERT INTO trusted_artifacts
		(artifact_sha256, action_id, module_version, risk, label, trusted_at, trusted_by)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(artifact_sha256, action_id, module_version) DO UPDATE SET
			risk = excluded.risk, label = excluded.label,
			trusted_at = excluded.trusted_at, trusted_by = excluded.trusted_by`,
		sum, a.ActionID, a.ModuleVersion, a.Risk.Rank(), a.Label, db.now().Unix(), a.TrustedBy)
	if err != nil {
		return fmt.Errorf("executordb: trust artifact: %w", err)
	}
	return nil
}

// UntrustArtifact removes an entry and reports whether one existed.
func (db *DB) UntrustArtifact(sha256Hex, actionID, moduleVersion string) (bool, error) {
	sum, err := parseSHA256(sha256Hex)
	if err != nil {
		return false, err
	}
	res, err := db.sql.Exec(`DELETE FROM trusted_artifacts
		WHERE artifact_sha256 = ? AND action_id = ? AND module_version = ?`, sum, actionID, moduleVersion)
	if err != nil {
		return false, fmt.Errorf("executordb: untrust artifact: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("executordb: untrust artifact: %w", err)
	}
	return n > 0, nil
}

// ListTrustedArtifacts returns all entries, ordered by action and version.
func (db *DB) ListTrustedArtifacts() ([]TrustedArtifact, error) {
	rows, err := db.sql.Query(`SELECT artifact_sha256, action_id, module_version, risk, label, trusted_at, trusted_by
		FROM trusted_artifacts ORDER BY action_id, module_version, artifact_sha256`)
	if err != nil {
		return nil, fmt.Errorf("executordb: list trusted artifacts: %w", err)
	}
	defer rows.Close()
	var out []TrustedArtifact
	for rows.Next() {
		var (
			sum  []byte
			a    TrustedArtifact
			rank int64
			at   int64
		)
		if err := rows.Scan(&sum, &a.ActionID, &a.ModuleVersion, &rank, &a.Label, &at, &a.TrustedBy); err != nil {
			return nil, fmt.Errorf("executordb: list trusted artifacts: %w", err)
		}
		if a.Risk, err = riskFromDB(rank); err != nil {
			return nil, err
		}
		a.SHA256 = hex.EncodeToString(sum)
		a.TrustedAt = time.Unix(at, 0)
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("executordb: list trusted artifacts: %w", err)
	}
	return out, nil
}

// ArtifactRisk implements riskpolicy.Source. The artifact counts as trusted
// only if it is trusted for exactly this action and version; its risk is
// then the highest risk it is trusted at under any action, because the
// server chooses the action_id it presents for the same bytes.
func (db *DB) ArtifactRisk(sha256Hex, actionID, moduleVersion string) (canonical.Risk, bool, error) {
	sum, err := parseSHA256(sha256Hex)
	if err != nil {
		return "", false, err
	}
	var rank sql.NullInt64
	err = db.sql.QueryRow(`SELECT MAX(risk) FROM trusted_artifacts WHERE artifact_sha256 = ?1
		AND EXISTS (SELECT 1 FROM trusted_artifacts
			WHERE artifact_sha256 = ?1 AND action_id = ?2 AND module_version = ?3)`,
		sum, actionID, moduleVersion).Scan(&rank)
	if err == nil && !rank.Valid {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("executordb: artifact risk: %w", err)
	}
	r, err := riskFromDB(rank.Int64)
	if err != nil {
		return "", false, err
	}
	return r, true, nil
}

// SetHostCriticality records the criticality of a host and binds it to the
// host's key fingerprint, replacing an earlier record for the host. A key
// already recorded for another host is refused. If the host has a pinned
// key (H05), the record is bound to it: an empty fingerprint means the
// pinned one, and a different fingerprint is refused. It returns the
// fingerprint the record was bound to.
func (db *DB) SetHostCriticality(hostID, fingerprint string, c canonical.Risk, by string) (string, error) {
	if !canonical.ValidHostID(hostID) {
		return "", fmt.Errorf("executordb: %w: host_id %q is malformed", ErrInvalid, hostID)
	}
	if fingerprint != "" && !canonical.ValidHostKeyFingerprint(fingerprint) {
		return "", fmt.Errorf("executordb: %w: host key fingerprint %q is malformed", ErrInvalid, fingerprint)
	}
	if c.Rank() == 0 {
		return "", fmt.Errorf("executordb: %w: criticality %q is unknown", ErrInvalid, c)
	}
	if err := checkText("actor", by, maxActorLen, false); err != nil {
		return "", err
	}
	tx, err := db.sql.Begin()
	if err != nil {
		return "", fmt.Errorf("executordb: set host criticality: %w", err)
	}
	defer func() { _ = tx.Rollback() }() // no-op after Commit
	var pinned string
	err = tx.QueryRow(`SELECT fingerprint FROM host_keys WHERE host_id = ?`, hostID).Scan(&pinned)
	switch {
	case err == nil && fingerprint == "":
		fingerprint = pinned
	case err == nil && fingerprint != pinned:
		return "", fmt.Errorf("executordb: %w: host %s is pinned to %s, not %s", ErrInvalid, hostID, pinned, fingerprint)
	case errors.Is(err, sql.ErrNoRows) && fingerprint == "":
		return "", fmt.Errorf("executordb: %w: host %s has no pinned key; give its fingerprint", ErrInvalid, hostID)
	case err != nil && !errors.Is(err, sql.ErrNoRows):
		return "", fmt.Errorf("executordb: set host criticality: %w", err)
	}
	var other string
	err = tx.QueryRow(`SELECT host_id FROM host_criticality WHERE host_key_fingerprint = ? AND host_id != ?`,
		fingerprint, hostID).Scan(&other)
	switch {
	case err == nil:
		return "", fmt.Errorf("executordb: %w: key %s is already recorded for host %s", ErrInvalid, fingerprint, other)
	case !errors.Is(err, sql.ErrNoRows):
		return "", fmt.Errorf("executordb: set host criticality: %w", err)
	}
	_, err = tx.Exec(`INSERT INTO host_criticality (host_id, host_key_fingerprint, criticality, updated_at, updated_by)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(host_id) DO UPDATE SET host_key_fingerprint = excluded.host_key_fingerprint,
			criticality = excluded.criticality, updated_at = excluded.updated_at, updated_by = excluded.updated_by`,
		hostID, fingerprint, c.Rank(), db.now().Unix(), by)
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		return "", fmt.Errorf("executordb: set host criticality: %w", err)
	}
	return fingerprint, nil
}

// ClearHostCriticality removes the record of a host (it then counts as
// HIGH) and reports whether one existed.
func (db *DB) ClearHostCriticality(hostID string) (bool, error) {
	res, err := db.sql.Exec(`DELETE FROM host_criticality WHERE host_id = ?`, hostID)
	if err != nil {
		return false, fmt.Errorf("executordb: clear host criticality: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("executordb: clear host criticality: %w", err)
	}
	return n > 0, nil
}

// HostCriticality implements riskpolicy.Source. With exact true, c is the
// criticality recorded for exactly this host ID and key. Otherwise c is the
// highest criticality of any record sharing the host ID or the key ("" if
// there is none), so a recorded host cannot be made less critical by
// presenting it under another key or name.
func (db *DB) HostCriticality(hostID, fingerprint string) (c canonical.Risk, exact bool, err error) {
	var exactRank, relatedRank sql.NullInt64
	err = db.sql.QueryRow(`SELECT
			MAX(CASE WHEN host_id = ?1 AND host_key_fingerprint = ?2 THEN criticality END),
			MAX(criticality)
		FROM host_criticality WHERE host_id = ?1 OR host_key_fingerprint = ?2`,
		hostID, fingerprint).Scan(&exactRank, &relatedRank)
	if err != nil {
		return "", false, fmt.Errorf("executordb: host criticality: %w", err)
	}
	switch {
	case exactRank.Valid:
		c, err = riskFromDB(exactRank.Int64)
		return c, err == nil, err
	case relatedRank.Valid:
		c, err = riskFromDB(relatedRank.Int64)
		return c, false, err
	default:
		return "", false, nil
	}
}

// ListHostCriticality returns all host records, ordered by host ID.
func (db *DB) ListHostCriticality() ([]HostCriticality, error) {
	rows, err := db.sql.Query(`SELECT host_id, host_key_fingerprint, criticality, updated_at, updated_by
		FROM host_criticality ORDER BY host_id`)
	if err != nil {
		return nil, fmt.Errorf("executordb: list host criticality: %w", err)
	}
	defer rows.Close()
	var out []HostCriticality
	for rows.Next() {
		var (
			h    HostCriticality
			rank int64
			at   int64
		)
		if err := rows.Scan(&h.HostID, &h.HostKeyFingerprint, &rank, &at, &h.UpdatedBy); err != nil {
			return nil, fmt.Errorf("executordb: list host criticality: %w", err)
		}
		if h.Criticality, err = riskFromDB(rank); err != nil {
			return nil, err
		}
		h.UpdatedAt = time.Unix(at, 0)
		out = append(out, h)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("executordb: list host criticality: %w", err)
	}
	return out, nil
}

func parseSHA256(s string) ([]byte, error) {
	if !canonical.ValidSHA256Hex(s) {
		return nil, fmt.Errorf("executordb: %w: artifact sha256 must be 64 lowercase hex characters", ErrInvalid)
	}
	return hex.DecodeString(s)
}

func riskFromDB(rank int64) (canonical.Risk, error) {
	r := canonical.RiskFromRank(int(rank))
	if r == "" {
		return "", fmt.Errorf("executordb: stored risk %d out of range", rank)
	}
	return r, nil
}

// checkText rejects text that could rewrite a terminal (control and bidi
// characters, invalid UTF-8) or exceeds max bytes.
// CheckLabel checks a trust label as TrustArtifact does.
func CheckLabel(label string) error { return checkText("label", label, maxLabelLen, true) }

func checkText(field, s string, max int, allowEmpty bool) error {
	if s == "" && !allowEmpty {
		return fmt.Errorf("executordb: %w: %s is required", ErrInvalid, field)
	}
	if len(s) > max {
		return fmt.Errorf("executordb: %w: %s longer than %d bytes", ErrInvalid, field, max)
	}
	if !utf8.ValidString(s) {
		return fmt.Errorf("executordb: %w: %s is not valid UTF-8", ErrInvalid, field)
	}
	for _, r := range s {
		if !unicode.IsPrint(r) { // also rejects bidi controls (category Cf)
			return fmt.Errorf("executordb: %w: %s contains a non-printable character %U", ErrInvalid, field, r)
		}
	}
	return nil
}

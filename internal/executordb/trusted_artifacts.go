// SPDX-License-Identifier: AGPL-3.0-or-later

package executordb

import (
	"database/sql"
	"encoding/hex"
	"fmt"
	"regexp"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
)

// MaxBuiltinTrustEntries bounds the trust and the retire list of one
// built-in trust commit each (ADR 0007 E16).
const MaxBuiltinTrustEntries = 4096

// builtinModuleRe is a built-in module family: the first component of its
// action IDs (canonical action ID syntax).
var builtinModuleRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

// BuiltinVersion names one version of a built-in module family.
type BuiltinVersion struct {
	// Module is the module family, the first component of its action IDs.
	Module string
	// Version is the module version.
	Version string
}

// BuiltinTrustChange is the artifact trust a committed built-in trust
// review implies (ADR 0007 E16): exact (sha256, action, version) entries
// for every action of every newly committed built-in version, and the old
// versions the admin retired.
//
// The entries are ordinary trusted_artifacts rows, the same that
// `nebula artifact trust` writes; the risk policy reads nothing else.
type BuiltinTrustChange struct {
	// Trust are the entries to record.
	Trust []TrustedArtifact
	// Retire are the module versions whose trust entries are revoked.
	Retire []BuiltinVersion
}

// CheckBuiltinTrust validates c as ApplyBuiltinTrust does, without
// writing. Callers check before committing the built-in trust store so a
// malformed tuple cannot leave the store committed without artifact trust.
func (db *DB) CheckBuiltinTrust(c BuiltinTrustChange) error {
	_, err := checkBuiltinTrust(c)
	return err
}

// ApplyBuiltinTrust records c in one transaction: first every entry of
// each retired module version is deleted (whoever trusted it), then every
// trust entry is inserted or replaced. It returns the revoked entries.
// Nothing is written if any entry is malformed.
func (db *DB) ApplyBuiltinTrust(c BuiltinTrustChange) ([]TrustedArtifact, error) {
	sums, err := checkBuiltinTrust(c)
	if err != nil {
		return nil, err
	}
	tx, err := db.sql.Begin()
	if err != nil {
		return nil, fmt.Errorf("executordb: apply built-in trust: %w", err)
	}
	defer func() { _ = tx.Rollback() }() // no-op after Commit
	var revoked []TrustedArtifact
	for _, v := range c.Retire {
		rows, err := retiredRows(tx, v)
		if err != nil {
			return nil, err
		}
		revoked = append(revoked, rows...)
		if _, err := tx.Exec(`DELETE FROM trusted_artifacts
			WHERE module_version = ?1 AND substr(action_id, 1, length(?2) + 1) = ?2 || '.'`,
			v.Version, v.Module); err != nil {
			return nil, fmt.Errorf("executordb: retire built-in %s@%s: %w", v.Module, v.Version, err)
		}
	}
	at := db.now().Unix()
	for i, a := range c.Trust {
		if _, err := tx.Exec(`INSERT INTO trusted_artifacts
			(artifact_sha256, action_id, module_version, risk, label, trusted_at, trusted_by)
			VALUES (?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(artifact_sha256, action_id, module_version) DO UPDATE SET
				risk = excluded.risk, label = excluded.label,
				trusted_at = excluded.trusted_at, trusted_by = excluded.trusted_by`,
			sums[i], a.ActionID, a.ModuleVersion, a.Risk.Rank(), a.Label, at, a.TrustedBy); err != nil {
			return nil, fmt.Errorf("executordb: trust built-in %s@%s: %w", a.ActionID, a.ModuleVersion, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("executordb: apply built-in trust: %w", err)
	}
	return revoked, nil
}

// BuiltinTrustRows returns every entry a retirement of vs would delete
// (whoever trusted it), without writing.
func (db *DB) BuiltinTrustRows(vs []BuiltinVersion) ([]TrustedArtifact, error) {
	if _, err := checkBuiltinTrust(BuiltinTrustChange{Retire: vs}); err != nil {
		return nil, err
	}
	tx, err := db.sql.Begin()
	if err != nil {
		return nil, fmt.Errorf("executordb: list built-in trust: %w", err)
	}
	defer func() { _ = tx.Rollback() }() // read-only
	var out []TrustedArtifact
	for _, v := range vs {
		rows, err := retiredRows(tx, v)
		if err != nil {
			return nil, err
		}
		out = append(out, rows...)
	}
	return out, nil
}

// retiredRows lists the entries a retirement of v deletes, ordered by
// action and artifact.
func retiredRows(tx *sql.Tx, v BuiltinVersion) ([]TrustedArtifact, error) {
	rows, err := tx.Query(`SELECT artifact_sha256, action_id, module_version, risk, label, trusted_at, trusted_by
		FROM trusted_artifacts WHERE module_version = ?1 AND substr(action_id, 1, length(?2) + 1) = ?2 || '.'
		ORDER BY action_id, artifact_sha256`, v.Version, v.Module)
	if err != nil {
		return nil, fmt.Errorf("executordb: retire built-in %s@%s: %w", v.Module, v.Version, err)
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
			return nil, fmt.Errorf("executordb: retire built-in %s@%s: %w", v.Module, v.Version, err)
		}
		if a.Risk, err = riskFromDB(rank); err != nil {
			return nil, err
		}
		a.SHA256 = hex.EncodeToString(sum)
		a.TrustedAt = time.Unix(at, 0)
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("executordb: retire built-in %s@%s: %w", v.Module, v.Version, err)
	}
	return out, nil
}

// checkBuiltinTrust validates every entry as TrustArtifact does and every
// retirement, and returns the decoded artifact hashes.
func checkBuiltinTrust(c BuiltinTrustChange) ([][]byte, error) {
	if len(c.Trust) > MaxBuiltinTrustEntries || len(c.Retire) > MaxBuiltinTrustEntries {
		return nil, fmt.Errorf("executordb: %w: at most %d built-in trust entries and retirements", ErrInvalid, MaxBuiltinTrustEntries)
	}
	for _, v := range c.Retire {
		if !builtinModuleRe.MatchString(v.Module) || !canonical.ValidModuleVersion(v.Version) {
			return nil, fmt.Errorf("executordb: %w: retired built-in %q@%q is malformed", ErrInvalid, v.Module, v.Version)
		}
	}
	sums := make([][]byte, len(c.Trust))
	for i, a := range c.Trust {
		sum, err := parseSHA256(a.SHA256)
		if err != nil {
			return nil, err
		}
		if !canonical.ValidActionID(a.ActionID) || len(a.ActionID) > maxActionIDLen {
			return nil, fmt.Errorf("executordb: %w: action_id %q is malformed", ErrInvalid, a.ActionID)
		}
		if !canonical.ValidModuleVersion(a.ModuleVersion) {
			return nil, fmt.Errorf("executordb: %w: module_version %q is malformed", ErrInvalid, a.ModuleVersion)
		}
		if a.Risk.Rank() == 0 {
			return nil, fmt.Errorf("executordb: %w: risk %q is unknown", ErrInvalid, a.Risk)
		}
		if err := checkText("label", a.Label, maxLabelLen, true); err != nil {
			return nil, err
		}
		if err := checkText("actor", a.TrustedBy, maxActorLen, false); err != nil {
			return nil, err
		}
		sums[i] = sum
	}
	return sums, nil
}

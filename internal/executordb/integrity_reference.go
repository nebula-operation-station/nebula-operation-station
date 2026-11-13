// SPDX-License-Identifier: AGPL-3.0-or-later

package executordb

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/release"
)

// Integrity reference errors callers branch on.
var (
	// ErrNoIntegrityReference: no installed-files reference was admitted.
	ErrNoIntegrityReference = errors.New("executordb: no admitted integrity reference")
	// ErrReferenceRollback: the release version is lower than the
	// active admitted one (ADR 0015 D4 rollback rule).
	ErrReferenceRollback = errors.New("executordb: integrity reference has a lower release version than the admitted one")
	// ErrReferenceConflict: a different manifest for a release version
	// that was already admitted (ADR 0015 D2: two validly signed
	// manifests for one version are an alarm).
	ErrReferenceConflict = errors.New("executordb: a different manifest was already admitted for this release version")
)

// maxSignedByLen bounds the stored root ID (CHECK in
// 0027_integrity_references.sql).
const maxSignedByLen = 128

// IntegrityReference is an installed-files reference admitted by the
// executor: the exact bytes of release-manifest.json, its signature and
// installed-files.json, after the executor verified them with
// integrity.Admit against its durable root state. The store checks
// formats, limits and that the digests match the bytes; it does not
// verify signatures, so callers must only pass verified bytes and must
// re-verify what they read back before relying on it.
type IntegrityReference struct {
	ReleaseVersion string
	Manifest       []byte
	Signature      []byte
	List           []byte
	// ManifestSHA256 and ListSHA256 are lowercase hex SHA-256 of
	// Manifest and List.
	ManifestSHA256 string
	ListSHA256     string
	// SignedBy is the ID of the release root that signed the manifest.
	SignedBy string
	// AdmittedAt, Active and SupersededAt are set by the store.
	AdmittedAt   time.Time
	Active       bool
	SupersededAt time.Time
}

func (r IntegrityReference) validate() error {
	if !release.ValidReleaseVersion(r.ReleaseVersion) {
		return fmt.Errorf("executordb: %w: integrity reference release version is malformed", ErrInvalid)
	}
	if err := checkBlob("manifest", r.Manifest, release.MaxManifest); err != nil {
		return err
	}
	if err := checkBlob("signature", r.Signature, release.MaxSignature); err != nil {
		return err
	}
	if err := checkBlob("installed-files list", r.List, release.MaxInstalledFilesDocument); err != nil {
		return err
	}
	if !digestMatches(r.Manifest, r.ManifestSHA256) {
		return fmt.Errorf("executordb: %w: manifest digest does not match its bytes", ErrInvalid)
	}
	if !digestMatches(r.List, r.ListSHA256) {
		return fmt.Errorf("executordb: %w: installed-files digest does not match its bytes", ErrInvalid)
	}
	return checkText("signed_by", r.SignedBy, maxSignedByLen, false)
}

func checkBlob(field string, b []byte, max int) error {
	if len(b) == 0 || len(b) > max {
		return fmt.Errorf("executordb: %w: %s must be 1 to %d bytes", ErrInvalid, field, max)
	}
	return nil
}

func digestMatches(b []byte, sum string) bool {
	s := sha256.Sum256(b)
	return sum == hex.EncodeToString(s[:])
}

// AdmitIntegrityReference stores r as the active reference and keeps the
// previous one as history, in one transaction. It returns false and no
// error if r's manifest is already the active one (a restart). A lower
// release version than the active one is ErrReferenceRollback; another
// manifest for an already admitted release version (equal SemVer
// precedence) is ErrReferenceConflict. Neither changes the stored state.
func (db *DB) AdmitIntegrityReference(r IntegrityReference) (bool, error) {
	if err := r.validate(); err != nil {
		return false, err
	}
	tx, err := db.sql.Begin()
	if err != nil {
		return false, fmt.Errorf("executordb: admit integrity reference: %w", err)
	}
	defer tx.Rollback()

	var activeVersion, activeManifest, activeList string
	err = tx.QueryRow(`SELECT release_version, manifest_sha256, list_sha256
		FROM integrity_references WHERE active = 1`).Scan(&activeVersion, &activeManifest, &activeList)
	switch {
	case errors.Is(err, sql.ErrNoRows):
	case err != nil:
		return false, fmt.Errorf("executordb: read active integrity reference: %w", err)
	default:
		if activeManifest == r.ManifestSHA256 {
			if activeList != r.ListSHA256 || activeVersion != r.ReleaseVersion {
				return false, fmt.Errorf("%w: %s", ErrReferenceConflict, r.ReleaseVersion)
			}
			return false, nil
		}
		switch c := compareReleaseVersion(r.ReleaseVersion, activeVersion); {
		case c < 0:
			return false, fmt.Errorf("%w: %s is lower than %s", ErrReferenceRollback, r.ReleaseVersion, activeVersion)
		case c == 0:
			return false, fmt.Errorf("%w: %s", ErrReferenceConflict, r.ReleaseVersion)
		}
	}
	// A superseded manifest for the same version is a conflict too (the
	// rule above already implies it while history stays ordered).
	var n int
	if err := tx.QueryRow(`SELECT count(*) FROM integrity_references
		WHERE release_version = ? AND manifest_sha256 <> ?`, r.ReleaseVersion, r.ManifestSHA256).Scan(&n); err != nil {
		return false, fmt.Errorf("executordb: read integrity reference history: %w", err)
	}
	if n > 0 {
		return false, fmt.Errorf("%w: %s", ErrReferenceConflict, r.ReleaseVersion)
	}
	now := db.now().Unix()
	if _, err := tx.Exec(`UPDATE integrity_references SET active = 0, superseded_at = ? WHERE active = 1`, now); err != nil {
		return false, fmt.Errorf("executordb: supersede integrity reference: %w", err)
	}
	if _, err := tx.Exec(`INSERT INTO integrity_references
		(release_version, manifest, signature, list, manifest_sha256, list_sha256, signed_by, admitted_at, active)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)`,
		r.ReleaseVersion, r.Manifest, r.Signature, r.List, r.ManifestSHA256, r.ListSHA256, r.SignedBy, now); err != nil {
		return false, fmt.Errorf("executordb: insert integrity reference: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("executordb: admit integrity reference: %w", err)
	}
	return true, nil
}

// ActiveIntegrityReference returns the active admitted reference, or
// ErrNoIntegrityReference. The bytes are what was admitted; the caller
// re-verifies them before use.
func (db *DB) ActiveIntegrityReference() (IntegrityReference, error) {
	var r IntegrityReference
	var at int64
	err := db.sql.QueryRow(`SELECT release_version, manifest, signature, list, manifest_sha256,
		list_sha256, signed_by, admitted_at FROM integrity_references WHERE active = 1`).Scan(
		&r.ReleaseVersion, &r.Manifest, &r.Signature, &r.List, &r.ManifestSHA256, &r.ListSHA256, &r.SignedBy, &at)
	if errors.Is(err, sql.ErrNoRows) {
		return IntegrityReference{}, ErrNoIntegrityReference
	}
	if err != nil {
		return IntegrityReference{}, fmt.Errorf("executordb: read integrity reference: %w", err)
	}
	r.AdmittedAt = time.Unix(at, 0).UTC()
	r.Active = true
	// A row that no longer matches its digests is not returned.
	if err := r.validate(); err != nil {
		return IntegrityReference{}, fmt.Errorf("executordb: stored integrity reference: %w", err)
	}
	return r, nil
}

// compareReleaseVersion orders two valid release versions by SemVer 2.0.0
// precedence (build metadata ignored): -1, 0 or 1.
func compareReleaseVersion(a, b string) int {
	a, _, _ = strings.Cut(a, "+")
	b, _, _ = strings.Cut(b, "+")
	ac, ap, aHasPre := strings.Cut(a, "-")
	bc, bp, bHasPre := strings.Cut(b, "-")
	if c := compareDotted(ac, bc, true); c != 0 {
		return c
	}
	switch {
	case !aHasPre && !bHasPre:
		return 0
	case !aHasPre:
		return 1
	case !bHasPre:
		return -1
	}
	return compareDotted(ap, bp, false)
}

// compareDotted compares dot-separated identifiers. Core components are
// numeric; prerelease identifiers compare numerically when both are
// numeric, numeric ones sort before alphanumeric ones, and a shorter list
// that is a prefix sorts first.
func compareDotted(a, b string, core bool) int {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(as) && i < len(bs); i++ {
		aNum, bNum := core || isDigits(as[i]), core || isDigits(bs[i])
		switch {
		case aNum && bNum:
			// No leading zeros (ValidReleaseVersion), so the longer
			// number is the larger one; no integer parsing, no overflow.
			if c := cmpInt(len(as[i]), len(bs[i])); c != 0 {
				return c
			}
			if c := strings.Compare(as[i], bs[i]); c != 0 {
				return c
			}
		case aNum:
			return -1
		case bNum:
			return 1
		default:
			if c := strings.Compare(as[i], bs[i]); c != 0 {
				return c
			}
		}
	}
	return cmpInt(len(as), len(bs))
}

func isDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return s != ""
}

func cmpInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

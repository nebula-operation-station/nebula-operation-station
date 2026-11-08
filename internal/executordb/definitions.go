// SPDX-License-Identifier: AGPL-3.0-or-later

package executordb

import (
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Standalone container definitions (ADR 0006 P2-03, container update plan
// cu05, storage part).
//
// The content of a definition holds env values and is secret: it lives
// only in the executor vault, one vault secret per version with the ID
// ContainerDefinitionSecretID(definition_id, version). This table holds
// metadata only, never the content and never a digest of it. Each version
// is written once, together with its vault secret in one transaction, and
// never replaced. A version is dropped (row and vault secret together)
// only while no container recreation inside its rollback window references
// it.

// ContainerDefinitionSecretPrefix starts every vault secret ID that holds a
// container definition. Only this file writes or deletes such secrets.
const ContainerDefinitionSecretPrefix = "ctrdef."

// Container definition limits.
const (
	// MaxContainerDefinitionVersion is the highest version number; it is
	// the largest integer the batch canonical form binds exactly (2^53-1).
	MaxContainerDefinitionVersion = 1<<53 - 1
	// MaxContainerDefinitionVersionsKept bounds the stored versions of one
	// definition; drop an older one before adding more.
	MaxContainerDefinitionVersionsKept = 32
	// MaxContainerDefinitions bounds the distinct definitions (host and
	// container name pairs) of one executor.
	MaxContainerDefinitions = 1024
	// maxDefinitionSecretID is the vault's secret ID limit.
	maxDefinitionSecretID = 64
	// maxDefinitionHostID and maxDefinitionContainerName repeat the table.
	maxDefinitionHostID        = 255
	maxDefinitionContainerName = 128
	// maxDefinitionsListed bounds one list answer: every kept version of
	// every definition.
	maxDefinitionsListed = MaxContainerDefinitions * MaxContainerDefinitionVersionsKept
)

var (
	// ErrNoContainerDefinition means no definition (or no such version)
	// exists for the host and container name.
	ErrNoContainerDefinition = errors.New("executordb: no container definition")
	// ErrDefinitionInWindow means a container recreation inside its
	// rollback window (or still in intent) references the version, so it
	// must be kept.
	ErrDefinitionInWindow = errors.New("executordb: a container recreation inside its rollback window references the definition")
	// ErrDefinitionLimit means a definition or version limit is reached.
	ErrDefinitionLimit = errors.New("executordb: container definition limit reached")
	// ErrDefinitionLatest means the current (newest) version cannot be
	// dropped on its own; remove the whole definition instead.
	ErrDefinitionLatest = errors.New("executordb: the newest definition version cannot be dropped alone")
	// ErrDefinitionExists means the version or its vault secret already
	// exists: a version is written once and never replaced.
	ErrDefinitionExists = errors.New("executordb: container definition version already exists")
)

var definitionIDRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// ContainerDefinition is the metadata of one stored definition version.
// It never carries the content.
type ContainerDefinition struct {
	HostID        string
	ContainerName string
	// DefinitionID is the random UUID of the host and container name.
	DefinitionID string
	Version      uint64
	// VaultSecretID is ContainerDefinitionSecretID(DefinitionID, Version).
	VaultSecretID string
	CreatedBy     string
	CreatedAt     time.Time
}

// ValidContainerDefinitionID reports whether id is a lowercase UUID.
func ValidContainerDefinitionID(id string) bool { return definitionIDRe.MatchString(id) }

// ContainerDefinitionSecretID returns the vault secret ID of one version.
func ContainerDefinitionSecretID(definitionID string, version uint64) string {
	return ContainerDefinitionSecretPrefix + definitionID + "." + strconv.FormatUint(version, 10)
}

func checkDefinitionUnit(hostID, name string) error {
	if hostID == "" || len(hostID) > maxDefinitionHostID || name == "" || len(name) > maxDefinitionContainerName {
		return fmt.Errorf("executordb: container definition: malformed host or container name")
	}
	return nil
}

func (d ContainerDefinition) check() error {
	if err := checkDefinitionUnit(d.HostID, d.ContainerName); err != nil {
		return err
	}
	if !ValidContainerDefinitionID(d.DefinitionID) || d.Version < 1 || d.Version > MaxContainerDefinitionVersion {
		return fmt.Errorf("executordb: container definition: malformed identity")
	}
	id := ContainerDefinitionSecretID(d.DefinitionID, d.Version)
	if d.VaultSecretID != id || len(id) > maxDefinitionSecretID {
		return fmt.Errorf("executordb: container definition: vault secret ID does not match")
	}
	return checkText("created_by", d.CreatedBy, maxActorLen, false)
}

type definitionQuerier interface {
	QueryRow(string, ...any) *sql.Row
}

// nextDefinition returns the identity the next version of hostID/name
// gets: the existing definition ID and the newest version plus one, or
// newID and version 1 when none exists. It also returns how many versions
// are kept.
func nextDefinition(q definitionQuerier, hostID, name, newID string) (string, uint64, int, error) {
	var id sql.NullString
	var newest sql.NullInt64
	var kept int
	err := q.QueryRow(`SELECT MIN(definition_id), MAX(version), COUNT(*) FROM container_definitions
		WHERE host_id = ? AND container_name = ?`, hostID, name).Scan(&id, &newest, &kept)
	if err != nil {
		return "", 0, 0, fmt.Errorf("executordb: container definition %s/%s: %w", hostID, name, err)
	}
	if !id.Valid {
		return newID, 1, 0, nil
	}
	return id.String, uint64(newest.Int64) + 1, kept, nil
}

// NextContainerDefinition returns the metadata the next version of
// hostID/name would get (definition ID, version and vault secret ID; the
// caller fills CreatedBy). A first version takes newID, which must be a
// fresh random UUID. AddContainerDefinition rechecks it atomically.
func (db *DB) NextContainerDefinition(hostID, name, newID string) (ContainerDefinition, error) {
	if err := checkDefinitionUnit(hostID, name); err != nil {
		return ContainerDefinition{}, err
	}
	if !ValidContainerDefinitionID(newID) {
		return ContainerDefinition{}, fmt.Errorf("executordb: container definition: malformed new definition ID")
	}
	id, version, _, err := nextDefinition(db.sql, hostID, name, newID)
	if err != nil {
		return ContainerDefinition{}, err
	}
	if version > MaxContainerDefinitionVersion {
		return ContainerDefinition{}, fmt.Errorf("%w: version numbers exhausted", ErrDefinitionLimit)
	}
	return ContainerDefinition{HostID: hostID, ContainerName: name, DefinitionID: id, Version: version,
		VaultSecretID: ContainerDefinitionSecretID(id, version)}, nil
}

// AddContainerDefinition stores one new version: the encrypted vault
// secret and the metadata row in one transaction. d must still be what
// NextContainerDefinition returned (a concurrent Put gives
// ErrSecretVersion) and secret must be the first version of d's vault
// secret ID (an existing secret is never replaced: ErrDefinitionExists).
// Earlier versions are kept.
func (db *DB) AddContainerDefinition(d ContainerDefinition, secret VaultSecret) error {
	if err := d.check(); err != nil {
		return err
	}
	if secret.ID != d.VaultSecretID {
		return fmt.Errorf("executordb: container definition: vault secret ID does not match")
	}
	if secret.Version != 1 {
		return ErrDefinitionExists
	}
	tx, err := db.sql.Begin()
	if err != nil {
		return fmt.Errorf("executordb: add container definition: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	id, version, kept, err := nextDefinition(tx, d.HostID, d.ContainerName, d.DefinitionID)
	if err != nil {
		return err
	}
	if id != d.DefinitionID || version != d.Version {
		return ErrSecretVersion
	}
	if kept >= MaxContainerDefinitionVersionsKept {
		return fmt.Errorf("%w: at most %d kept versions per container", ErrDefinitionLimit, MaxContainerDefinitionVersionsKept)
	}
	if kept == 0 {
		var defs int
		if err := tx.QueryRow(`SELECT COUNT(DISTINCT definition_id) FROM container_definitions`).Scan(&defs); err != nil {
			return fmt.Errorf("executordb: add container definition: %w", err)
		}
		if defs >= MaxContainerDefinitions {
			return fmt.Errorf("%w: at most %d container definitions", ErrDefinitionLimit, MaxContainerDefinitions)
		}
	}
	now := db.now().Truncate(time.Second)
	if err := putSecret(tx, secret, now); err != nil {
		if errors.Is(err, ErrSecretVersion) {
			return ErrDefinitionExists
		}
		return err
	}
	if _, err := tx.Exec(`INSERT INTO container_definitions (host_id, container_name, definition_id, version,
		vault_secret_id, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		d.HostID, d.ContainerName, d.DefinitionID, int64(d.Version), d.VaultSecretID, d.CreatedBy, now.Unix()); err != nil {
		return fmt.Errorf("executordb: add container definition %s/%s: %w", d.HostID, d.ContainerName, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("executordb: add container definition: %w", err)
	}
	return nil
}

// definitionInWindow reports whether a container recreation that is still
// in intent or inside its rollback window references definitionID at
// version (0: any version). The recreation definition of a standalone row
// names the version (definition_id, definition_version).
func definitionInWindow(q definitionQuerier, definitionID string, version uint64, now time.Time) (bool, error) {
	var n int
	err := q.QueryRow(`SELECT COUNT(*) FROM container_recreations
		WHERE json_extract(definition, '$.definition_id') = ?
		AND (? = 0 OR json_extract(definition, '$.definition_version') = ?)
		AND (state = 'intent' OR window_expires_at = 0 OR window_expires_at > ?)`,
		definitionID, int64(version), int64(version), now.Unix()).Scan(&n)
	if err != nil {
		return false, fmt.Errorf("executordb: container definition window check: %w", err)
	}
	return n > 0, nil
}

// RemoveContainerDefinition drops stored versions of hostID/name together
// with their vault secrets, in one transaction: every version when version
// is 0, otherwise that one version, which must not be the newest
// (ErrDefinitionLatest). It is refused with ErrDefinitionInWindow while a
// container recreation in intent or inside its rollback window references
// a version it would drop. It returns the dropped versions.
//
// A locked executor must not lose secrets, like a vault delete: after
// deleting the rows and secrets and right before committing, the
// transaction calls vaultUnlocked, and any error from it rolls everything
// back and is returned. So a vault lock that lands after the caller's own
// check still removes nothing. A nil vaultUnlocked is refused.
// vaultUnlocked runs while the transaction holds the only database
// connection, so it must not use the database.
func (db *DB) RemoveContainerDefinition(hostID, name string, version uint64, vaultUnlocked func() error) ([]ContainerDefinition, error) {
	if err := checkDefinitionUnit(hostID, name); err != nil {
		return nil, err
	}
	if vaultUnlocked == nil {
		return nil, fmt.Errorf("executordb: remove container definition: no vault check")
	}
	tx, err := db.sql.Begin()
	if err != nil {
		return nil, fmt.Errorf("executordb: remove container definition: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	versions, err := queryDefinitions(tx, `WHERE host_id = ? AND container_name = ? ORDER BY version`, hostID, name)
	if err != nil {
		return nil, err
	}
	if len(versions) == 0 {
		return nil, ErrNoContainerDefinition
	}
	drop := versions
	if version != 0 {
		drop = nil
		for _, v := range versions {
			if v.Version == version {
				drop = []ContainerDefinition{v}
			}
		}
		if drop == nil {
			return nil, ErrNoContainerDefinition
		}
		if version == versions[len(versions)-1].Version {
			return nil, ErrDefinitionLatest
		}
	}
	inWindow, err := definitionInWindow(tx, versions[0].DefinitionID, version, db.now())
	if err != nil {
		return nil, err
	}
	if inWindow {
		return nil, ErrDefinitionInWindow
	}
	for _, d := range drop {
		if _, err := tx.Exec(`DELETE FROM vault_secrets WHERE id = ?`, d.VaultSecretID); err != nil {
			return nil, fmt.Errorf("executordb: remove container definition secret: %w", err)
		}
		if _, err := tx.Exec(`DELETE FROM container_definitions WHERE definition_id = ? AND version = ?`,
			d.DefinitionID, int64(d.Version)); err != nil {
			return nil, fmt.Errorf("executordb: remove container definition: %w", err)
		}
	}
	// The last step before the commit: the deferred rollback keeps every
	// secret if the vault was locked meanwhile.
	if err := vaultUnlocked(); err != nil {
		return nil, fmt.Errorf("executordb: remove container definition: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("executordb: remove container definition: %w", err)
	}
	return drop, nil
}

// ContainerDefinitionVersions returns the kept versions of hostID/name,
// oldest first (ErrNoContainerDefinition when there are none).
func (db *DB) ContainerDefinitionVersions(hostID, name string) ([]ContainerDefinition, error) {
	if err := checkDefinitionUnit(hostID, name); err != nil {
		return nil, err
	}
	out, err := queryDefinitions(db.sql, `WHERE host_id = ? AND container_name = ? ORDER BY version`, hostID, name)
	if err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, ErrNoContainerDefinition
	}
	return out, nil
}

// ListContainerDefinitions returns the metadata of every kept version, of
// one host or (empty hostID) of all hosts, ordered by host, container name
// and version. It never returns content.
func (db *DB) ListContainerDefinitions(hostID string) ([]ContainerDefinition, error) {
	if len(hostID) > maxDefinitionHostID {
		return nil, fmt.Errorf("executordb: list container definitions: malformed host")
	}
	return queryDefinitions(db.sql, `WHERE ? = '' OR host_id = ? ORDER BY host_id, container_name, version LIMIT `+
		strconv.Itoa(maxDefinitionsListed), hostID, hostID)
}

type definitionRows interface {
	Query(string, ...any) (*sql.Rows, error)
}

func queryDefinitions(q definitionRows, where string, args ...any) ([]ContainerDefinition, error) {
	rows, err := q.Query(`SELECT host_id, container_name, definition_id, version, vault_secret_id, created_by, created_at
		FROM container_definitions `+where, args...)
	if err != nil {
		return nil, fmt.Errorf("executordb: container definitions: %w", err)
	}
	defer rows.Close()
	var out []ContainerDefinition
	for rows.Next() {
		var d ContainerDefinition
		var version, at int64
		if err := rows.Scan(&d.HostID, &d.ContainerName, &d.DefinitionID, &version, &d.VaultSecretID, &d.CreatedBy, &at); err != nil {
			return nil, fmt.Errorf("executordb: container definitions: %w", err)
		}
		d.Version, d.CreatedAt = uint64(version), time.Unix(at, 0)
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("executordb: container definitions: %w", err)
	}
	return out, nil
}

// IsContainerDefinitionSecretID reports whether a vault secret ID belongs
// to the container definition store, which alone may write or delete it.
func IsContainerDefinitionSecretID(id string) bool {
	return strings.HasPrefix(id, ContainerDefinitionSecretPrefix)
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package executordb

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

// Container recreation records (ADR 0006 P2-04, container update plan cu03).
//
// One row per container update or rollback member run. It is written in
// state intent before the job is dispatched, completed exactly once from
// the run (Complete), and afterwards changes only by a resolve of an
// uncertain row or by a successful rollback. The baseline is never
// overwritten and the rollback window's expiry is set once, when the row
// first leaves intent. Rows are never deleted.

// Recreation states.
const (
	RecreationIntent       = "intent"
	RecreationNotRecreated = "not_recreated"
	RecreationRecreated    = "recreated"
	RecreationPartial      = "partial"
	RecreationUncertain    = "uncertain"
	RecreationRolledBack   = "rolled_back"
)

// Per-container statuses in a completed row.
const (
	ContainerRecreated = "recreated"
	ContainerUnchanged = "unchanged"
	ContainerMissing   = "missing"
)

// Limits enforced on every recreation row (the table repeats them).
const (
	maxRecreationJSON       = 128 << 10
	maxRecreationContainers = 256 << 10
	maxRecreationBaseline   = 512 << 10
	maxRecreationVerdict    = 64 << 10
	maxRecreationUnit       = 255
	maxRecreationHostKey    = 512
	// maxRecreationsListed bounds one ListContainerRecreations answer.
	maxRecreationsListed = 500
	// maxRecoveryReference bounds a recovery plan's free-text reference.
	maxRecoveryReference = 2048
)

// Column limits a caller checks before completing a row, so a record that
// cannot fit is left out deliberately instead of failing the completion.
const (
	// MaxRecreationBaselineBytes bounds a completion's baseline.
	MaxRecreationBaselineBytes = maxRecreationBaseline
	// MaxRecreationContainersBytes bounds a completion's containers, as JSON.
	MaxRecreationContainersBytes = maxRecreationContainers
)

var (
	// ErrNoRecreation means no recreation row exists for the execution.
	ErrNoRecreation = errors.New("executordb: no container recreation")
	// ErrRecreationState means the row is not in the state the change
	// requires (a completed row is never completed again, a rollback
	// source only leaves recreated or partial).
	ErrRecreationState = errors.New("executordb: container recreation is not in the required state")
	// ErrNoRecoveryPlan means no recovery plan is recorded for the unit.
	ErrNoRecoveryPlan = errors.New("executordb: no recovery plan recorded")
)

// RecreationImage is one bound image of a row: what the update moved to
// and what a rollback returns to.
type RecreationImage struct {
	Service    string `json:"service"`
	Repository string `json:"repository"`
	OldTag     string `json:"old_tag"`
	NewTag     string `json:"new_tag"`
	// NewPlatformDigest is the approved digest of an update ('' on a
	// rollback, which pulls nothing).
	NewPlatformDigest string `json:"new_platform_digest,omitempty"`
	// PriorImageID is the image the update replaced and retained.
	PriorImageID string `json:"prior_image_id"`
	// RetainedTag is nos-retained:<execution-id>-<entry-index>; it is set
	// from intent on, because the script derives it from the same values.
	RetainedTag string `json:"retained_tag"`
	// RetainedReference is repository:old_tag@<first old digest>.
	RetainedReference string `json:"retained_reference"`
	// NewImageID is the pulled image the result reports ('' until then).
	NewImageID string `json:"new_image_id,omitempty"`
}

// RecreationContainer is one container of a completed row, matched by
// service and replica number across the recreate.
type RecreationContainer struct {
	Service         string `json:"service"`
	Replica         string `json:"replica"`
	Name            string `json:"name"`
	IDBefore        string `json:"id_before"`
	IDAfter         string `json:"id_after,omitempty"`
	ReferenceBefore string `json:"reference_before"`
	ReferenceAfter  string `json:"reference_after,omitempty"`
	ConfigBefore    string `json:"configuration_digest_before"`
	ConfigAfter     string `json:"configuration_digest_after,omitempty"`
	ImageBefore     string `json:"image_id_before"`
	ImageAfter      string `json:"image_id_after,omitempty"`
	Status          string `json:"status"`
}

// RecreationVerdict is the executor's postcheck verdict of a row.
type RecreationVerdict struct {
	Judged   bool     `json:"judged"`
	Passed   bool     `json:"passed"`
	Findings []string `json:"findings"`
}

// ContainerRecreation is one row.
type ContainerRecreation struct {
	ExecutionID, BatchDigest, MemberID string
	Kind, RollbackOf                   string
	HostID, HostKey                    string
	Form, Unit                         string
	// Binding is the member's frozen update binding as canonical JSON.
	Binding []byte
	// Definition is the executor-owned recreation definition (JSON).
	Definition []byte
	Images     []RecreationImage
	Containers []RecreationContainer
	// Baseline is the phase 1 snapshot as reported (a JSON array); empty
	// while no result with a baseline was read.
	Baseline        []byte
	Verdict         RecreationVerdict
	State           string
	WindowExpiresAt time.Time
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// RecreationCompletion is what a finished run adds to its intent row.
type RecreationCompletion struct {
	State      string
	Images     []RecreationImage
	Containers []RecreationContainer
	Baseline   []byte
	Verdict    RecreationVerdict
}

func checkJSON(name string, b []byte, limit int) error {
	if len(b) < 2 || len(b) > limit || !utf8.Valid(b) || !json.Valid(b) {
		return fmt.Errorf("executordb: recreation %s is not bounded JSON", name)
	}
	return nil
}

func marshalBounded(name string, v any, limit int) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("executordb: encode recreation %s: %w", name, err)
	}
	if len(b) > limit {
		return "", fmt.Errorf("executordb: recreation %s over %d bytes", name, limit)
	}
	return string(b), nil
}

// CreateContainerRecreation writes the intent row of a container member
// run before it is dispatched. An existing row for the execution is an
// error: an execution ID is single-use.
func (db *DB) CreateContainerRecreation(r ContainerRecreation) error {
	if len(r.ExecutionID) != 36 || len(r.BatchDigest) != 64 || r.MemberID == "" || r.HostID == "" ||
		len(r.Unit) > maxRecreationUnit || len(r.HostKey) > maxRecreationHostKey {
		return fmt.Errorf("executordb: create recreation %s: malformed identity", r.ExecutionID)
	}
	if err := checkJSON("binding", r.Binding, maxRecreationJSON); err != nil {
		return err
	}
	if err := checkJSON("definition", r.Definition, maxRecreationJSON); err != nil {
		return err
	}
	images, err := marshalBounded("images", nonNilImages(r.Images), maxRecreationJSON)
	if err != nil {
		return err
	}
	now := db.now().Unix()
	_, err = db.sql.Exec(`INSERT INTO container_recreations (execution_id, batch_digest, member_id, kind, rollback_of,
		host_id, host_key, form, unit, binding, definition, images, state, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'intent', ?, ?)`,
		r.ExecutionID, r.BatchDigest, r.MemberID, r.Kind, r.RollbackOf, r.HostID, r.HostKey, r.Form, r.Unit,
		string(r.Binding), string(r.Definition), images, now, now)
	if err != nil {
		return fmt.Errorf("executordb: create recreation %s: %w", r.ExecutionID, err)
	}
	return nil
}

func nonNilImages(v []RecreationImage) []RecreationImage {
	if v == nil {
		return []RecreationImage{}
	}
	return v
}

func nonNilContainers(v []RecreationContainer) []RecreationContainer {
	if v == nil {
		return []RecreationContainer{}
	}
	return v
}

// CompleteContainerRecreation completes an intent row exactly once: it
// stores the state, images, containers and verdict, the baseline if the
// row has none yet (a baseline is never overwritten), and the rollback
// window's expiry, now plus window, which is never set again. A row that
// already left intent is refused with ErrRecreationState.
func (db *DB) CompleteContainerRecreation(executionID string, c RecreationCompletion, now time.Time, window time.Duration) error {
	switch c.State {
	case RecreationNotRecreated, RecreationRecreated, RecreationPartial, RecreationUncertain:
	default:
		return fmt.Errorf("executordb: complete recreation %s: state %q is not a completion", executionID, c.State)
	}
	if len(c.Baseline) > 0 {
		if err := checkJSON("baseline", c.Baseline, maxRecreationBaseline); err != nil {
			return err
		}
	}
	// No images in the completion keeps the intent row's images.
	images := ""
	if c.Images != nil {
		var err error
		if images, err = marshalBounded("images", c.Images, maxRecreationJSON); err != nil {
			return err
		}
	}
	containers, err := marshalBounded("containers", nonNilContainers(c.Containers), maxRecreationContainers)
	if err != nil {
		return err
	}
	if c.Verdict.Findings == nil {
		c.Verdict.Findings = []string{}
	}
	verdict, err := marshalBounded("verdict", c.Verdict, maxRecreationVerdict)
	if err != nil {
		return err
	}
	res, err := db.sql.Exec(`UPDATE container_recreations SET state = ?,
		images = CASE WHEN ? = '' THEN images ELSE ? END, containers = ?, verdict = ?,
		baseline = CASE WHEN baseline = '' THEN ? ELSE baseline END,
		window_expires_at = CASE WHEN window_expires_at = 0 THEN ? ELSE window_expires_at END,
		updated_at = ?
		WHERE execution_id = ? AND state = 'intent'`,
		c.State, images, images, containers, verdict, string(c.Baseline), now.Add(window).Unix(), db.now().Unix(), executionID)
	return expectOneRecreation(res, err, executionID)
}

func expectOneRecreation(res sql.Result, err error, executionID string) error {
	if err != nil {
		return fmt.Errorf("executordb: update recreation %s: %w", executionID, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("executordb: update recreation %s: %w", executionID, err)
	}
	if n != 1 {
		return fmt.Errorf("executordb: update recreation %s: %w", executionID, ErrRecreationState)
	}
	return nil
}

// MarkContainerRecreationRolledBack records that a later rollback of the
// row succeeded. Only a recreated or partial row can be rolled back.
func (db *DB) MarkContainerRecreationRolledBack(executionID string) error {
	res, err := db.sql.Exec(`UPDATE container_recreations SET state = 'rolled_back', updated_at = ?
		WHERE execution_id = ? AND kind = 'update' AND state IN ('recreated', 'partial')`, db.now().Unix(), executionID)
	return expectOneRecreation(res, err, executionID)
}

const recreationColumns = `execution_id, batch_digest, member_id, kind, rollback_of, host_id, host_key, form, unit,
	binding, definition, images, containers, baseline, verdict, state, window_expires_at, created_at, updated_at`

func scanRecreation(row interface{ Scan(...any) error }) (ContainerRecreation, error) {
	var r ContainerRecreation
	var binding, definition, images, containers, baseline, verdict string
	var expires, created, updated int64
	if err := row.Scan(&r.ExecutionID, &r.BatchDigest, &r.MemberID, &r.Kind, &r.RollbackOf, &r.HostID, &r.HostKey,
		&r.Form, &r.Unit, &binding, &definition, &images, &containers, &baseline, &verdict, &r.State,
		&expires, &created, &updated); err != nil {
		return ContainerRecreation{}, err
	}
	r.Binding, r.Definition = []byte(binding), []byte(definition)
	if baseline != "" {
		r.Baseline = []byte(baseline)
	}
	if err := json.Unmarshal([]byte(images), &r.Images); err != nil {
		return ContainerRecreation{}, fmt.Errorf("executordb: recreation %s images: %w", r.ExecutionID, err)
	}
	if err := json.Unmarshal([]byte(containers), &r.Containers); err != nil {
		return ContainerRecreation{}, fmt.Errorf("executordb: recreation %s containers: %w", r.ExecutionID, err)
	}
	if verdict != "" {
		if err := json.Unmarshal([]byte(verdict), &r.Verdict); err != nil {
			return ContainerRecreation{}, fmt.Errorf("executordb: recreation %s verdict: %w", r.ExecutionID, err)
		}
	}
	if expires != 0 {
		r.WindowExpiresAt = time.Unix(expires, 0).UTC()
	}
	r.CreatedAt, r.UpdatedAt = time.Unix(created, 0).UTC(), time.Unix(updated, 0).UTC()
	return r, nil
}

// GetContainerRecreation returns the row of an execution.
func (db *DB) GetContainerRecreation(executionID string) (ContainerRecreation, error) {
	r, err := scanRecreation(db.sql.QueryRow(`SELECT `+recreationColumns+` FROM container_recreations WHERE execution_id = ?`, executionID))
	if errors.Is(err, sql.ErrNoRows) {
		return ContainerRecreation{}, ErrNoRecreation
	}
	if err != nil {
		return ContainerRecreation{}, fmt.Errorf("executordb: get recreation %s: %w", executionID, err)
	}
	return r, nil
}

func (db *DB) queryRecreations(query string, args ...any) ([]ContainerRecreation, error) {
	rows, err := db.sql.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("executordb: list recreations: %w", err)
	}
	defer rows.Close()
	var out []ContainerRecreation
	for rows.Next() {
		r, err := scanRecreation(rows)
		if err != nil {
			return nil, fmt.Errorf("executordb: list recreations: %w", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("executordb: list recreations: %w", err)
	}
	return out, nil
}

// ContainerRecreationsInIntent returns the oldest rows still in intent, at
// most maxRecreationsListed. The reconcile pass uses
// FinishedRecreationIntents instead.
func (db *DB) ContainerRecreationsInIntent() ([]ContainerRecreation, error) {
	return db.queryRecreations(`SELECT `+recreationColumns+` FROM container_recreations WHERE state = 'intent' ORDER BY created_at, execution_id LIMIT ?`,
		maxRecreationsListed)
}

// maxIntentPage bounds one FinishedRecreationIntents page.
const maxIntentPage = 100

// RecreationIntentKey identifies an intent row whose run has finished. It
// is also the cursor of the next page.
type RecreationIntentKey struct {
	ExecutionID, HostID string
	CreatedAt           time.Time
}

// FinishedRecreationIntents returns, oldest first and after the cursor
// after (the zero key starts at the beginning), the keys of at most limit
// rows still in intent whose run has finished, so a run that finished
// before its row was completed (a crash in between) is judged on the next
// reconcile pass. A limit outside 1..maxIntentPage is maxIntentPage. Only
// the keys are loaded; a row whose run has not finished, or that has no
// run, is not returned.
func (db *DB) FinishedRecreationIntents(after RecreationIntentKey, limit int) ([]RecreationIntentKey, error) {
	if limit <= 0 || limit > maxIntentPage {
		limit = maxIntentPage
	}
	var since int64
	if !after.CreatedAt.IsZero() {
		since = after.CreatedAt.Unix()
	}
	rows, err := db.sql.Query(`SELECT c.execution_id, c.host_id, c.created_at FROM container_recreations c
		JOIN runs r ON r.execution_id = c.execution_id AND r.host_id = c.host_id
		WHERE c.state = 'intent' AND r.state = 'finished'
			AND (c.created_at > ? OR (c.created_at = ? AND c.execution_id > ?))
		ORDER BY c.created_at, c.execution_id LIMIT ?`, since, since, after.ExecutionID, limit)
	if err != nil {
		return nil, fmt.Errorf("executordb: finished recreation intents: %w", err)
	}
	defer rows.Close()
	var out []RecreationIntentKey
	for rows.Next() {
		var k RecreationIntentKey
		var created int64
		if err := rows.Scan(&k.ExecutionID, &k.HostID, &created); err != nil {
			return nil, fmt.Errorf("executordb: finished recreation intents: %w", err)
		}
		k.CreatedAt = time.Unix(created, 0).UTC()
		out = append(out, k)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("executordb: finished recreation intents: %w", err)
	}
	return out, nil
}

// ListContainerRecreations returns the newest rows of a host, at most
// maxRecreationsListed; an empty hostID lists every host.
func (db *DB) ListContainerRecreations(hostID string) ([]ContainerRecreation, error) {
	if hostID == "" {
		return db.queryRecreations(`SELECT `+recreationColumns+` FROM container_recreations ORDER BY created_at DESC, execution_id LIMIT ?`, maxRecreationsListed)
	}
	return db.queryRecreations(`SELECT `+recreationColumns+` FROM container_recreations WHERE host_id = ? ORDER BY created_at DESC, execution_id LIMIT ?`,
		hostID, maxRecreationsListed)
}

// HostHasUncertainRecreation reports whether a row of the host is
// uncertain (a preview's result is then kept for Resolve).
func (db *DB) HostHasUncertainRecreation(hostID string) (bool, error) {
	var n int
	if err := db.sql.QueryRow(`SELECT COUNT(*) FROM container_recreations WHERE host_id = ? AND state = 'uncertain'`, hostID).Scan(&n); err != nil {
		return false, fmt.Errorf("executordb: uncertain recreations of %s: %w", hostID, err)
	}
	return n > 0, nil
}

// --- recovery plans ---------------------------------------------------------

// Recovery plan kinds: a reference to the operator's data backup or
// recovery procedure, or the explicit declaration that the unit keeps no
// persistent data.
const (
	RecoveryPlanReference = "plan"
	RecoveryNoData        = "no_persistent_data"
)

// RecoveryPlan is the recovery plan record of one unit on one host.
type RecoveryPlan struct {
	HostID, Unit string
	Kind         string
	Reference    string
	Actor        string
	Version      uint64
	RecordedAt   time.Time
}

// Digest is the SHA-256 of the record a rollback binds
// (recovery_plan_digest): host, unit, kind, reference, actor, version and
// time, so a plan changed or cleared and set again differs.
func (p RecoveryPlan) Digest() string {
	b, _ := json.Marshal(struct {
		Label      string `json:"label"`
		HostID     string `json:"host_id"`
		Unit       string `json:"unit"`
		Kind       string `json:"kind"`
		Reference  string `json:"reference"`
		Actor      string `json:"actor"`
		Version    uint64 `json:"version"`
		RecordedAt int64  `json:"recorded_at"`
	}{"nos-container-recovery-plan-v1", p.HostID, p.Unit, p.Kind, p.Reference, p.Actor, p.Version, p.RecordedAt.Unix()})
	d := sha256.Sum256(b)
	return hex.EncodeToString(d[:])
}

func validRecoveryText(s string, limit int) bool {
	if len(s) > limit || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// SetContainerRecoveryPlan records the unit's recovery plan, replacing an
// earlier one with the next version. kind is RecoveryPlanReference with a
// non-empty reference, or RecoveryNoData with none: exactly one of the
// two, never inferred.
func (db *DB) SetContainerRecoveryPlan(hostID, unit, kind, reference, actor string) (RecoveryPlan, error) {
	if hostID == "" || len(hostID) > 255 || unit == "" || len(unit) > maxRecreationUnit || actor == "" || len(actor) > 255 ||
		!validRecoveryText(unit, maxRecreationUnit) || !validRecoveryText(actor, 255) {
		return RecoveryPlan{}, errors.New("executordb: recovery plan: malformed host, unit or actor")
	}
	switch {
	case kind == RecoveryPlanReference && strings.TrimSpace(reference) != "" && validRecoveryText(reference, maxRecoveryReference):
	case kind == RecoveryNoData && reference == "":
	default:
		return RecoveryPlan{}, errors.New("executordb: recovery plan needs either a reference or the explicit no_persistent_data declaration")
	}
	now := db.now().UTC().Truncate(time.Second)
	tx, err := db.sql.Begin()
	if err != nil {
		return RecoveryPlan{}, fmt.Errorf("executordb: recovery plan: %w", err)
	}
	defer tx.Rollback()
	var version uint64
	if err := tx.QueryRow(`SELECT COALESCE(MAX(version), 0) FROM container_recovery_plans WHERE host_id = ? AND unit = ?`, hostID, unit).Scan(&version); err != nil {
		return RecoveryPlan{}, fmt.Errorf("executordb: recovery plan: %w", err)
	}
	p := RecoveryPlan{HostID: hostID, Unit: unit, Kind: kind, Reference: reference, Actor: actor, Version: version + 1, RecordedAt: now}
	if _, err := tx.Exec(`INSERT INTO container_recovery_plans (host_id, unit, kind, reference, actor, version, recorded_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (host_id, unit) DO UPDATE SET kind = excluded.kind, reference = excluded.reference,
			actor = excluded.actor, version = excluded.version, recorded_at = excluded.recorded_at`,
		hostID, unit, kind, reference, actor, p.Version, now.Unix()); err != nil {
		return RecoveryPlan{}, fmt.Errorf("executordb: recovery plan: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return RecoveryPlan{}, fmt.Errorf("executordb: recovery plan: %w", err)
	}
	return p, nil
}

// ClearContainerRecoveryPlan removes the unit's recovery plan; a rollback
// bound to it then fails revalidation.
func (db *DB) ClearContainerRecoveryPlan(hostID, unit string) error {
	res, err := db.sql.Exec(`DELETE FROM container_recovery_plans WHERE host_id = ? AND unit = ?`, hostID, unit)
	if err != nil {
		return fmt.Errorf("executordb: clear recovery plan: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil || n == 0 {
		return ErrNoRecoveryPlan
	}
	return nil
}

// ContainerRecoveryPlan returns the unit's current recovery plan.
func (db *DB) ContainerRecoveryPlan(hostID, unit string) (RecoveryPlan, error) {
	var p RecoveryPlan
	var at int64
	err := db.sql.QueryRow(`SELECT host_id, unit, kind, reference, actor, version, recorded_at FROM container_recovery_plans
		WHERE host_id = ? AND unit = ?`, hostID, unit).Scan(&p.HostID, &p.Unit, &p.Kind, &p.Reference, &p.Actor, &p.Version, &at)
	if errors.Is(err, sql.ErrNoRows) {
		return RecoveryPlan{}, ErrNoRecoveryPlan
	}
	if err != nil {
		return RecoveryPlan{}, fmt.Errorf("executordb: recovery plan: %w", err)
	}
	p.RecordedAt = time.Unix(at, 0).UTC()
	return p, nil
}

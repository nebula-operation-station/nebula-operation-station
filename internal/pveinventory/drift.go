// SPDX-License-Identifier: AGPL-3.0-or-later
package pveinventory

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
)

// Drift fields compared between the linked managed host and the PVE
// guest observation.
const (
	// DriftFieldIP compares the host endpoints against the guest IPs.
	DriftFieldIP = "ip"
	// DriftFieldRAM compares the host tag "pve.ram" against the guest
	// RAM.
	DriftFieldRAM = "ram"
	// DriftFieldNode compares the host tag "pve.node" against the PVE
	// node.
	DriftFieldNode = "node"
	// DriftFieldState compares the host tag "pve.state" against the
	// PVE guest state.
	DriftFieldState = "state"
)

// Drift resolutions.
const (
	// DriftAccepted: the PVE value was accepted into the host's display
	// fields (tags only).
	DriftAccepted = "accepted"
	// DriftIgnored: the hint was dismissed without changes.
	DriftIgnored = "ignored"
)

// Host tags written by accepting a drift hint. Accepting never touches
// SSH endpoints, credential refs or criticality.
const (
	TagPVEIP    = "pve.ip"
	TagPVERAM   = "pve.ram"
	TagPVENode  = "pve.node"
	TagPVEState = "pve.state"
)

// ErrDriftHintNotFound is returned when the drift hint does not exist.
var ErrDriftHintNotFound = errors.New("pveinventory: drift hint not found")

// ErrDriftResolved is returned when the drift hint was already
// resolved.
var ErrDriftResolved = errors.New("pveinventory: drift hint already resolved")

// ErrDriftStale is returned when newer observations superseded the hint.
var ErrDriftStale = errors.New("pveinventory: drift hint superseded")

// DriftHint is a read-only record of a difference between the linked
// managed host and the PVE guest observation. It is never applied
// automatically: a human accepts (updates display fields only) or
// ignores it.
type DriftHint struct {
	// ID is the drift hint row id.
	ID int64
	// RemoteID is the PVE remote the guest belongs to.
	RemoteID string
	// VMID is the PVE guest ID.
	VMID uint64
	// Generation is the incarnation of the VMID.
	Generation uint64
	// HostID is the linked managed host.
	HostID string
	// Field is DriftFieldIP, DriftFieldRAM, DriftFieldNode or
	// DriftFieldState.
	Field string
	// InventoryValue is the value on the managed host side.
	InventoryValue string
	// PVEValue is the value observed in PVE.
	PVEValue string
	// CreatedAt is when the hint was first recorded.
	CreatedAt time.Time
	// ResolvedAt is when the hint was resolved; zero while open.
	ResolvedAt time.Time
	// Resolution is DriftAccepted or DriftIgnored; empty while open.
	Resolution string
	// ResolvedBy is the user who resolved the hint.
	ResolvedBy string
	// SupersededAt is when newer observations invalidated this confirmation.
	SupersededAt time.Time
}

// SweepDrift computes drift hints for all actively linked guests of one
// remote and records one open hint per (host, field) difference.
// Accepting or ignoring a hint is a separate explicit call.
func (s *Store) SweepDrift(ctx context.Context, remoteID string) ([]DriftHint, error) {
	links, err := s.ListLinks(ctx, remoteID, 0)
	if err != nil {
		return nil, err
	}
	var out []DriftHint
	for _, l := range links {
		guest, err := s.getIncarnation(ctx, remoteID, l.VMID, l.Generation)
		if err != nil {
			return nil, err
		}
		host, err := s.hostStore().Get(ctx, l.HostID)
		if err != nil {
			if errors.Is(err, inventory.ErrHostNotFound) {
				continue // host deleted: the link is stale, not a drift
			}
			return nil, fmt.Errorf("pveinventory: get host %s for drift: %w", l.HostID, err)
		}
		hints, err := s.computeDrift(ctx, l, guest, host)
		if err != nil {
			return nil, err
		}
		out = append(out, hints...)
	}
	return out, nil
}

// computeDrift records the drift hints of one linked guest.
func (s *Store) computeDrift(ctx context.Context, l Link, g Guest, h inventory.Host) ([]DriftHint, error) {
	ifaces, err := s.ListInterfaces(ctx, l.RemoteID, l.VMID, l.Generation, 0)
	if err != nil {
		return nil, err
	}
	guestIPs := []string{}
	seen := map[string]bool{}
	for _, in := range ifaces {
		for _, ip := range in.IPs {
			a, ok := parseGuestIP(ip)
			if !ok || seen[a] {
				continue
			}
			seen[a] = true
			guestIPs = append(guestIPs, a)
		}
	}
	sort.Strings(guestIPs)
	endpointIPs := map[string]bool{}
	for _, e := range h.Endpoints {
		endpointIPs[strings.ToLower(e.Address)] = true
	}
	var pending []DriftHint
	add := func(field, invValue, pveValue string) {
		pending = append(pending, DriftHint{Field: field, InventoryValue: invValue, PVEValue: pveValue})
	}

	if missing := missingGuestIPs(guestIPs, endpointIPs); len(missing) > 0 {
		add(DriftFieldIP, strings.Join(endpointAddresses(h), ", "), strings.Join(missing, ", "))
	}

	// Dataset status is authoritative: an unavailable poll may retain an
	// older config row. Neither missing nor unavailable RAM blocks other fields.
	status, err := s.GetGuestDatasetStatus(ctx, l.RemoteID, l.VMID, l.Generation, DatasetConfig)
	if err != nil && !errors.Is(err, ErrDatasetNotFound) {
		return nil, err
	}
	if err == nil && status.State == StateAvailable {
		cfg, err := s.GetGuestConfig(ctx, l.RemoteID, l.VMID, l.Generation)
		if err != nil && !errors.Is(err, ErrGuestNotFound) {
			return nil, err
		}
		if v, ok := h.Tags[TagPVERAM]; err == nil && ok && cfg.State == StateAvailable && cfg.RAMBytes > 0 && v != formatRAM(cfg.RAMBytes) {
			add(DriftFieldRAM, v, formatRAM(cfg.RAMBytes))
		}
	}
	if v, ok := h.Tags[TagPVENode]; ok && v != g.Node {
		add(DriftFieldNode, v, g.Node)
	}
	if v, ok := h.Tags[TagPVEState]; ok && v != g.Status {
		add(DriftFieldState, v, g.Status)
	}
	var out []DriftHint
	args := []any{s.formatTime(s.now()), h.ID}
	query := `UPDATE pve_drift_hints SET superseded_at = ?
		WHERE host_id = ? AND resolved_at = '' AND superseded_at = ''`
	for _, p := range pending {
		hint, err := s.recordDrift(ctx, l, h.ID, p.Field, p.InventoryValue, p.PVEValue)
		if err != nil {
			return nil, err
		}
		out = append(out, hint)
		query += ` AND id != ?`
		args = append(args, hint.ID)
	}
	// A difference that disappeared also invalidates its old confirmation.
	if _, err := s.db.ExecContext(ctx, query, args...); err != nil {
		return nil, fmt.Errorf("pveinventory: supersede obsolete drift hints: %w", err)
	}
	return out, nil
}

// recordDrift retains immutable values and decisions. Only unchanged
// observations reuse a confirmation ID; new values supersede the open version.
func (s *Store) recordDrift(ctx context.Context, l Link, hostID, field, invValue, pveValue string) (DriftHint, error) {
	now := s.formatTime(s.now())
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return DriftHint{}, fmt.Errorf("pveinventory: begin drift hint: %w", err)
	}
	defer tx.Rollback()
	h, err := scanDriftRow(tx.QueryRowContext(ctx, `SELECT `+driftColumns+`
		FROM pve_drift_hints WHERE host_id = ? AND field = ? ORDER BY id DESC LIMIT 1`, hostID, field))
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return DriftHint{}, fmt.Errorf("pveinventory: read previous drift hint: %w", err)
	}
	if err == nil && h.ResolvedAt.IsZero() && h.SupersededAt.IsZero() && h.RemoteID == l.RemoteID && h.VMID == l.VMID && h.Generation == l.Generation && h.InventoryValue == invValue && h.PVEValue == pveValue {
		return h, nil
	}
	if _, err := tx.ExecContext(ctx, `UPDATE pve_drift_hints SET superseded_at = ?
		WHERE host_id = ? AND field = ? AND resolved_at = '' AND superseded_at = ''`, now, hostID, field); err != nil {
		return DriftHint{}, fmt.Errorf("pveinventory: supersede drift hint: %w", err)
	}
	res, err := tx.ExecContext(ctx, `INSERT INTO pve_drift_hints
		(remote_id, vmid, generation, host_id, field, inventory_value, pve_value, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, l.RemoteID, l.VMID, l.Generation, hostID, field, invValue, pveValue, now)
	if err != nil {
		return DriftHint{}, fmt.Errorf("pveinventory: insert drift hint: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return DriftHint{}, fmt.Errorf("pveinventory: drift hint id: %w", err)
	}
	h, err = s.getDriftHintRow(ctx, tx, id)
	if err != nil {
		return DriftHint{}, fmt.Errorf("pveinventory: read stored drift hint: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return DriftHint{}, fmt.Errorf("pveinventory: commit drift hint: %w", err)
	}
	return h, nil
}

// ResolveDriftHint explicitly resolves one open drift hint. Accept
// copies the PVE value into the host's display tag for the field
// (never into SSH endpoints, credential refs or criticality); ignore
// records the dismissal. Both are audited.
func (s *Store) ResolveDriftHint(ctx context.Context, id int64, resolution, actor string) (DriftHint, error) {
	if err := validActor(actor); err != nil {
		return DriftHint{}, err
	}
	if resolution != DriftAccepted && resolution != DriftIgnored {
		return DriftHint{}, fmt.Errorf("pveinventory: drift resolution must be %q or %q", DriftAccepted, DriftIgnored)
	}
	now := s.formatTime(s.now())
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return DriftHint{}, fmt.Errorf("pveinventory: begin resolve drift hint: %w", err)
	}
	defer tx.Rollback()
	h, err := s.getDriftHintRow(ctx, tx, id)
	if err != nil {
		return DriftHint{}, err
	}
	if !h.ResolvedAt.IsZero() {
		return DriftHint{}, fmt.Errorf("%w: %d", ErrDriftResolved, id)
	}
	if !h.SupersededAt.IsZero() {
		return DriftHint{}, fmt.Errorf("%w: %d", ErrDriftStale, id)
	}
	if resolution == DriftAccepted {
		tag, ok := driftTagForField(h.Field)
		if !ok {
			return DriftHint{}, fmt.Errorf("pveinventory: no display tag for drift field %q", h.Field)
		}
		// Write only the display tag. No host snapshot is rewritten, so
		// concurrent endpoint, credential and criticality edits survive.
		res, err := tx.ExecContext(ctx, `INSERT INTO host_tag_kv (host_id, tag_key, tag_value)
			SELECT id, ?, ? FROM hosts WHERE name = ?
			ON CONFLICT (host_id, tag_key) DO UPDATE SET tag_value = excluded.tag_value`, tag, h.PVEValue, h.HostID)
		if err != nil {
			return DriftHint{}, fmt.Errorf("pveinventory: update host %s display tag: %w", h.HostID, err)
		}
		if n, err := res.RowsAffected(); err != nil {
			return DriftHint{}, fmt.Errorf("pveinventory: display tag affected rows: %w", err)
		} else if n != 1 {
			return DriftHint{}, fmt.Errorf("pveinventory: accept drift for host %s: %w", h.HostID, inventory.ErrHostNotFound)
		}
	}
	res, err := tx.ExecContext(ctx, `
		UPDATE pve_drift_hints SET resolved_at = ?, resolution = ?, resolved_by = ?
		WHERE id = ? AND resolved_at = '' AND superseded_at = ''`, now, resolution, actor, id)
	if err != nil {
		return DriftHint{}, fmt.Errorf("pveinventory: resolve drift hint %d: %w", id, err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return DriftHint{}, fmt.Errorf("%w: %d", ErrDriftResolved, id)
	}
	if err := tx.Commit(); err != nil {
		return DriftHint{}, fmt.Errorf("pveinventory: commit drift resolution: %w", err)
	}
	h.ResolvedAt, _ = time.Parse(time.RFC3339, now)
	h.Resolution = resolution
	h.ResolvedBy = actor
	return h, nil
}

// ListDriftHints returns the drift hints of one remote, open first,
// bounded.
func (s *Store) ListDriftHints(ctx context.Context, remoteID string, limit int) ([]DriftHint, error) {
	limit, err := checkLimit(limit, MaxLinksQuery)
	if err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT `+driftColumns+`
		FROM pve_drift_hints
		WHERE remote_id = ?
		ORDER BY (resolved_at = '' AND superseded_at = '') DESC, id
		LIMIT ?`, remoteID, limit)
	if err != nil {
		return nil, fmt.Errorf("pveinventory: list drift hints %s: %w", remoteID, err)
	}
	defer rows.Close()
	var out []DriftHint
	for rows.Next() {
		h, err := scanDriftRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// getDriftHint loads one drift hint by id.
func (s *Store) getDriftHint(ctx context.Context, id int64) (DriftHint, error) {
	return s.getDriftHintRow(ctx, s.db, id)
}

const driftColumns = `id, remote_id, vmid, generation, host_id, field,
	inventory_value, pve_value, created_at, resolved_at, resolution, resolved_by, superseded_at`

func (s *Store) getDriftHintRow(ctx context.Context, db rowQuerier, id int64) (DriftHint, error) {
	row := db.QueryRowContext(ctx, `
		SELECT `+driftColumns+`
		FROM pve_drift_hints WHERE id = ?`, id)
	h, err := scanDriftRow(row)
	if errors.Is(err, sql.ErrNoRows) {
		return DriftHint{}, fmt.Errorf("%w: %d", ErrDriftHintNotFound, id)
	}
	return h, err
}

// driftTagForField maps a drift field to the host display tag that
// holds the accepted value.
func driftTagForField(field string) (string, bool) {
	switch field {
	case DriftFieldIP:
		return TagPVEIP, true
	case DriftFieldRAM:
		return TagPVERAM, true
	case DriftFieldNode:
		return TagPVENode, true
	case DriftFieldState:
		return TagPVEState, true
	}
	return "", false
}

// missingGuestIPs returns the guest IPs that are not endpoint
// addresses of the host.
func missingGuestIPs(guestIPs []string, endpointIPs map[string]bool) []string {
	var out []string
	for _, ip := range guestIPs {
		if !endpointIPs[strings.ToLower(ip)] {
			out = append(out, ip)
		}
	}
	return out
}

// endpointAddresses returns the host endpoint addresses, sorted.
func endpointAddresses(h inventory.Host) []string {
	out := make([]string, 0, len(h.Endpoints))
	for _, e := range h.Endpoints {
		out = append(out, e.Address)
	}
	sort.Strings(out)
	return out
}

// formatRAM renders a byte count as a human display value.
func formatRAM(b uint64) string {
	const gib = 1024 * 1024 * 1024
	const mib = 1024 * 1024
	switch {
	case b%gib == 0:
		return fmt.Sprintf("%d GiB", b/gib)
	case b%mib == 0:
		return fmt.Sprintf("%d MiB", b/mib)
	default:
		return fmt.Sprintf("%d B", b)
	}
}

// scanDriftRow scans one pve_drift_hints row.
func scanDriftRow(row linkScanner) (DriftHint, error) {
	var h DriftHint
	var createdAt, resolvedAt, supersededAt string
	err := row.Scan(&h.ID, &h.RemoteID, &h.VMID, &h.Generation, &h.HostID, &h.Field,
		&h.InventoryValue, &h.PVEValue, &createdAt, &resolvedAt, &h.Resolution, &h.ResolvedBy, &supersededAt)
	if err != nil {
		return DriftHint{}, err
	}
	h.SupersededAt, _ = time.Parse(time.RFC3339, supersededAt)
	h.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	if resolvedAt != "" {
		h.ResolvedAt, _ = time.Parse(time.RFC3339, resolvedAt)
	}
	return h, nil
}

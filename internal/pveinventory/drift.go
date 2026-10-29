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
	var out []DriftHint

	// IP: a guest IP that is not an endpoint address of the host.
	if missing := missingGuestIPs(guestIPs, endpointIPs); len(missing) > 0 {
		out = append(out, s.recordDrift(ctx, l, h.ID, DriftFieldIP,
			strings.Join(endpointAddresses(h), ", "), strings.Join(missing, ", ")))
	}

	// RAM / node / state: compared against the host's display tags; no
	// hint when the tag is not recorded yet.
	cfg, err := s.GetGuestConfig(ctx, l.RemoteID, l.VMID, l.Generation)
	if err != nil {
		return nil, err
	}
	if v, ok := h.Tags[TagPVERAM]; ok && cfg.RAMBytes > 0 && v != formatRAM(cfg.RAMBytes) {
		out = append(out, s.recordDrift(ctx, l, h.ID, DriftFieldRAM, v, formatRAM(cfg.RAMBytes)))
	}
	if v, ok := h.Tags[TagPVENode]; ok && v != g.Node {
		out = append(out, s.recordDrift(ctx, l, h.ID, DriftFieldNode, v, g.Node))
	}
	if v, ok := h.Tags[TagPVEState]; ok && v != g.Status {
		out = append(out, s.recordDrift(ctx, l, h.ID, DriftFieldState, v, g.Status))
	}
	return out, nil
}

// recordDrift upserts one hint per (host, field) and returns the stored
// hint. Re-detection reopens a previously resolved hint.
func (s *Store) recordDrift(ctx context.Context, l Link, hostID, field, invValue, pveValue string) DriftHint {
	now := s.formatTime(s.now())
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO pve_drift_hints (remote_id, vmid, generation, host_id, field,
		                              inventory_value, pve_value, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (host_id, field) DO UPDATE SET
			remote_id = excluded.remote_id,
			vmid = excluded.vmid,
			generation = excluded.generation,
			inventory_value = excluded.inventory_value,
			pve_value = excluded.pve_value,
			resolved_at = '',
			resolution = '',
			resolved_by = ''`,
		l.RemoteID, l.VMID, l.Generation, hostID, field, invValue, pveValue, now)
	if err != nil {
		return DriftHint{}
	}
	row := s.db.QueryRowContext(ctx, `
		SELECT id, remote_id, vmid, generation, host_id, field,
		       inventory_value, pve_value, created_at, resolved_at, resolution, resolved_by
		FROM pve_drift_hints
		WHERE host_id = ? AND field = ?`, hostID, field)
	h, err := scanDriftRow(row)
	if err != nil {
		return DriftHint{}
	}
	return h
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
	h, err := s.getDriftHint(ctx, id)
	if err != nil {
		return DriftHint{}, err
	}
	if !h.ResolvedAt.IsZero() {
		return DriftHint{}, fmt.Errorf("%w: %d", ErrDriftResolved, id)
	}
	if resolution == DriftAccepted {
		host, err := s.hostStore().Get(ctx, h.HostID)
		if err != nil {
			return DriftHint{}, fmt.Errorf("pveinventory: get host %s for drift accept: %w", h.HostID, err)
		}
		tag, ok := driftTagForField(h.Field)
		if !ok {
			return DriftHint{}, fmt.Errorf("pveinventory: no display tag for drift field %q", h.Field)
		}
		if host.Tags == nil {
			host.Tags = map[string]string{}
		}
		host.Tags[tag] = h.PVEValue
		if _, err := s.hostStore().Update(ctx, host); err != nil {
			return DriftHint{}, fmt.Errorf("pveinventory: update host %s tags: %w", h.HostID, err)
		}
	}
	now := s.formatTime(s.now())
	res, err := s.db.ExecContext(ctx, `
		UPDATE pve_drift_hints SET resolved_at = ?, resolution = ?, resolved_by = ?
		WHERE id = ? AND resolved_at = ''`, now, resolution, actor, id)
	if err != nil {
		return DriftHint{}, fmt.Errorf("pveinventory: resolve drift hint %d: %w", id, err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return DriftHint{}, fmt.Errorf("%w: %d", ErrDriftResolved, id)
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
		SELECT id, remote_id, vmid, generation, host_id, field,
		       inventory_value, pve_value, created_at, resolved_at, resolution, resolved_by
		FROM pve_drift_hints
		WHERE remote_id = ?
		ORDER BY (resolved_at = ''), id
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
	row := s.db.QueryRowContext(ctx, `
		SELECT id, remote_id, vmid, generation, host_id, field,
		       inventory_value, pve_value, created_at, resolved_at, resolution, resolved_by
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
	var createdAt, resolvedAt string
	err := row.Scan(&h.ID, &h.RemoteID, &h.VMID, &h.Generation, &h.HostID, &h.Field,
		&h.InventoryValue, &h.PVEValue, &createdAt, &resolvedAt, &h.Resolution, &h.ResolvedBy)
	if err != nil {
		return DriftHint{}, err
	}
	h.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	if resolvedAt != "" {
		h.ResolvedAt, _ = time.Parse(time.RFC3339, resolvedAt)
	}
	return h, nil
}

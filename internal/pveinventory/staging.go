// SPDX-License-Identifier: AGPL-3.0-or-later
package pveinventory

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
)

// Staging statuses, mirroring the discovery staging classes.
const (
	// StagingNew: no managed host matches the guest.
	StagingNew = "NEW"
	// StagingExisting: a MAC matches exactly one managed host.
	StagingExisting = "EXISTING"
	// StagingPossible: IP-only or multiple matches, with no hard conflict.
	StagingPossible = "POSSIBLE MATCH"
	// StagingConflict: a hard conflict (one MAC on two guests, one IP on
	// two hosts). Conflicts are flagged, never resolved silently.
	StagingConflict = "CONFLICT"
)

// ErrStagingNotFound is returned when the staged guest incarnation does
// not exist in the staging list.
var ErrStagingNotFound = errors.New("pveinventory: staging entry not found")

// ErrStagingConflict is returned when importing a CONFLICT staging
// entry. Conflicts are never imported or resolved silently.
var ErrStagingConflict = errors.New("pveinventory: staged guest has a conflict")

// ErrStagingImported is returned when the staged guest was already
// imported.
var ErrStagingImported = errors.New("pveinventory: staged guest already imported")

// StagingEntry is one unmanaged PVE guest awaiting a human decision.
// Nothing becomes a managed host until an explicit import ("add to
// managed hosts" or an explicit link to an existing host).
type StagingEntry struct {
	// RemoteID is the PVE remote the guest belongs to.
	RemoteID string
	// VMID is the PVE guest ID.
	VMID uint64
	// Generation is the incarnation of the VMID.
	Generation uint64
	// Kind is the guest kind (vm or lxc).
	Kind string
	// Name is the PVE guest name.
	Name string
	// Node is the PVE node the guest runs on.
	Node string
	// Status is StagingNew, StagingExisting, StagingPossible or
	// StagingConflict.
	Status string
	// MACs are the guest MAC addresses (validated at ingest).
	MACs []string
	// IPs are the guest IP addresses (validated at ingest).
	IPs []string
	// State is the PVE guest state (running, stopped, ...).
	State string
	// Candidates are the suggested managed hosts (suggestions only).
	Candidates []Candidate
	// CreatedAt is when the staging row was first computed.
	CreatedAt time.Time
	// ImportedAt is when the guest was imported; zero while pending.
	ImportedAt time.Time
	// ImportedBy is the user who imported the guest.
	ImportedBy string
	// ImportedAsset is the managed host id created or linked at import
	// time; empty while pending.
	ImportedAsset string
}

// SweepStaging recomputes the staging list of one remote: every active
// guest without an active explicit link is (re)classified as NEW,
// EXISTING, POSSIBLE MATCH or CONFLICT from its candidate matches.
// Linked guests are managed via their link and stay out of staging.
func (s *Store) SweepStaging(ctx context.Context, remoteID string) ([]StagingEntry, error) {
	var out []StagingEntry
	var afterVMID, afterGeneration uint64
	for {
		guests, err := s.stagingGuestBatch(ctx, remoteID, afterVMID, afterGeneration)
		if err != nil {
			return nil, err
		}
		if len(guests) == 0 {
			break
		}
		for _, g := range guests {
			if _, err := s.GetLink(ctx, remoteID, g.VMID, g.Generation); err == nil {
				continue // actively linked: managed
			} else if !errors.Is(err, ErrLinkNotFound) {
				return nil, err
			}
			entry, err := s.computeStaging(ctx, remoteID, g)
			if err != nil {
				return nil, err
			}
			if err := s.upsertStaging(ctx, entry); err != nil {
				return nil, err
			}
			out = append(out, entry)
		}
		last := guests[len(guests)-1]
		afterVMID, afterGeneration = last.VMID, last.Generation
	}
	return out, nil
}

// stagingGuestBatch uses a stable cursor and closes the bounded read before
// the sweep writes staging rows.
func (s *Store) stagingGuestBatch(ctx context.Context, remoteID string, afterVMID, afterGeneration uint64) ([]Guest, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT remote_id, vmid, generation, kind, node, name, status, uuid,
		       observed_at, source, state, reason, collection_generation,
		       tombstoned, tombstoned_at
		FROM pve_guests WHERE remote_id = ? AND tombstoned = 0
		  AND (vmid, generation) > (?, ?)
		ORDER BY vmid, generation LIMIT ?`, remoteID, afterVMID, afterGeneration, MaxGuestsQuery)
	if err != nil {
		return nil, fmt.Errorf("pveinventory: staging guest batch: %w", err)
	}
	defer rows.Close()
	var out []Guest
	for rows.Next() {
		g, err := scanGuestRow(rows, s, "staging guest batch")
		if err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// computeStaging classifies one unlinked guest.
func (s *Store) computeStaging(ctx context.Context, remoteID string, g Guest) (StagingEntry, error) {
	entry := StagingEntry{
		RemoteID:   remoteID,
		VMID:       g.VMID,
		Generation: g.Generation,
		Kind:       g.Kind,
		Name:       g.Name,
		Node:       g.Node,
		State:      g.Status,
	}
	candidates, err := s.SuggestHosts(ctx, remoteID, g.VMID, g.Generation)
	if err != nil {
		return StagingEntry{}, err
	}
	entry.Candidates = candidates
	ifaces, err := s.ListInterfaces(ctx, remoteID, g.VMID, g.Generation, 0)
	if err != nil {
		return StagingEntry{}, err
	}
	seenMAC := map[string]bool{}
	seenIP := map[string]bool{}
	for _, in := range ifaces {
		if in.MAC != "" && !seenMAC[in.MAC] {
			seenMAC[in.MAC] = true
			entry.MACs = append(entry.MACs, in.MAC)
		}
		for _, ip := range in.IPs {
			a, ok := parseGuestIP(ip)
			if !ok || seenIP[a] {
				continue
			}
			seenIP[a] = true
			entry.IPs = append(entry.IPs, a)
		}
	}
	sort.Strings(entry.MACs)
	sort.Strings(entry.IPs)

	hostSet := map[string]bool{}
	// A cloned MAC is a guest conflict even when no IPAM asset or host
	// candidate exists. Host match conflicts are handled below.
	conflict := false
	for mac := range seenMAC {
		others, err := s.guestsWithMAC(ctx, remoteID, mac, g.VMID)
		if err != nil {
			return StagingEntry{}, err
		}
		conflict = conflict || len(others) > 0
	}
	strongMatch := false
	for _, c := range candidates {
		hostSet[c.HostID] = true
		strongMatch = strongMatch || c.Match == MatchMAC
		conflict = conflict || c.Conflict
	}
	switch {
	case conflict:
		entry.Status = StagingConflict
	case len(hostSet) == 1 && strongMatch:
		entry.Status = StagingExisting
	case len(hostSet) > 0:
		entry.Status = StagingPossible
	default:
		entry.Status = StagingNew
	}
	return entry, nil
}

// upsertStaging stores the computed staging row, preserving the import
// fields of an existing row.
func (s *Store) upsertStaging(ctx context.Context, e StagingEntry) error {
	macs, err := json.Marshal(e.MACs)
	if err != nil {
		return fmt.Errorf("pveinventory: marshal staging macs: %w", err)
	}
	ips, err := json.Marshal(e.IPs)
	if err != nil {
		return fmt.Errorf("pveinventory: marshal staging ips: %w", err)
	}
	cands, err := json.Marshal(e.Candidates)
	if err != nil {
		return fmt.Errorf("pveinventory: marshal staging candidates: %w", err)
	}
	now := s.formatTime(s.now())
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO pve_staging (remote_id, vmid, generation, kind, name, node, status,
		                          macs_json, ips_json, state, candidates_json, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (remote_id, vmid, generation) DO UPDATE SET
			kind = excluded.kind,
			name = excluded.name,
			node = excluded.node,
			status = excluded.status,
			macs_json = excluded.macs_json,
			ips_json = excluded.ips_json,
			state = excluded.state,
			candidates_json = excluded.candidates_json`,
		e.RemoteID, e.VMID, e.Generation, e.Kind, e.Name, e.Node, e.State,
		string(macs), string(ips), e.Status, string(cands), now)
	if err != nil {
		return fmt.Errorf("pveinventory: upsert staging %s/%d/%d: %w", e.RemoteID, e.VMID, e.Generation, err)
	}
	return nil
}

// ListStaging returns the stored staging rows of one remote, pending
// first, bounded.
func (s *Store) ListStaging(ctx context.Context, remoteID string, limit int) ([]StagingEntry, error) {
	limit, err := checkLimit(limit, MaxLinksQuery)
	if err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT remote_id, vmid, generation, kind, name, node, status,
		       macs_json, ips_json, state, candidates_json, created_at,
		       imported_at, imported_by, imported_asset
		FROM pve_staging
		WHERE remote_id = ?
		ORDER BY (imported_at = ''), vmid, generation
		LIMIT ?`, remoteID, limit)
	if err != nil {
		return nil, fmt.Errorf("pveinventory: list staging %s: %w", remoteID, err)
	}
	defer rows.Close()
	var out []StagingEntry
	for rows.Next() {
		e, err := scanStagingRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ImportStaged explicitly imports one staged guest. With hostID empty
// it creates a new managed host from the guest data ("add to managed
// hosts"); with a hostID it links the guest to that existing managed
// host. Both paths create the explicit link and preserve existing asset
// ids. CONFLICT entries are never imported.
func (s *Store) ImportStaged(ctx context.Context, remoteID string, vmid, generation uint64, hostID, actor string) (string, error) {
	if err := validActor(actor); err != nil {
		return "", err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", fmt.Errorf("pveinventory: begin staged import: %w", err)
	}
	defer tx.Rollback()
	entry, err := s.getStagingRow(ctx, tx, remoteID, vmid, generation)
	if err != nil {
		return "", err
	}
	if !entry.ImportedAt.IsZero() {
		return "", fmt.Errorf("%w: %s (imported as %s)", ErrStagingImported, entry.Name, entry.ImportedAsset)
	}
	if entry.Status == StagingConflict {
		return "", fmt.Errorf("%w: %s/%d/%d", ErrStagingConflict, remoteID, vmid, generation)
	}
	if err := validateLinkIncarnation(ctx, tx, remoteID, vmid, generation); err != nil {
		return "", err
	}
	if hostID == "" {
		hostID, err = s.createHostFromGuest(ctx, tx, entry)
		if err != nil {
			return "", err
		}
	}
	now := s.formatTime(s.now())
	if err := s.createLinkTx(ctx, tx, remoteID, vmid, generation, hostID, actor, now); err != nil {
		return "", err
	}
	res, err := tx.ExecContext(ctx, `
		UPDATE pve_staging SET imported_at = ?, imported_by = ?, imported_asset = ?
		WHERE remote_id = ? AND vmid = ? AND generation = ? AND imported_at = ''`,
		now, actor, hostID, remoteID, vmid, generation)
	if err != nil {
		return "", fmt.Errorf("pveinventory: mark staging imported %s/%d/%d: %w", remoteID, vmid, generation, err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return "", fmt.Errorf("%w: %s/%d/%d", ErrStagingImported, remoteID, vmid, generation)
	}
	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("pveinventory: commit staged import: %w", err)
	}
	return hostID, nil
}

// getStaging loads one stored staging row.
func (s *Store) getStaging(ctx context.Context, remoteID string, vmid, generation uint64) (StagingEntry, error) {
	return s.getStagingRow(ctx, s.db, remoteID, vmid, generation)
}

type rowQuerier interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func (s *Store) getStagingRow(ctx context.Context, db rowQuerier, remoteID string, vmid, generation uint64) (StagingEntry, error) {
	row := db.QueryRowContext(ctx, `
		SELECT remote_id, vmid, generation, kind, name, node, status,
		       macs_json, ips_json, state, candidates_json, created_at,
		       imported_at, imported_by, imported_asset
		FROM pve_staging
		WHERE remote_id = ? AND vmid = ? AND generation = ?`,
		remoteID, vmid, generation)
	e, err := scanStagingRow(row)
	if errors.Is(err, sql.ErrNoRows) {
		return StagingEntry{}, fmt.Errorf("%w: %s/%d/%d", ErrStagingNotFound, remoteID, vmid, generation)
	}
	return e, err
}

// createHostFromGuest creates a new managed host from the staged guest
// data: a deterministic id derived from the guest name, the guest name
// as display name, and the guest IPs as endpoints.
func (s *Store) createHostFromGuest(ctx context.Context, tx *sql.Tx, e StagingEntry) (string, error) {
	base := slugifyHostID(e.Name)
	if base == "" {
		base = fmt.Sprintf("vm%d", e.VMID)
	}
	id := base
	for i := 2; ; i++ {
		var exists int
		if err := tx.QueryRowContext(ctx, `SELECT 1 FROM hosts WHERE name = ?`, id).Scan(&exists); errors.Is(err, sql.ErrNoRows) {
			break
		} else if err != nil {
			return "", fmt.Errorf("pveinventory: check host id %s: %w", id, err)
		}
		id = fmt.Sprintf("%s-%d", base, i)
		if len(id) > 63 {
			id = base[:63-len(fmt.Sprintf("-%d", i))] + fmt.Sprintf("-%d", i)
		}
	}
	if len(e.IPs) == 0 {
		return "", fmt.Errorf("pveinventory: cannot import %s/%d/%d: the guest has no IP address", e.RemoteID, e.VMID, e.Generation)
	}
	eps := make([]inventory.Endpoint, 0, len(e.IPs))
	for _, ip := range e.IPs {
		eps = append(eps, inventory.Endpoint{Address: ip, Port: 22})
	}
	host := inventory.Host{
		ID:          id,
		DisplayName: e.Name,
		Environment: "DEV",
		Criticality: "LOW",
		Endpoints:   eps,
	}
	if err := inventory.Validate(host); err != nil {
		return "", err
	}
	now := s.formatTime(s.now())
	res, err := tx.ExecContext(ctx, `INSERT INTO hosts
		(name, display_name, environment, criticality, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?)`, host.ID, host.DisplayName, host.Environment, host.Criticality, now, now)
	if err != nil {
		return "", fmt.Errorf("pveinventory: create staged host %s: %w", id, err)
	}
	hid, err := res.LastInsertId()
	if err != nil {
		return "", fmt.Errorf("pveinventory: staged host id: %w", err)
	}
	for i, ep := range host.Endpoints {
		if _, err := tx.ExecContext(ctx, `INSERT INTO host_endpoints
			(host_id, address, port, priority, created_at) VALUES (?, ?, ?, ?, ?)`, hid, ep.Address, ep.Port, i, now); err != nil {
			return "", fmt.Errorf("pveinventory: staged host endpoint: %w", err)
		}
	}
	return id, nil
}

// slugifyHostID turns a guest name into a valid managed host id
// fragment (lowercase alphanumerics, dot, underscore, hyphen).
func slugifyHostID(name string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(name) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '.' || r == '_' || r == '-':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	s := b.String()
	s = strings.Trim(s, "-.")
	if s == "" {
		return ""
	}
	if s[0] == '.' || s[0] == '-' || s[0] == '_' {
		s = "h-" + s
	}
	if len(s) > 63 {
		s = s[:63]
	}
	return s
}

// scanStagingRow scans one pve_staging row.
func scanStagingRow(row linkScanner) (StagingEntry, error) {
	var e StagingEntry
	var macs, ips, cands, createdAt, importedAt string
	err := row.Scan(&e.RemoteID, &e.VMID, &e.Generation, &e.Kind, &e.Name, &e.Node,
		&e.State, &macs, &ips, &e.Status, &cands, &createdAt, &importedAt, &e.ImportedBy, &e.ImportedAsset)
	if err != nil {
		return StagingEntry{}, err
	}
	if err := json.Unmarshal([]byte(macs), &e.MACs); err != nil {
		return StagingEntry{}, fmt.Errorf("pveinventory: staging macs: %w", err)
	}
	if err := json.Unmarshal([]byte(ips), &e.IPs); err != nil {
		return StagingEntry{}, fmt.Errorf("pveinventory: staging ips: %w", err)
	}
	if err := json.Unmarshal([]byte(cands), &e.Candidates); err != nil {
		return StagingEntry{}, fmt.Errorf("pveinventory: staging candidates: %w", err)
	}
	e.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	if importedAt != "" {
		e.ImportedAt, _ = time.Parse(time.RFC3339, importedAt)
	}
	return e, nil
}

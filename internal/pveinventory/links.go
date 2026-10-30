// SPDX-License-Identifier: AGPL-3.0-or-later
package pveinventory

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/servicecheck"
	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/ipam"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
)

// boolInt renders a boolean as a 0/1 integer for SQLite.
func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// Sentinel errors callers branch on.
var (
	// ErrLinkNotFound is returned when no active link exists for the
	// guest incarnation.
	ErrLinkNotFound = errors.New("pveinventory: link not found")
	// ErrLinkExists is returned when the guest incarnation is already
	// actively linked.
	ErrLinkExists = errors.New("pveinventory: incarnation already linked")
	// ErrHostAlreadyLinked is returned when the managed host is already
	// actively linked to a different guest incarnation. The conflict is
	// surfaced, never resolved silently.
	ErrHostAlreadyLinked = errors.New("pveinventory: host already linked to another guest")
	// ErrManagedHostNotFound is returned when the referenced inventory
	// host does not exist.
	ErrManagedHostNotFound = errors.New("pveinventory: managed host not found")
)

// Link match kinds (Candidate.Match).
const (
	// MatchMAC is a MAC address match via an IPAM asset.
	MatchMAC = "mac"
	// MatchAgentIP is an IP reported by the guest agent (qemu-agent).
	MatchAgentIP = "agent-ip"
	// MatchIP is an IP match from an interface or cloud-init record.
	MatchIP = "ip"
)

// Limits for the linking surface.
const (
	// MaxActorLen is the maximum length of an actor (user) string.
	MaxActorLen = 64
	// MaxUnlinkReasonLen is the maximum length of an unlink reason.
	MaxUnlinkReasonLen = 200
	// MaxLinksQuery caps a ListLinks result.
	MaxLinksQuery = 1000
)

var actorRe = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,64}$`)

// Link is an explicit, reviewed link between a PVE guest incarnation and
// a managed inventory host. Links are created only by an explicit
// import/confirm call, never automatically, and preserve the existing
// asset id of the managed host.
type Link struct {
	// RemoteID is the PVE remote the guest belongs to.
	RemoteID string
	// VMID is the PVE guest ID.
	VMID uint64
	// Generation is the incarnation of the VMID.
	Generation uint64
	// HostID is the managed inventory host id (asset id preserved).
	HostID string
	// CreatedBy is the user who created the link.
	CreatedBy string
	// CreatedAt is when the link was created.
	CreatedAt time.Time
	// UnlinkedAt is when the link was unlinked; zero while active.
	UnlinkedAt time.Time
	// UnlinkReason is the reason recorded at unlink time.
	UnlinkReason string
}

// Candidate is a suggestion of which managed host a PVE guest might be.
// Candidates are suggestions only: a link is created only by an explicit
// import/confirm call.
type Candidate struct {
	// HostID is the suggested managed host id.
	HostID string
	// Match is how the candidate was found: MatchMAC, MatchAgentIP or
	// MatchIP.
	Match string
	// Detail is a human-readable explanation built from validated values.
	Detail string
	// Conflict is true when the same identifying value points to more
	// than one managed host (one MAC on two guests, one IP on two hosts).
	// Conflicts are flagged, never resolved silently.
	Conflict bool
}

// ReuseNotice is a visible notice that a VMID was reused (new
// incarnation) and the old explicit link no longer applies.
type ReuseNotice struct {
	// RemoteID is the PVE remote.
	RemoteID string
	// VMID is the reused guest ID.
	VMID uint64
	// OldGeneration is the tombstoned incarnation the link pointed at.
	OldGeneration uint64
	// OldHostID is the host the old link pointed at.
	OldHostID string
	// NewGeneration is the current active incarnation of the VMID.
	NewGeneration uint64
	// Notice is a human-readable message safe to display.
	Notice string
}

func validActor(actor string) error {
	if !actorRe.MatchString(actor) {
		return fmt.Errorf("pveinventory: invalid actor %q", actor)
	}
	return nil
}

// hostStore returns an inventory store on the same database.
func (s *Store) hostStore() *inventory.Store {
	return inventory.NewWithNow(s.db, s.now)
}

// ipamStore returns an IPAM store on the same database. Managed-host
// enrichment is not needed for the read-only candidate lookups.
func (s *Store) ipamStore() *ipam.Store {
	return ipam.New(s.db, nil)
}

// CreateLink creates an explicit link between the guest incarnation
// (remoteID, vmid, generation) and the managed host hostID. It is the
// only way a link is created: candidate matching never links
// automatically. The existing asset id of the managed host is preserved.
// The "at most one active link per incarnation" and "one host, one
// guest" invariants are checked and inserted in a single transaction.
func (s *Store) CreateLink(ctx context.Context, remoteID string, vmid, generation uint64, hostID, actor string) (Link, error) {
	if err := validActor(actor); err != nil {
		return Link{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Link{}, fmt.Errorf("pveinventory: begin create link: %w", err)
	}
	defer tx.Rollback()

	now := s.formatTime(s.now())
	if err := s.createLinkTx(ctx, tx, remoteID, vmid, generation, hostID, actor, now); err != nil {
		return Link{}, err
	}
	if err := tx.Commit(); err != nil {
		return Link{}, fmt.Errorf("pveinventory: commit create link: %w", err)
	}
	createdAt, _ := time.Parse(time.RFC3339, now)
	return Link{RemoteID: remoteID, VMID: vmid, Generation: generation, HostID: hostID, CreatedBy: actor, CreatedAt: createdAt}, nil
}

// createLinkTx validates the active incarnation and link invariants in
// the same transaction as the caller's writes.
func (s *Store) createLinkTx(ctx context.Context, tx *sql.Tx, remoteID string, vmid, generation uint64, hostID, actor, now string) error {
	if err := validateLinkIncarnation(ctx, tx, remoteID, vmid, generation); err != nil {
		return err
	}
	var exists int
	if err := tx.QueryRowContext(ctx, `SELECT 1 FROM hosts WHERE name = ?`, hostID).Scan(&exists); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: %s", ErrManagedHostNotFound, hostID)
		}
		return fmt.Errorf("pveinventory: validate managed host %s: %w", hostID, err)
	}
	if l, err := scanLinkRow(tx.QueryRowContext(ctx, linkByIncarnationSQL, remoteID, vmid, generation)); err == nil {
		return fmt.Errorf("%w: %s/%d/%d -> %s", ErrLinkExists, remoteID, vmid, generation, l.HostID)
	} else if !errors.Is(err, ErrLinkNotFound) {
		return err
	}
	if l, err := scanLinkRow(tx.QueryRowContext(ctx, linkByHostSQL, hostID)); err == nil {
		return fmt.Errorf("%w: %s -> %s/%d/%d", ErrHostAlreadyLinked, hostID, l.RemoteID, l.VMID, l.Generation)
	} else if !errors.Is(err, ErrLinkNotFound) {
		return err
	}

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO pve_host_links (remote_id, vmid, generation, host_id, created_by, created_at)
		VALUES (?, ?, ?, ?, ?, ?)`,
		remoteID, vmid, generation, hostID, actor, now); err != nil {
		return fmt.Errorf("pveinventory: create link %s/%d/%d -> %s: %w", remoteID, vmid, generation, hostID, err)
	}
	return nil
}

// validateLinkIncarnation rejects stale staging rows before creating a host.
func validateLinkIncarnation(ctx context.Context, tx *sql.Tx, remoteID string, vmid, generation uint64) error {
	var exists int
	if err := tx.QueryRowContext(ctx, `SELECT 1 FROM pve_guests
		WHERE remote_id = ? AND vmid = ? AND generation = ? AND tombstoned = 0`, remoteID, vmid, generation).Scan(&exists); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: %s/%d/%d", ErrGuestNotFound, remoteID, vmid, generation)
		}
		return fmt.Errorf("pveinventory: validate link incarnation: %w", err)
	}
	return nil
}

// GetLink returns the active link for the guest incarnation.
func (s *Store) GetLink(ctx context.Context, remoteID string, vmid, generation uint64) (Link, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT remote_id, vmid, generation, host_id, created_by, created_at, unlinked_at, unlink_reason
		FROM pve_host_links
		WHERE remote_id = ? AND vmid = ? AND generation = ? AND unlinked_at = ''`,
		remoteID, vmid, generation)
	return scanLinkRow(row)
}

// LinkHistory returns all link rows (active and unlinked) for the guest
// incarnation, newest first, so the explicit link history stays visible.
func (s *Store) LinkHistory(ctx context.Context, remoteID string, vmid, generation uint64) ([]Link, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT remote_id, vmid, generation, host_id, created_by, created_at, unlinked_at, unlink_reason
		FROM pve_host_links
		WHERE remote_id = ? AND vmid = ? AND generation = ?
		ORDER BY created_at DESC, host_id`,
		remoteID, vmid, generation)
	if err != nil {
		return nil, fmt.Errorf("pveinventory: link history %s/%d/%d: %w", remoteID, vmid, generation, err)
	}
	defer rows.Close()
	var out []Link
	for rows.Next() {
		l, err := scanLinkRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// Unlink removes the active link for the guest incarnation. The row is
// tombstoned (unlinked_at, unlink_reason), never deleted, so the
// explicit link history stays visible. The returned link carries the
// notice data for the UI.
func (s *Store) Unlink(ctx context.Context, remoteID string, vmid, generation uint64, actor, reason string) (Link, error) {
	if err := validActor(actor); err != nil {
		return Link{}, err
	}
	if !utf8.ValidString(reason) || len(reason) > MaxUnlinkReasonLen {
		return Link{}, fmt.Errorf("pveinventory: unlink reason must be valid UTF-8 of at most %d bytes", MaxUnlinkReasonLen)
	}
	link, err := s.GetLink(ctx, remoteID, vmid, generation)
	if err != nil {
		return Link{}, err
	}
	now := s.formatTime(s.now())
	res, err := s.db.ExecContext(ctx, `
		UPDATE pve_host_links SET unlinked_at = ?, unlink_reason = ?
		WHERE remote_id = ? AND vmid = ? AND generation = ? AND unlinked_at = ''`,
		now, reason, remoteID, vmid, generation)
	if err != nil {
		return Link{}, fmt.Errorf("pveinventory: unlink %s/%d/%d: %w", remoteID, vmid, generation, err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return Link{}, fmt.Errorf("%w: %s/%d/%d", ErrLinkNotFound, remoteID, vmid, generation)
	}
	link.UnlinkedAt, _ = time.Parse(time.RFC3339, now)
	link.UnlinkReason = reason
	return link, nil
}

// LinksForHost returns the active links pointing at the managed host.
func (s *Store) LinksForHost(ctx context.Context, hostID string) ([]Link, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT remote_id, vmid, generation, host_id, created_by, created_at, unlinked_at, unlink_reason
		FROM pve_host_links
		WHERE host_id = ? AND unlinked_at = ''
		ORDER BY remote_id, vmid, generation`, hostID)
	if err != nil {
		return nil, fmt.Errorf("pveinventory: links for host %s: %w", hostID, err)
	}
	defer rows.Close()
	var out []Link
	for rows.Next() {
		l, err := scanLinkRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// ListLinks returns the active links of one remote, bounded.
func (s *Store) ListLinks(ctx context.Context, remoteID string, limit int) ([]Link, error) {
	limit, err := checkLimit(limit, MaxLinksQuery)
	if err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT remote_id, vmid, generation, host_id, created_by, created_at, unlinked_at, unlink_reason
		FROM pve_host_links
		WHERE remote_id = ? AND unlinked_at = ''
		ORDER BY vmid, generation
		LIMIT ?`, remoteID, limit)
	if err != nil {
		return nil, fmt.Errorf("pveinventory: list links %s: %w", remoteID, err)
	}
	defer rows.Close()
	var out []Link
	for rows.Next() {
		l, err := scanLinkRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// SweepVMIDReuse detects active links whose incarnation was tombstoned
// by a VMID reuse (a newer active incarnation of the same VMID exists),
// unlinks them with the reason "vmid reused" and returns one visible
// notice per unlinked link. The new incarnation is never linked
// automatically.
func (s *Store) SweepVMIDReuse(ctx context.Context, remoteID string) ([]ReuseNotice, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("pveinventory: begin vmid reuse sweep: %w", err)
	}
	defer tx.Rollback()

	rows, err := tx.QueryContext(ctx, `
		SELECT l.vmid, l.generation, l.host_id,
		       (SELECT MAX(n.generation) FROM pve_guests n
		        WHERE n.remote_id = l.remote_id AND n.vmid = l.vmid AND n.tombstoned = 0)
		FROM pve_host_links l
		JOIN pve_guests g ON g.remote_id = l.remote_id AND g.vmid = l.vmid AND g.generation = l.generation
		WHERE l.remote_id = ? AND l.unlinked_at = '' AND g.tombstoned = 1
		  AND EXISTS (SELECT 1 FROM pve_guests n
		           WHERE n.remote_id = l.remote_id AND n.vmid = l.vmid
		                 AND n.generation > l.generation AND n.tombstoned = 0)
		ORDER BY l.vmid, l.generation`, remoteID)
	if err != nil {
		return nil, fmt.Errorf("pveinventory: vmid reuse sweep %s: %w", remoteID, err)
	}
	defer rows.Close()

	type item struct {
		vmid, generation, newGeneration uint64
		hostID                          string
	}
	var items []item
	for rows.Next() {
		var it item
		if err := rows.Scan(&it.vmid, &it.generation, &it.hostID, &it.newGeneration); err != nil {
			return nil, fmt.Errorf("pveinventory: scan vmid reuse sweep: %w", err)
		}
		items = append(items, it)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	var notices []ReuseNotice
	now := s.formatTime(s.now())
	for _, it := range items {
		res, err := tx.ExecContext(ctx, `
			UPDATE pve_host_links SET unlinked_at = ?, unlink_reason = 'vmid reused: new incarnation'
			WHERE remote_id = ? AND vmid = ? AND generation = ? AND unlinked_at = ''`,
			now, remoteID, it.vmid, it.generation)
		if err != nil {
			return nil, fmt.Errorf("pveinventory: unlink reused vmid %s/%d/%d: %w", remoteID, it.vmid, it.generation, err)
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return nil, fmt.Errorf("pveinventory: unlink reused vmid %s/%d/%d: %w", remoteID, it.vmid, it.generation, ErrLinkNotFound)
		}
		notices = append(notices, ReuseNotice{
			RemoteID:      remoteID,
			VMID:          it.vmid,
			OldGeneration: it.generation,
			OldHostID:     it.hostID,
			NewGeneration: it.newGeneration,
			Notice: fmt.Sprintf("VMID %d on %s was reused: the link to host %s (incarnation %d) does not apply to the new guest (incarnation %d)",
				it.vmid, remoteID, it.hostID, it.generation, it.newGeneration),
		})
	}
	if _, err := tx.ExecContext(ctx, `UPDATE pve_service_placements
 SET removed_at = ?, removed_by = 'system', remove_reason = 'guest incarnation no longer active'
 WHERE kind = 'guest' AND remote_id = ? AND removed_at = '' AND NOT EXISTS (
 SELECT 1 FROM pve_guests g WHERE g.remote_id = pve_service_placements.remote_id
 AND g.vmid = pve_service_placements.vmid AND g.generation = pve_service_placements.generation AND g.tombstoned = 0)`, now, remoteID); err != nil {
		return nil, fmt.Errorf("pveinventory: expire guest service placements: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("pveinventory: commit vmid reuse sweep: %w", err)
	}
	return notices, nil
}

// guestIPs are the IP addresses observed on one guest incarnation:
// plain interface IPs, guest-agent IPs and the cloud-init IP.
type guestIPs struct {
	agent map[string]bool
	plain map[string]bool
}

// SuggestHosts computes candidate managed hosts for the guest
// incarnation by MAC address (via IPAM assets) and guest IP (interface
// IPs, guest-agent IPs and the cloud-init IP). Candidates are
// suggestions only; they never create a link. Conflicts (one MAC on two
// guests, one IP on two hosts) are flagged in the candidates.
func (s *Store) SuggestHosts(ctx context.Context, remoteID string, vmid, generation uint64) ([]Candidate, error) {
	if _, err := s.getIncarnation(ctx, remoteID, vmid, generation); err != nil {
		return nil, err
	}

	// Guest MACs and IPs.
	macs := map[string]bool{}
	ips := guestIPs{agent: map[string]bool{}, plain: map[string]bool{}}
	ifaces, err := s.ListInterfaces(ctx, remoteID, vmid, generation, 0)
	if err != nil {
		return nil, err
	}
	for _, in := range ifaces {
		if in.MAC != "" {
			macs[in.MAC] = true
		}
		for _, ip := range in.IPs {
			a, ok := parseGuestIP(ip)
			if !ok {
				continue
			}
			if in.Source == pvecontract.SourceQEMUAgent {
				ips.agent[a] = true
			}
			ips.plain[a] = true
		}
	}
	if cfg, err := s.GetGuestConfig(ctx, remoteID, vmid, generation); err == nil && cfg.State == StateAvailable && cfg.CloudInitIP != nil {
		if a, ok := parseGuestIP(cfg.CloudInitIP.IP); ok {
			ips.plain[a] = true
		}
	}

	// Managed hosts: endpoint addresses.
	hosts, err := s.hostStore().List(ctx)
	if err != nil {
		return nil, fmt.Errorf("pveinventory: list managed hosts: %w", err)
	}
	hostByEndpoint := map[string][]string{} // lowercased address -> host ids
	for _, h := range hosts {
		for _, e := range h.Endpoints {
			hostByEndpoint[strings.ToLower(e.Address)] = append(hostByEndpoint[strings.ToLower(e.Address)], h.ID)
		}
	}

	// IPAM assets: MACs and addresses with a managed host.
	assets, err := s.ipamStore().Assets(ctx)
	if err != nil {
		return nil, fmt.Errorf("pveinventory: list ipam assets: %w", err)
	}
	hostsByAssetMAC := map[string][]string{} // normalized mac -> host ids
	hostsByAssetIP := map[string][]string{}  // lowercased ip -> host ids
	for _, a := range assets {
		if a.HostID == "" {
			continue
		}
		if a.MAC != "" {
			hostsByAssetMAC[a.MAC] = append(hostsByAssetMAC[a.MAC], a.HostID)
		}
		for _, addr := range a.Addresses {
			low := strings.ToLower(addr.String())
			hostsByAssetIP[low] = append(hostsByAssetIP[low], a.HostID)
		}
	}

	out := map[string]*Candidate{} // host|match -> candidate
	add := func(hostID, match, detail string, conflict bool) {
		key := hostID + "|" + match
		c, ok := out[key]
		if !ok {
			c = &Candidate{HostID: hostID, Match: match, Detail: detail}
			out[key] = c
		}
		c.Conflict = c.Conflict || conflict
	}

	// MAC matches: a guest MAC present on another guest of the same
	// remote is a conflict (cloned MAC), flagged not resolved.
	for mac := range macs {
		others, err := s.guestsWithMAC(ctx, remoteID, mac, vmid)
		if err != nil {
			return nil, err
		}
		macConflict := len(others) > 0
		for _, hostID := range hostsByAssetMAC[mac] {
			detail := fmt.Sprintf("MAC %s matches an IPAM asset of host %s", mac, hostID)
			if macConflict {
				detail += fmt.Sprintf(" (conflict: MAC also seen on guest %s)", strings.Join(others, ", "))
			}
			add(hostID, MatchMAC, detail, macConflict || len(hostsByAssetMAC[mac]) > 1)
		}
	}

	// IP matches: agent IPs first (stronger), then plain IPs.
	for ip := range ips.agent {
		s.addIPCandidate(ip, MatchAgentIP, hostByEndpoint, hostsByAssetIP, add)
	}
	for ip := range ips.plain {
		if ips.agent[ip] {
			continue
		}
		s.addIPCandidate(ip, MatchIP, hostByEndpoint, hostsByAssetIP, add)
	}

	var candidates []Candidate
	for _, c := range out {
		candidates = append(candidates, *c)
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].HostID != candidates[j].HostID {
			return candidates[i].HostID < candidates[j].HostID
		}
		return candidates[i].Match < candidates[j].Match
	})
	return candidates, nil
}

func (s *Store) addIPCandidate(ip, match string, hostByEndpoint, hostsByAssetIP map[string][]string, add func(hostID, match, detail string, conflict bool)) {
	low := strings.ToLower(ip)
	hostSet := map[string]bool{}
	for _, h := range hostByEndpoint[low] {
		hostSet[h] = true
	}
	for _, h := range hostsByAssetIP[low] {
		hostSet[h] = true
	}
	ipConflict := len(hostSet) > 1
	for h := range hostSet {
		detail := fmt.Sprintf("IP %s matches an endpoint of host %s", ip, h)
		if match == MatchAgentIP {
			detail = fmt.Sprintf("guest agent IP %s matches an endpoint of host %s", ip, h)
		}
		if ipConflict {
			detail += fmt.Sprintf(" (conflict: IP also matches %d other hosts)", len(hostSet)-1)
		}
		add(h, match, detail, ipConflict)
	}
}

// GuestConflicts returns human-readable conflict descriptions for the
// guest incarnation: one MAC present on two guests of the same remote,
// or one guest IP matching more than one managed host. Conflicts are
// flagged, never resolved silently.
func (s *Store) GuestConflicts(ctx context.Context, remoteID string, vmid, generation uint64) ([]string, error) {
	if _, err := s.getIncarnation(ctx, remoteID, vmid, generation); err != nil {
		return nil, err
	}
	var out []string
	ifaces, err := s.ListInterfaces(ctx, remoteID, vmid, generation, 0)
	if err != nil {
		return nil, err
	}
	seenMAC := map[string]bool{}
	for _, in := range ifaces {
		if in.MAC == "" || seenMAC[in.MAC] {
			continue
		}
		seenMAC[in.MAC] = true
		others, err := s.guestsWithMAC(ctx, remoteID, in.MAC, vmid)
		if err != nil {
			return nil, err
		}
		if len(others) > 0 {
			out = append(out, fmt.Sprintf("MAC %s is present on this guest and on guest %s (cloned MAC; link needs review)",
				in.MAC, strings.Join(others, ", ")))
		}
	}
	hosts, err := s.hostStore().List(ctx)
	if err != nil {
		return nil, err
	}
	countByIP := map[string][]string{}
	for _, h := range hosts {
		for _, e := range h.Endpoints {
			countByIP[strings.ToLower(e.Address)] = append(countByIP[strings.ToLower(e.Address)], h.ID)
		}
	}
	seenIP := map[string]bool{}
	for _, in := range ifaces {
		for _, ip := range in.IPs {
			a, ok := parseGuestIP(ip)
			if !ok || seenIP[a] {
				continue
			}
			seenIP[a] = true
			if hs := countByIP[strings.ToLower(a)]; len(hs) > 1 {
				out = append(out, fmt.Sprintf("IP %s is an endpoint of %d managed hosts: %s", a, len(hs), strings.Join(hs, ", ")))
			}
		}
	}
	sort.Strings(out)
	return out, nil
}

// guestsWithMAC returns the "vmid (gen)" labels of other active guests
// of the same remote carrying the MAC.
func (s *Store) guestsWithMAC(ctx context.Context, remoteID, mac string, selfVMID uint64) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT g.vmid, g.generation
		FROM pve_interfaces i
		JOIN pve_guests g ON g.remote_id = i.remote_id AND g.vmid = i.vmid AND g.generation = i.generation
		WHERE i.remote_id = ? AND i.mac = ? AND g.tombstoned = 0
		ORDER BY g.vmid, g.generation`, remoteID, mac)
	if err != nil {
		return nil, fmt.Errorf("pveinventory: guests with mac %s: %w", mac, err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var vmid, gen uint64
		if err := rows.Scan(&vmid, &gen); err != nil {
			return nil, err
		}
		if vmid == selfVMID {
			continue
		}
		out = append(out, fmt.Sprintf("%d (gen %d)", vmid, gen))
	}
	return out, rows.Err()
}

// parseGuestIP parses a stored interface IP ("10.0.0.5" or
// "10.0.0.5/24") into its canonical address string.
func parseGuestIP(ip string) (string, bool) {
	if i := strings.IndexByte(ip, '/'); i >= 0 {
		ip = ip[:i]
	}
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return "", false
	}
	return a.String(), true
}

// getIncarnation loads one active guest incarnation.
func (s *Store) getIncarnation(ctx context.Context, remoteID string, vmid, generation uint64) (Guest, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT remote_id, vmid, generation, kind, node, name, status, uuid,
		       observed_at, source, state, reason, collection_generation,
		       tombstoned, tombstoned_at
		FROM pve_guests
		WHERE remote_id = ? AND vmid = ? AND generation = ? AND tombstoned = 0`,
		remoteID, vmid, generation)
	return scanGuestRow(row, s, fmt.Sprintf("get guest %s/%d/%d", remoteID, vmid, generation))
}

const (
	linkColumns = "remote_id, vmid, generation, host_id, created_by, created_at, unlinked_at, unlink_reason"

	linkByIncarnationSQL = `
		SELECT ` + linkColumns + `
		FROM pve_host_links
		WHERE remote_id = ? AND vmid = ? AND generation = ? AND unlinked_at = ''
		LIMIT 1`

	linkByHostSQL = `
		SELECT ` + linkColumns + `
		FROM pve_host_links
		WHERE host_id = ? AND unlinked_at = ''
		ORDER BY remote_id, vmid, generation
		LIMIT 1`
)

type linkScanner interface {
	Scan(dest ...any) error
}

// scanLinkRow scans one pve_host_links row; sql.ErrNoRows maps to
// ErrLinkNotFound.
func scanLinkRow(row linkScanner) (Link, error) {
	var l Link
	var createdAt, unlinkedAt string
	err := row.Scan(&l.RemoteID, &l.VMID, &l.Generation, &l.HostID, &l.CreatedBy, &createdAt, &unlinkedAt, &l.UnlinkReason)
	if errors.Is(err, sql.ErrNoRows) {
		return Link{}, ErrLinkNotFound
	}
	if err != nil {
		return Link{}, fmt.Errorf("pveinventory: scan link: %w", err)
	}
	l.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	if unlinkedAt != "" {
		l.UnlinkedAt, _ = time.Parse(time.RFC3339, unlinkedAt)
	}
	return l, nil
}

// Service placement (ADR 0006, ticket P1-27): an explicit, reviewed
// association of a service with the place where it runs. A service has at
// most one active placement. A placement is only ever created by an
// explicit call with an actor — no code path infers placements from
// observed state (names, processes, Compose labels). A service without a
// placement, or without a configured check, stays unknown.

// Service placement kinds (ServicePlacement.Kind).
const (
	// PlacementHost: the service runs on the managed host itself.
	PlacementHost = "host"
	// PlacementGuest: the service runs inside a PVE guest incarnation.
	PlacementGuest = "guest"
	// PlacementContainer: the service runs in a Docker container on a
	// managed host; the container identity is (host_id, full container ID).
	PlacementContainer = "container"
)

// Limits for service placements.
const (
	// MaxServiceNameLen is the maximum length of a service name.
	MaxServiceNameLen = 128
	// MaxPlacementSourceLen is the maximum length of a placement source.
	MaxPlacementSourceLen = 64
	// MaxContainerIDLen is the length of a full Docker container ID.
	MaxContainerIDLen = 64
	// MaxPlacementQuery is the cap for ListServicePlacements results.
	MaxPlacementQuery = 1000
)

var (
	serviceNameRe     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	containerIDRe     = regexp.MustCompile(`^[0-9a-f]{64}$`)
	placementSourceRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)
)

// ErrServicePlaced reports that the service already has an active
// placement.
var ErrServicePlaced = errors.New("service already has an active placement")

// ErrPlacementNotFound reports that the service has no active placement.
var ErrPlacementNotFound = errors.New("no active service placement")

// ServicePlacement is an explicit association of a service with the place
// where it runs, plus its optional health-check configuration.
type ServicePlacement struct {
	// ServiceName is the service name (for example a Compose service
	// name).
	ServiceName string
	// Kind is PlacementHost, PlacementGuest or PlacementContainer.
	Kind string
	// HostID is the managed host (host and container kinds).
	HostID string
	// RemoteID is the PVE remote (guest kind only).
	RemoteID string
	// VMID is the guest VMID (guest kind only).
	VMID uint64
	// Generation is the guest incarnation generation (guest kind only).
	Generation uint64
	// ContainerID is the full Docker container ID (container kind only).
	ContainerID string
	// CheckProtocol is the health-check protocol (http, https or tcp),
	// empty when no check is configured.
	CheckProtocol string
	// CheckDestination is the approved destination of the check.
	CheckDestination string
	// CheckPort is the port of the check.
	CheckPort int
	// CheckInternal is true when the check destination is an approved
	// reserved address (including resolved DNS answers).
	CheckInternal bool
	// Source is how the association was established (for example
	// "manual" or "reviewed-compose").
	Source string
	// RecordedBy is the actor that recorded the placement.
	RecordedBy string
	// RecordedAt is when the placement was recorded.
	RecordedAt time.Time
	// RemovedAt is the tombstone time (zero while active).
	RemovedAt time.Time
	// RemovedBy is the actor that removed the placement.
	RemovedBy string
	// RemoveReason is why the placement was removed.
	RemoveReason string
}

// CheckConfigured reports whether an HTTP/TCP health check is configured
// for this placement. Without one, the service health stays unknown.
func (p ServicePlacement) CheckConfigured() bool {
	return p.CheckProtocol != "" && p.CheckDestination != "" && p.CheckPort != 0
}

const placementColumns = `service_name, kind, host_id, remote_id, vmid, generation, container_id,
	check_protocol, check_destination, check_port, check_internal,
	source, recorded_by, recorded_at, removed_at, removed_by, remove_reason`

func scanPlacementRow(row linkScanner) (ServicePlacement, error) {
	var p ServicePlacement
	var recordedAt, removedAt string
	err := row.Scan(
		&p.ServiceName, &p.Kind, &p.HostID, &p.RemoteID, &p.VMID, &p.Generation, &p.ContainerID,
		&p.CheckProtocol, &p.CheckDestination, &p.CheckPort, &p.CheckInternal,
		&p.Source, &p.RecordedBy, &recordedAt, &removedAt, &p.RemovedBy, &p.RemoveReason,
	)
	if err != nil {
		return ServicePlacement{}, err
	}
	p.RecordedAt, err = time.Parse(time.RFC3339Nano, recordedAt)
	if err != nil {
		return ServicePlacement{}, fmt.Errorf("pveinventory: parse placement recorded_at: %w", err)
	}
	if removedAt != "" {
		t, err := time.Parse(time.RFC3339Nano, removedAt)
		if err != nil {
			return ServicePlacement{}, fmt.Errorf("pveinventory: parse placement removed_at %q: %w", removedAt, err)
		}
		p.RemovedAt = t
	}
	return p, nil
}

// validateServicePlacement checks the placement fields that do not need
// the database.
func validateServicePlacement(p ServicePlacement) error {
	if !serviceNameRe.MatchString(p.ServiceName) {
		return fmt.Errorf("pveinventory: set service placement: invalid service name")
	}
	if !placementSourceRe.MatchString(p.Source) {
		return fmt.Errorf("pveinventory: set service placement: invalid source")
	}
	switch p.Kind {
	case PlacementHost:
		if p.HostID == "" {
			return fmt.Errorf("pveinventory: set service placement: host placement requires host_id")
		}
		if p.RemoteID != "" || p.VMID != 0 || p.Generation != 0 || p.ContainerID != "" {
			return fmt.Errorf("pveinventory: set service placement: host placement carries guest or container fields")
		}
	case PlacementGuest:
		if p.RemoteID == "" || p.VMID == 0 || p.Generation == 0 {
			return fmt.Errorf("pveinventory: set service placement: guest placement requires remote_id, vmid and generation")
		}
		if p.HostID != "" || p.ContainerID != "" {
			return fmt.Errorf("pveinventory: set service placement: guest placement carries host or container fields")
		}
	case PlacementContainer:
		if p.HostID == "" {
			return fmt.Errorf("pveinventory: set service placement: container placement requires host_id")
		}
		if !containerIDRe.MatchString(p.ContainerID) {
			return fmt.Errorf("pveinventory: set service placement: container placement requires the full container ID")
		}
		if p.RemoteID != "" || p.VMID != 0 || p.Generation != 0 {
			return fmt.Errorf("pveinventory: set service placement: container placement carries guest fields")
		}
	default:
		return fmt.Errorf("pveinventory: set service placement: unknown kind")
	}
	// The check configuration is all-or-nothing; a partially
	// configured check is rejected, and a complete one is validated by
	// the servicecheck contract (approved destination and port).
	configured := p.CheckConfigured()
	partial := (p.CheckProtocol != "" || p.CheckDestination != "" || p.CheckPort != 0 || p.CheckInternal) && !configured
	if partial {
		return fmt.Errorf("pveinventory: set service placement: check configuration must be complete or absent")
	}
	if configured {
		if err := servicecheck.ValidateCheck(servicecheck.Check{
			Protocol:         p.CheckProtocol,
			Destination:      p.CheckDestination,
			Port:             p.CheckPort,
			InternalApproved: p.CheckInternal,
		}); err != nil {
			return fmt.Errorf("pveinventory: set service placement: %w", err)
		}
	}
	return nil
}

// SetServicePlacement records an explicit service placement. It is the
// only way a placement is created; nothing infers placements from
// observed state. It fails with ErrServicePlaced when the service
// already has an active placement.
func (s *Store) SetServicePlacement(ctx context.Context, p ServicePlacement, actor string) (ServicePlacement, error) {
	if err := validActor(actor); err != nil {
		return ServicePlacement{}, err
	}
	if err := validateServicePlacement(p); err != nil {
		return ServicePlacement{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ServicePlacement{}, fmt.Errorf("pveinventory: set service placement: %w", err)
	}
	defer tx.Rollback()

	switch p.Kind {
	case PlacementHost, PlacementContainer:
		if err := requireManagedHost(ctx, tx, p.HostID); err != nil {
			return ServicePlacement{}, err
		}
	case PlacementGuest:
		if err := validateLinkIncarnation(ctx, tx, p.RemoteID, p.VMID, p.Generation); err != nil {
			return ServicePlacement{}, err
		}
	}

	var exists int
	err = tx.QueryRowContext(ctx,
		`SELECT count(*) FROM pve_service_placements WHERE service_name = ? AND removed_at = ''`,
		p.ServiceName).Scan(&exists)
	if err != nil {
		return ServicePlacement{}, fmt.Errorf("pveinventory: set service placement %q: %w", p.ServiceName, err)
	}
	if exists > 0 {
		return ServicePlacement{}, fmt.Errorf("pveinventory: set service placement %q: %w", p.ServiceName, ErrServicePlaced)
	}

	p.RecordedBy = actor
	p.RecordedAt = s.now().UTC().Truncate(time.Second)
	p.RemovedAt = time.Time{}
	p.RemovedBy = ""
	p.RemoveReason = ""
	_, err = tx.ExecContext(ctx, `
		INSERT INTO pve_service_placements (`+placementColumns+`)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '', '', '')`,
		p.ServiceName, p.Kind, p.HostID, p.RemoteID, p.VMID, p.Generation, p.ContainerID,
		p.CheckProtocol, p.CheckDestination, p.CheckPort, boolInt(p.CheckInternal),
		p.Source, p.RecordedBy, s.formatTime(p.RecordedAt))
	if err != nil {
		return ServicePlacement{}, fmt.Errorf("pveinventory: set service placement %q: %w", p.ServiceName, err)
	}
	if err := tx.Commit(); err != nil {
		return ServicePlacement{}, fmt.Errorf("pveinventory: set service placement %q: %w", p.ServiceName, err)
	}
	return p, nil
}

// requireManagedHost fails with ErrManagedHostNotFound when the managed
// host does not exist.
func requireManagedHost(ctx context.Context, tx *sql.Tx, hostID string) error {
	var exists int
	err := tx.QueryRowContext(ctx, `SELECT count(*) FROM hosts WHERE name = ?`, hostID).Scan(&exists)
	if err != nil {
		return fmt.Errorf("pveinventory: set service placement: %w", err)
	}
	if exists == 0 {
		return fmt.Errorf("pveinventory: set service placement: %w", ErrManagedHostNotFound)
	}
	return nil
}

// GetServicePlacement returns the active placement of a service. It
// fails with ErrPlacementNotFound when the service has no active
// placement, or when a guest placement points at a tombstoned
// incarnation or a removed remote (the placement no longer applies).
func (s *Store) GetServicePlacement(ctx context.Context, serviceName string) (ServicePlacement, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+placementColumns+` FROM pve_service_placements WHERE service_name = ? AND `+activePlacementSQL, serviceName)
	p, err := scanPlacementRow(row)
	if errors.Is(err, sql.ErrNoRows) {
		return ServicePlacement{}, fmt.Errorf("pveinventory: get service placement: %w", ErrPlacementNotFound)
	}
	if err != nil {
		return ServicePlacement{}, fmt.Errorf("pveinventory: get service placement: %w", err)
	}
	return p, nil
}

// Placements cannot transfer across guest or container incarnations. Stale
// references remain in history but never appear as currently placed services.
const activePlacementSQL = `removed_at = '' AND (
 (kind IN ('host', 'container') AND EXISTS (SELECT 1 FROM hosts h WHERE h.name = pve_service_placements.host_id)) OR
 (kind = 'guest' AND EXISTS (SELECT 1 FROM pve_guests g JOIN pve_remotes r ON r.remote_id = g.remote_id
 WHERE g.remote_id = pve_service_placements.remote_id AND g.vmid = pve_service_placements.vmid
 AND g.generation = pve_service_placements.generation AND g.tombstoned = 0)))`

// ListServicePlacements returns the active placements, ordered by
// service name, capped at limit (or MaxPlacementQuery when limit <= 0).
func (s *Store) ListServicePlacements(ctx context.Context, limit int) ([]ServicePlacement, error) {
	limit, err := checkLimit(limit, MaxPlacementQuery)
	if err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT `+placementColumns+` FROM pve_service_placements WHERE `+activePlacementSQL+` ORDER BY service_name LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("pveinventory: list service placements: %w", err)
	}
	defer rows.Close()
	var out []ServicePlacement
	for rows.Next() {
		p, err := scanPlacementRow(rows)
		if err != nil {
			return nil, fmt.Errorf("pveinventory: list service placements: %w", err)
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("pveinventory: list service placements: %w", err)
	}
	return out, nil
}

// RemoveServicePlacement tombstones the active placement of a service.
// It fails with ErrPlacementNotFound when the service has no active
// placement.
func (s *Store) RemoveServicePlacement(ctx context.Context, serviceName, actor, reason string) (ServicePlacement, error) {
	if err := validActor(actor); err != nil {
		return ServicePlacement{}, err
	}
	if reason == "" || len(reason) > MaxUnlinkReasonLen || !utf8.ValidString(reason) {
		return ServicePlacement{}, fmt.Errorf("pveinventory: remove service placement %q: reason required", serviceName)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ServicePlacement{}, fmt.Errorf("pveinventory: remove service placement %q: %w", serviceName, err)
	}
	defer tx.Rollback()

	var id int64
	err = tx.QueryRowContext(ctx,
		`SELECT id FROM pve_service_placements WHERE service_name = ? AND removed_at = ''`,
		serviceName).Scan(&id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ServicePlacement{}, fmt.Errorf("pveinventory: remove service placement %q: %w", serviceName, ErrPlacementNotFound)
		}
		return ServicePlacement{}, fmt.Errorf("pveinventory: remove service placement %q: %w", serviceName, err)
	}
	res, err := tx.ExecContext(ctx,
		`UPDATE pve_service_placements SET removed_at = ?, removed_by = ?, remove_reason = ? WHERE id = ?`,
		s.formatTime(s.now()), actor, reason, id)
	if err != nil {
		return ServicePlacement{}, fmt.Errorf("pveinventory: remove service placement %q: %w", serviceName, err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return ServicePlacement{}, fmt.Errorf("pveinventory: remove service placement %q: %w", serviceName, ErrPlacementNotFound)
	}
	p, err := scanPlacementRow(tx.QueryRowContext(ctx, `SELECT `+placementColumns+` FROM pve_service_placements WHERE id = ?`, id))
	if err != nil {
		return ServicePlacement{}, fmt.Errorf("pveinventory: read removed placement: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return ServicePlacement{}, fmt.Errorf("pveinventory: remove service placement: %w", err)
	}
	return p, nil
}

// ServiceHealth keeps process/container runtime state separate from endpoint health.
type ServiceHealth struct {
	// Runtime is the independently observed process or container state.
	Runtime BoxState
	// Endpoint is unknown until a matching configured check has a valid result.
	Endpoint BoxState
	// Latency is the bounded probe duration; zero when no result applies.
	Latency time.Duration
	// HTTPStatus is the HTTP response code, or zero for TCP or unavailable results.
	HTTPStatus int
}

// Health returns unknown endpoint health until a check configured for this exact
// destination, port, protocol and approval has produced a valid result. Runtime
// state never supplies or overrides an endpoint result.
func (p ServicePlacement) Health(runtime BoxState, checked servicecheck.Check, result *servicecheck.Result) ServiceHealth {
	h := ServiceHealth{Runtime: runtime, Endpoint: StateUnknown}
	configured := servicecheck.Check{Protocol: p.CheckProtocol, Destination: p.CheckDestination, Port: p.CheckPort, InternalApproved: p.CheckInternal}
	if !p.RemovedAt.IsZero() || !p.CheckConfigured() || configured != checked || result == nil || servicecheck.ValidateCheck(configured) != nil || servicecheck.ValidateResult(*result) != nil {
		return h
	}
	if (configured.Protocol == "tcp") != (result.HTTPStatus == 0) && result.Status == servicecheck.StatusOK {
		return h
	}
	if configured.Protocol == "tcp" && result.HTTPStatus != 0 {
		return h
	}
	h.Latency, h.HTTPStatus = result.Latency, result.HTTPStatus
	switch result.Status {
	case servicecheck.StatusOK:
		h.Endpoint = StateOK
	case servicecheck.StatusRedirect, servicecheck.StatusHTTPError, servicecheck.StatusRefused, servicecheck.StatusUnresolved, servicecheck.StatusTimeout, servicecheck.StatusTLS:
		h.Endpoint = StateCritical
	}
	return h
}
